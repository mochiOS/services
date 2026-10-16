extern crate alloc;
use mnu_abi::status::Error as NativeError;

#[path = "../../../core/src/mem/byte_extent.rs"]
mod byte_extent;

// Exercise the production storage implementation, substituting only the host
// equivalents of physical frame allocation and interrupt-safe locking.
mod interrupt {
    pub mod spinlock {
        pub struct SpinLock<T>(std::sync::Mutex<T>);
        impl<T> SpinLock<T> {
            pub fn new(value: T) -> Self {
                Self(std::sync::Mutex::new(value))
            }
            pub fn lock(&self) -> std::sync::MutexGuard<'_, T> {
                self.0.lock().unwrap()
            }
        }
    }
}
#[path = "../../../core/src/mem/shared_memory.rs"]
mod shared_memory;
#[path = "../../../core/src/mem/shared_pages.rs"]
mod shared_pages;
mod vm_object {
    pub const PAGE_BYTES: usize = 4096;
}

fn frames() -> &'static std::sync::Mutex<std::collections::BTreeMap<u64, usize>> {
    static FRAMES: std::sync::OnceLock<std::sync::Mutex<std::collections::BTreeMap<u64, usize>>> =
        std::sync::OnceLock::new();
    FRAMES.get_or_init(Default::default)
}
thread_local! {
    static PHYSICAL_OFFSET: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(Some(0)) };
    static FAIL_FRAME: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_RETAIN: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
mod frame {
    pub struct Frame(u64);
    pub struct Address(u64);
    impl Frame {
        pub fn start_address(&self) -> Address {
            Address(self.0)
        }
    }
    impl Address {
        pub fn as_u64(&self) -> u64 {
            self.0
        }
    }
    pub fn allocate_zeroed_frame() -> Result<Frame, ()> {
        if super::FAIL_FRAME.get() {
            return Err(());
        }
        let layout = std::alloc::Layout::from_size_align(4096, 4096).unwrap();
        let pointer = unsafe { std::alloc::alloc_zeroed(layout) };
        if pointer.is_null() {
            return Err(());
        }
        super::frames().lock().unwrap().insert(pointer as u64, 1);
        Ok(Frame(pointer as u64))
    }
}
mod paging {
    pub fn physical_memory_offset() -> Option<u64> {
        super::PHYSICAL_OFFSET.get()
    }
    pub fn retain_shared_user_frame(address: u64) -> Result<(), ()> {
        if super::FAIL_RETAIN.get() {
            return Err(());
        }
        let mut frames = super::frames().lock().unwrap();
        *frames.get_mut(&address).ok_or(())? += 1;
        Ok(())
    }
    pub fn release_user_frame(address: u64) {
        let mut frames = super::frames().lock().unwrap();
        let references = frames.get_mut(&address).expect("double release");
        *references -= 1;
        if *references == 0 {
            frames.remove(&address);
            unsafe {
                std::alloc::dealloc(
                    address as *mut u8,
                    std::alloc::Layout::from_size_align(4096, 4096).unwrap(),
                );
            }
        }
    }
}

#[test]
fn production_shared_storage_reads_across_pages_and_clips_at_its_end() {
    let memory = shared_memory::SharedMemory::new(3 * 4096, 3).unwrap();
    assert_eq!(memory.length(), 3 * 4096);
    assert_ne!(memory.id(), 0);
    let mut output = vec![0xa5; 3 * 4096];
    assert_eq!(memory.read_at(0, &mut output), Ok(output.len()));
    assert!(output.iter().all(|byte| *byte == 0));
    let content: Vec<u8> = (0..8192).map(|index| (index % 251) as u8).collect();
    assert_eq!(memory.write_at(37, &content), Ok(content.len()));
    assert_eq!(memory.read_at(37, &mut output[..8192]), Ok(8192));
    assert_eq!(&output[..8192], &content);
    output.fill(0xa5);
    assert_eq!(memory.read_at(3 * 4096 - 5, &mut output), Ok(5));
    assert_eq!(&output[..5], &[0; 5]);
    assert!(output[5..].iter().all(|byte| *byte == 0xa5));
    assert_eq!(memory.read_at(3 * 4096, &mut output), Ok(0));
    assert_eq!(
        memory.read_at(3 * 4096 + 1, &mut output),
        Err(NativeError::InvalidArgument)
    );
    assert_eq!(
        memory.write_at(u64::MAX, b"x"),
        Err(NativeError::InvalidArgument)
    );
    assert_eq!(
        memory.write_at(3 * 4096 - 1, b"xy"),
        Err(NativeError::InvalidArgument)
    );
    assert_eq!(memory.read_at(3 * 4096 - 1, &mut output[..1]), Ok(1));
    assert_eq!(output[0], 0);
}

#[test]
fn retained_physical_storage_outlives_the_object_and_is_released_once() {
    let memory = shared_memory::SharedMemory::new(4096, 1).unwrap();
    memory.write_at(103, &[0xa7]).unwrap();
    let frame = memory.retain_page(0).unwrap();
    let alias = memory.retain_page(0).unwrap();
    assert_eq!(frame, alias);
    assert_eq!(memory.retain_page(1), Err(NativeError::InvalidArgument));
    assert_eq!(*frames().lock().unwrap().get(&frame).unwrap(), 3);
    drop(memory);
    assert_eq!(*frames().lock().unwrap().get(&frame).unwrap(), 2);
    assert_eq!(
        unsafe { std::ptr::read_volatile((frame + 103) as *const u8) },
        0xa7
    );
    paging::release_user_frame(alias);
    assert_eq!(*frames().lock().unwrap().get(&frame).unwrap(), 1);
    paging::release_user_frame(frame);
    assert!(!frames().lock().unwrap().contains_key(&frame));
}

#[test]
fn empty_byte_object_grows_lazily_and_keeps_its_original_ceiling() {
    let memory = shared_memory::SharedMemory::new_resizable(0, 2).unwrap();
    assert_eq!(memory.length(), 0);
    assert_eq!(memory.prepare_page(0), Err(NativeError::InvalidArgument));
    assert_eq!(memory.read_at(0, &mut [1]), Ok(0));
    assert_eq!(memory.write_at(0, &[1]), Err(NativeError::InvalidArgument));
    memory
        .resize_with(1, |_, _| panic!("no old mapping"))
        .unwrap();
    assert_eq!(memory.length(), 1);
    assert_eq!(memory.write_at(0, &[17]), Ok(1));
    let (frame, _) = memory.prepare_page(0).unwrap();
    assert_eq!(memory.prepare_page(1), Err(NativeError::InvalidArgument));
    memory
        .resize_with(8192, |start, end| {
            assert_eq!((start, end), (0, 4096));
            Ok(())
        })
        .unwrap();
    let mut bytes = [1; 2];
    assert_eq!(memory.read_at(0, &mut bytes), Ok(2));
    assert_eq!(bytes, [17, 0]);
    let epoch = memory.generation();
    assert_eq!(
        memory.resize_with(8193, |_, _| panic!("quota before revoke")),
        Err(NativeError::ResourceUnavailable)
    );
    assert_eq!(memory.length(), 8192);
    assert_eq!(memory.with_generation(epoch, || Ok(())), Ok(()));
    paging::release_user_frame(frame);
}

#[test]
fn byte_creation_checks_rounded_capacity_without_rounding_logical_length() {
    assert!(matches!(
        shared_memory::SharedMemory::new(0, 1),
        Err(NativeError::InvalidArgument)
    ));
    assert!(matches!(
        shared_memory::SharedMemory::new(1, 1),
        Err(NativeError::InvalidArgument)
    ));
    let memory = shared_memory::SharedMemory::new_resizable(4097, 2).unwrap();
    assert_eq!(memory.length(), 4097);
    assert!(memory.contains_range(4096, 1));
    assert!(!memory.contains_range(4096, 2));
    assert_eq!(memory.write_at(4096, &[23]), Ok(1));
    let mut bytes = [0; 2];
    assert_eq!(memory.read_at(4096, &mut bytes), Ok(1));
    assert_eq!(bytes[0], 23);
    assert!(matches!(
        shared_memory::SharedMemory::new_resizable(4097, 1),
        Err(NativeError::ResourceUnavailable)
    ));
    assert!(matches!(
        shared_memory::SharedMemory::new_resizable(u64::MAX, u64::MAX),
        Err(NativeError::ResourceUnavailable)
    ));
    assert!(shared_memory::SharedMemory::new_resizable(0, 0).is_ok());
}

#[test]
fn page_population_uses_live_extent_including_its_partial_final_page() {
    let memory = shared_memory::SharedMemory::new_resizable(4097, 3).unwrap();
    let (partial, epoch) = memory.prepare_page(1).unwrap();
    assert_eq!(memory.prepare_page(2), Err(NativeError::InvalidArgument));
    memory.resize_with(12288, |_, _| Ok(())).unwrap();
    let (future, _) = memory.prepare_page(2).unwrap();
    memory.resize_with(4096, |_, _| Ok(())).unwrap();
    assert_eq!(memory.prepare_page(1), Err(NativeError::InvalidArgument));
    assert_eq!(memory.prepare_page(2), Err(NativeError::InvalidArgument));
    assert_eq!(
        memory.with_generation(epoch, || Ok(())),
        Err(NativeError::NotReady.into_raw())
    );
    // Outstanding pins retain storage but cannot authorize a stale install.
    assert!(frames().lock().unwrap().contains_key(&partial));
    assert!(frames().lock().unwrap().contains_key(&future));
    paging::release_user_frame(partial);
    paging::release_user_frame(future);
}

#[test]
fn byte_resize_preserves_prefix_and_clears_padding_before_growth() {
    let memory = shared_memory::SharedMemory::new(8192, 2).unwrap();
    memory.write_at(4999, &[7, 8, 9]).unwrap();
    let (frame, epoch) = memory.prepare_page(1).unwrap();
    assert_eq!(
        memory.resize_with(5000, |start, end| {
            assert_eq!((start, end), (4096, 8192));
            Err(NativeError::BackingFailure)
        }),
        Err(NativeError::BackingFailure)
    );
    assert_eq!(memory.length(), 8192);
    assert_eq!(memory.with_generation(epoch, || Ok(())), Ok(()));
    assert_eq!(
        unsafe { std::ptr::read_volatile((frame + 904) as *const u8) },
        8
    );
    memory.resize_with(5000, |_, _| Ok(())).unwrap();
    assert_eq!(
        memory.write_at(5000, &[1]),
        Err(NativeError::InvalidArgument)
    );
    let mut output = [0; 3];
    assert_eq!(memory.read_at(4999, &mut output), Ok(1));
    assert_eq!(output[0], 7);
    assert_eq!(
        unsafe { std::ptr::read_volatile((frame + 904) as *const u8) },
        0
    );
    unsafe { std::ptr::write_volatile((frame + 904) as *mut u8, 42) };
    memory
        .resize_with(5001, |start, end| {
            assert_eq!((start, end), (4096, 8192));
            Ok(())
        })
        .unwrap();
    assert_eq!(memory.read_at(5000, &mut output[..1]), Ok(1));
    assert_eq!(output[0], 0);
    assert_eq!(
        memory.with_generation(epoch, || Ok(())),
        Err(NativeError::NotReady.into_raw())
    );
    let alias = memory.retain_page(1).unwrap();
    assert_eq!(alias, frame);
    paging::release_user_frame(alias);
    paging::release_user_frame(frame);
}

#[test]
fn concurrent_byte_io_and_resize_preserve_prefix_and_validate_extent() {
    let memory = shared_memory::SharedMemory::new(8192, 2).unwrap();
    std::thread::scope(|scope| {
        for _ in 0..4 {
            let memory = &memory;
            scope.spawn(move || {
                for _ in 0..200 {
                    assert_eq!(memory.write_at(4095, &[6, 6]), Ok(2));
                    let mut bytes = [0; 2];
                    assert_eq!(memory.read_at(4095, &mut bytes), Ok(2));
                    assert_eq!(bytes, [6, 6]);
                    assert!(matches!(
                        memory.write_at(6000, &[3]),
                        Ok(1) | Err(NativeError::InvalidArgument)
                    ));
                }
            });
        }
        for _ in 0..200 {
            memory.resize_with(5000, |_, _| Ok(())).unwrap();
            memory.resize_with(8192, |_, _| Ok(())).unwrap();
        }
    });
    memory.resize_with(5000, |_, _| Ok(())).unwrap();
    memory.resize_with(8192, |_, _| Ok(())).unwrap();
    let mut bytes = [1];
    memory.read_at(6000, &mut bytes).unwrap();
    assert_eq!(bytes, [0]);
}

#[test]
fn shrink_and_regrowth_reject_old_prepared_generations_without_recycling_pins() {
    let memory = shared_memory::SharedMemory::new(4096, 2).unwrap();
    memory.write_at(17, &[0xa7]).unwrap();
    let (old_frame, old_generation) = memory.prepare_page(0).unwrap();
    memory
        .resize_with(0, |start, end| {
            assert_eq!((start, end), (0, 4096));
            assert_eq!(*frames().lock().unwrap().get(&old_frame).unwrap(), 2);
            Ok(())
        })
        .unwrap();
    assert_eq!(memory.length(), 0);
    assert_eq!(
        memory.with_generation(old_generation, || -> Result<(), u64> {
            panic!("old prepared page must not be installed")
        }),
        Err(NativeError::NotReady.into_raw())
    );
    memory
        .resize_with(4096, |_, _| -> Result<(), NativeError> {
            panic!("growth never revokes")
        })
        .unwrap();
    let (fresh_frame, fresh_generation) = memory.prepare_page(0).unwrap();
    assert_ne!(old_frame, fresh_frame);
    assert_ne!(old_generation, fresh_generation);
    assert_eq!(
        unsafe { std::ptr::read_volatile((old_frame + 17) as *const u8) },
        0xa7
    );
    assert_eq!(
        unsafe { std::ptr::read_volatile((fresh_frame + 17) as *const u8) },
        0
    );
    assert_eq!(
        memory.with_generation(fresh_generation, || Ok(42u32)),
        Ok(42)
    );
    paging::release_user_frame(old_frame);
    paging::release_user_frame(fresh_frame);
}

#[test]
fn failed_resize_and_noop_preserve_current_size_and_prepared_generation() {
    let memory = shared_memory::SharedMemory::new(8192, 2).unwrap();
    let (frame, generation) = memory.prepare_page(1).unwrap();
    assert_eq!(
        memory.resize_with(12288, |_, _| Ok(())),
        Err(NativeError::ResourceUnavailable)
    );
    assert_eq!(
        memory.resize_with(4096, |_, _| Err(NativeError::BackingFailure)),
        Err(NativeError::BackingFailure)
    );
    assert_eq!(memory.length(), 8192);
    assert_eq!(memory.with_generation(generation, || Ok(())), Ok(()));
    memory
        .resize_with(8192, |_, _| -> Result<(), NativeError> { panic!("no-op") })
        .unwrap();
    assert_eq!(memory.with_generation(generation, || Ok(())), Ok(()));
    paging::release_user_frame(frame);
}

#[test]
fn final_installation_holds_size_and_generation_stable_against_concurrent_resize() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let memory = shared_memory::SharedMemory::new(4096, 1).unwrap();
    let (frame, generation) = memory.prepare_page(0).unwrap();
    let entered = std::sync::Barrier::new(2);
    let finish = std::sync::Barrier::new(2);
    let attempted = std::sync::Barrier::new(2);
    let installed = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let installer = scope.spawn(|| {
            memory.with_generation(generation, || {
                entered.wait();
                finish.wait();
                installed.store(true, Ordering::Release);
                Ok(())
            })
        });
        entered.wait();
        let resize = scope.spawn(|| {
            attempted.wait();
            memory.resize_with(0, |_, _| {
                assert!(
                    installed.load(Ordering::Acquire),
                    "resize must wait for PTE installation"
                );
                Ok(())
            })
        });
        attempted.wait();
        finish.wait();
        assert_eq!(installer.join().unwrap(), Ok(()));
        assert_eq!(resize.join().unwrap(), Ok(()));
    });
    assert_eq!(
        memory.with_generation(generation, || Ok(())),
        Err(NativeError::NotReady.into_raw())
    );
    paging::release_user_frame(frame);
}

#[test]
fn backing_commit_runs_inside_mapping_exclusion_before_retained_pages_are_restored() {
    let memory = shared_memory::SharedMemory::new(8192, 2).unwrap();
    memory.write_at(4096, &[0x5a; 4096]).unwrap();
    let frame = memory.retain_page(1).unwrap();
    let generation = memory.generation();
    assert_eq!(
        memory.resize_transaction(4113, |start, end, _commit| {
            assert_eq!((start, end), (4096, 8192));
            Err(NativeError::BackingFailure)
        }),
        Err(NativeError::BackingFailure)
    );
    assert_eq!(memory.length(), 8192);
    assert_eq!(memory.generation(), generation);
    assert_eq!(
        unsafe { core::ptr::read_volatile((frame + 17) as *const u8) },
        0x5a
    );
    memory
        .resize_transaction(4113, |start, end, commit| {
            assert_eq!((start, end), (4096, 8192));
            // The VM adapter still owns suspended mappings at this point.
            assert_eq!(
                unsafe { core::ptr::read_volatile((frame + 17) as *const u8) },
                0x5a
            );
            let committed = commit.commit();
            // Restoring a retained PTE is safe only after both operations finish.
            assert_eq!(
                unsafe { core::ptr::read_volatile((frame + 16) as *const u8) },
                0x5a
            );
            assert_eq!(
                unsafe { core::ptr::read_volatile((frame + 17) as *const u8) },
                0
            );
            Ok(committed)
        })
        .unwrap();
    assert_eq!(memory.length(), 4113);
    assert_ne!(memory.generation(), generation);
    paging::release_user_frame(frame);
}

#[test]
fn private_byte_snapshot_is_rejected_after_resize_even_when_size_returns_to_original() {
    let memory = shared_memory::SharedMemory::new(4096, 1).unwrap();
    memory.write_at(17, &[0xa7]).unwrap();
    let generation = memory.generation();
    let mut snapshot = [0u8; 4096];
    memory.read_at(0, &mut snapshot).unwrap();
    assert_eq!(snapshot[17], 0xa7);
    memory.resize_with(0, |_, _| Ok(())).unwrap();
    memory.resize_with(4096, |_, _| Ok(())).unwrap();
    assert_eq!(
        memory.with_generation(generation, || -> Result<(), u64> {
            panic!("size equality alone must not authorize stale private bytes")
        }),
        Err(NativeError::NotReady.into_raw())
    );
    let current = memory.generation();
    memory.read_at(0, &mut snapshot).unwrap();
    assert_eq!(snapshot[17], 0);
    assert_eq!(memory.with_generation(current, || Ok(snapshot[17])), Ok(0));
}

#[test]
fn resize_preparation_and_coordinator_failures_preserve_bytes_length_and_generation() {
    let memory = shared_memory::SharedMemory::new(8192, 2).unwrap();
    memory.write_at(4096, &[0x5a; 4096]).unwrap();
    let generation = memory.generation();
    PHYSICAL_OFFSET.set(None);
    let preparation = memory.resize_with(4113, |_, _| panic!("preflight must precede coordinator"));
    PHYSICAL_OFFSET.set(Some(0));
    assert_eq!(preparation, Err(NativeError::BackingFailure));
    for error in [
        NativeError::AccessDenied,
        NativeError::NotReady,
        NativeError::ResourceUnavailable,
    ] {
        assert_eq!(memory.resize_with(4113, |_, _| Err(error)), Err(error));
        assert_eq!(memory.length(), 8192);
        assert_eq!(memory.generation(), generation);
        let mut bytes = [0; 4096];
        assert_eq!(memory.read_at(4096, &mut bytes), Ok(bytes.len()));
        assert_eq!(bytes, [0x5a; 4096]);
    }
    memory.resize_with(4113, |_, _| Ok(())).unwrap();
    assert_eq!(memory.length(), 4113);
    assert_ne!(memory.generation(), generation);
    memory.resize_with(8192, |_, _| Ok(())).unwrap();
    let mut bytes = [1; 4096];
    memory.read_at(4096, &mut bytes).unwrap();
    assert_eq!(&bytes[..17], &[0x5a; 17]);
    assert!(bytes[17..].iter().all(|&byte| byte == 0));
}

#[test]
fn population_and_pin_failures_keep_storage_owned_and_can_be_retried() {
    let memory = shared_memory::SharedMemory::new(4096, 1).unwrap();
    FAIL_FRAME.set(true);
    let failed = memory.prepare_page(0);
    FAIL_FRAME.set(false);
    assert_eq!(failed, Err(NativeError::ResourceUnavailable));
    FAIL_RETAIN.set(true);
    let failed = memory.prepare_page(0);
    FAIL_RETAIN.set(false);
    assert_eq!(failed, Err(NativeError::ResourceUnavailable));
    let (frame, _) = memory.prepare_page(0).unwrap();
    assert_eq!(*frames().lock().unwrap().get(&frame).unwrap(), 2);
    PHYSICAL_OFFSET.set(None);
    let mut byte = [0xa5];
    let read = memory.read_at(0, &mut byte);
    let write = memory.write_at(0, &[0x5a]);
    PHYSICAL_OFFSET.set(Some(0));
    assert_eq!(read, Err(NativeError::BackingFailure));
    assert_eq!(write, Err(NativeError::BackingFailure));
    assert_eq!(byte, [0xa5]);
    memory.read_at(0, &mut byte).unwrap();
    assert_eq!(byte, [0]);
    drop(memory);
    assert_eq!(*frames().lock().unwrap().get(&frame).unwrap(), 1);
    paging::release_user_frame(frame);
    assert!(!frames().lock().unwrap().contains_key(&frame));
}
