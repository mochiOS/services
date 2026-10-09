extern crate alloc;

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
mod syscall {
    pub const EINVAL: u64 = (-22i64) as u64;
    pub const ENOMEM: u64 = (-12i64) as u64;
    pub const EIO: u64 = (-5i64) as u64;
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
        Some(0)
    }
    pub fn retain_shared_user_frame(address: u64) -> Result<(), ()> {
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
        Err(syscall::EINVAL)
    );
    assert_eq!(memory.write_at(u64::MAX, b"x"), Err(syscall::EINVAL));
    assert_eq!(memory.write_at(3 * 4096 - 1, b"xy"), Err(syscall::EINVAL));
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
    assert_eq!(memory.retain_page(1), Err(syscall::EINVAL));
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
