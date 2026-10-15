//! Production VM object/cache code; substitute only IPC, scheduling, physical
//! frames and interrupt locks. Interleave mutations at the actual lock edges.
#![allow(dead_code)]
extern crate alloc;

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

thread_local! {
    static CACHE_EDGE: RefCell<Option<(usize, Box<dyn FnOnce()>)>> = RefCell::new(None);
    static LOWER_EDGE: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);
}

fn cache_edge<T>() {
    if !std::any::type_name::<T>().contains("CachedPage") {
        return;
    }
    let hook = CACHE_EDGE.with(|edge| {
        let mut edge = edge.borrow_mut();
        match edge.as_mut() {
            Some((remaining, _)) if *remaining > 1 => {
                *remaining -= 1;
                None
            }
            Some(_) => edge.take().map(|(_, hook)| hook),
            None => None,
        }
    });
    if let Some(hook) = hook {
        hook();
    }
}

mod interrupt {
    pub mod spinlock {
        pub struct SpinLock<T>(std::sync::Mutex<T>);
        impl<T> SpinLock<T> {
            pub const fn new(value: T) -> Self {
                Self(std::sync::Mutex::new(value))
            }
            pub fn lock(&self) -> std::sync::MutexGuard<'_, T> {
                crate::cache_edge::<T>();
                self.0.lock().unwrap()
            }
        }
    }
}

mod task {
    pub struct ProviderObject {
        pub endpoint_thread_id: u64,
        pub endpoint_slot: u16,
        pub endpoint_generation: u64,
    }
    pub fn yield_now() {
        std::thread::yield_now();
    }
    pub mod process {
        pub fn resize_shared_memory(
            _: &crate::shared_memory::SharedMemory,
            _: u64,
        ) -> Result<(), u64> {
            unreachable!("provider-only probe")
        }
    }
}

struct Lower {
    bytes: Vec<u8>,
    reads: usize,
}
static LOWER: Mutex<Lower> = Mutex::new(Lower {
    bytes: Vec::new(),
    reads: 0,
});

mod syscall {
    pub const EINVAL: u64 = (-22i64) as u64;
    pub const ENOMEM: u64 = (-12i64) as u64;
    pub const EIO: u64 = (-5i64) as u64;
    pub const EAGAIN: u64 = (-11i64) as u64;
    pub mod handle {
        pub fn provider_read_at(
            _: &crate::task::ProviderObject,
            offset: u64,
            output: &mut [u8],
        ) -> Result<usize, u64> {
            let count = {
                let mut lower = crate::LOWER.lock().unwrap();
                lower.reads += 1;
                let start = usize::try_from(offset)
                    .map_err(|_| super::EINVAL)?
                    .min(lower.bytes.len());
                let count = output.len().min(lower.bytes.len() - start);
                output[..count].copy_from_slice(&lower.bytes[start..start + count]);
                count
            };
            let hook = crate::LOWER_EDGE.with(|edge| edge.borrow_mut().take());
            if let Some(hook) = hook {
                hook();
            }
            Ok(count)
        }
        pub fn provider_write_at(
            _: &crate::task::ProviderObject,
            offset: u64,
            input: &[u8],
        ) -> Result<usize, u64> {
            let start = usize::try_from(offset).map_err(|_| super::EINVAL)?;
            let mut lower = crate::LOWER.lock().unwrap();
            let length = (start + input.len()).max(lower.bytes.len());
            lower.bytes.resize(length, 0);
            lower.bytes[start..start + input.len()].copy_from_slice(input);
            Ok(input.len())
        }
        pub fn provider_sync(_: &crate::task::ProviderObject) -> Result<(), u64> {
            Ok(())
        }
    }
}

// Only provider backing is used. RAM is a separate production implementation
// with its own generation/revocation tests.
mod shared_memory {
    pub struct SharedMemory;
    impl SharedMemory {
        pub fn id(&self) -> u64 {
            unreachable!()
        }
        pub fn length(&self) -> u64 {
            unreachable!()
        }
        pub fn generation(&self) -> u64 {
            unreachable!()
        }
        pub fn with_generation<T>(
            &self,
            _: u64,
            _: impl FnOnce() -> Result<T, u64>,
        ) -> Result<T, u64> {
            unreachable!()
        }
        pub fn read_at(&self, _: u64, _: &mut [u8]) -> Result<usize, u64> {
            unreachable!()
        }
        pub fn write_at(&self, _: u64, _: &[u8]) -> Result<usize, u64> {
            unreachable!()
        }
        pub fn prepare_page(&self, _: u64) -> Result<(u64, u64), u64> {
            unreachable!()
        }
    }
}

static FRAMES: Mutex<BTreeMap<u64, usize>> = Mutex::new(BTreeMap::new());
mod frame {
    pub struct Frame(pub u64);
    impl Frame {
        pub fn start_address(&self) -> Address {
            Address(self.0)
        }
    }
    pub struct Address(u64);
    impl Address {
        pub fn as_u64(&self) -> u64 {
            self.0
        }
    }
    pub fn allocate_zeroed_frame() -> Result<Frame, ()> {
        let frame = Box::into_raw(Box::new([0u8; 4096])) as u64;
        crate::FRAMES.lock().unwrap().insert(frame, 1);
        Ok(Frame(frame))
    }
    pub fn deallocate_frame(frame: Frame) -> Result<(), ()> {
        super::paging::release_user_frame(frame.0);
        Ok(())
    }
}
mod paging {
    pub fn physical_memory_offset() -> Option<u64> {
        Some(0)
    }
    pub fn retain_shared_user_frame(frame: u64) -> Result<(), ()> {
        *crate::FRAMES.lock().unwrap().get_mut(&frame).ok_or(())? += 1;
        Ok(())
    }
    pub fn user_frame_has_multiple_owners(frame: u64) -> bool {
        crate::FRAMES
            .lock()
            .unwrap()
            .get(&frame)
            .copied()
            .unwrap_or(0)
            > 1
    }
    pub fn release_user_frame(frame: u64) {
        let mut frames = crate::FRAMES.lock().unwrap();
        let count = frames.get_mut(&frame).expect("frame double release");
        *count -= 1;
        if *count == 0 {
            frames.remove(&frame);
            unsafe {
                drop(Box::from_raw(frame as *mut [u8; 4096]));
            }
        }
    }
    pub fn map_shared_frame_to_user(
        _: u64,
        _: u64,
        frame: u64,
        _: bool,
        _: bool,
    ) -> Result<(), ()> {
        assert!(crate::FRAMES.lock().unwrap().contains_key(&frame));
        Ok(())
    }
}

#[path = "../../../core/src/mem/cache_range.rs"]
pub mod cache_range;
#[path = "../../../core/src/mem/object_io.rs"]
pub mod object_io;
#[path = "../../../core/src/mem/vm_object.rs"]
pub mod vm_object;
mod mem {
    pub(crate) use crate::{frame, paging};
}

fn provider_object() -> vm_object::VmObject {
    vm_object::VmObject::provider(
        Arc::new(task::ProviderObject {
            endpoint_thread_id: 17,
            endpoint_slot: 2,
            endpoint_generation: 8,
        }),
        93,
    )
}

fn reset_lower(bytes: &[u8]) {
    *LOWER.lock().unwrap() = Lower {
        bytes: bytes.to_vec(),
        reads: 0,
    };
}

#[test]
fn production_cache_never_republishes_invalidated_lower_snapshots() {
    let object = provider_object();
    reset_lower(b"old");
    // The lower read has copied old bytes, but a completed write did not find
    // a resident page to update. Epoch rejection must cause a new lower read.
    LOWER_EDGE.with(|edge| {
        *edge.borrow_mut() = Some(Box::new(|| {
            provider_object().write_at(0, b"new").unwrap();
        }))
    });
    assert_eq!(&object.page(0).unwrap()[..3], b"new");
    assert_eq!(LOWER.lock().unwrap().reads, 2);
    object.invalidate();

    reset_lower(b"old");
    // A new resident page wins over the in-flight lower snapshot instead of
    // forcing another lower read or overwriting the staged dirty bytes.
    LOWER_EDGE.with(|edge| {
        *edge.borrow_mut() = Some(Box::new(|| {
            provider_object().stage_write_at(0, b"new").unwrap();
        }))
    });
    assert_eq!(&object.page(0).unwrap()[..3], b"new");
    assert_eq!(LOWER.lock().unwrap().reads, 2);
    object.invalidate();

    reset_lower(b"old");
    // The third lock is final shared-frame preparation, after loading and
    // admitting the page. Revoke it before that lock is acquired.
    CACHE_EDGE.with(|edge| {
        *edge.borrow_mut() = Some((
            3,
            Box::new(|| {
                provider_object().invalidate();
                LOWER.lock().unwrap().bytes = b"new".to_vec();
            }),
        ))
    });
    let prepared = object.prepare_shared_page(0).unwrap();
    assert_eq!(&object.page(0).unwrap()[..3], b"new");
    assert_eq!(LOWER.lock().unwrap().reads, 2);
    drop(prepared);
    object.invalidate();
    assert!(FRAMES.lock().unwrap().is_empty());

    reset_lower(b"old");
    CACHE_EDGE.with(|edge| {
        *edge.borrow_mut() = Some((
            3,
            Box::new(|| {
                provider_object().invalidate();
                LOWER.lock().unwrap().bytes = b"new".to_vec();
            }),
        ))
    });
    object.stage_write_at(1, b"X").unwrap();
    assert_eq!(&object.page(0).unwrap()[..3], b"nXw");
    assert_eq!(LOWER.lock().unwrap().reads, 2);
    object.invalidate();

    // A concurrent shrink to empty must not manufacture a successful page.
    reset_lower(b"old");
    LOWER_EDGE.with(|edge| {
        *edge.borrow_mut() = Some(Box::new(|| {
            provider_object().invalidate();
            LOWER.lock().unwrap().bytes.clear();
        }))
    });
    assert!(matches!(
        object.page(0),
        Err(vm_object::VmPageError::OutsideBacking)
    ));
    assert_eq!(LOWER.lock().unwrap().reads, 2);
    object.invalidate();

    // Keep every bounded-cache entry pinned. Capacity bypass must still
    // validate the epoch, retry stale lower data and return a fresh snapshot.
    const CACHE_PAGES: usize = 256;
    reset_lower(&vec![0x11; (CACHE_PAGES + 1) * 4096]);
    let pins: Vec<_> = (0..CACHE_PAGES)
        .map(|index| object.prepare_shared_page(index as u64).unwrap())
        .collect();
    assert_eq!(FRAMES.lock().unwrap().len(), CACHE_PAGES);
    let before = LOWER.lock().unwrap().reads;
    LOWER_EDGE.with(|edge| {
        *edge.borrow_mut() = Some(Box::new(|| {
            provider_object()
                .write_at((CACHE_PAGES * 4096) as u64, b"new")
                .unwrap();
        }));
    });
    assert_eq!(&object.page(CACHE_PAGES as u64).unwrap()[..3], b"new");
    assert_eq!(LOWER.lock().unwrap().reads, before + 2);
    // No admission was possible: a second read must go back to the provider.
    assert_eq!(&object.page(CACHE_PAGES as u64).unwrap()[..3], b"new");
    assert_eq!(LOWER.lock().unwrap().reads, before + 3);
    assert_eq!(FRAMES.lock().unwrap().len(), CACHE_PAGES);
    drop(pins);
    object.invalidate();
    assert!(FRAMES.lock().unwrap().is_empty());
}
