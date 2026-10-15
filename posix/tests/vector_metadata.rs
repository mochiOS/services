use std::ffi::{c_int, c_void};
use std::ptr;
use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};
const EINVAL: c_int = 22;
const ENOMEM: c_int = 12;
static SERIAL: Mutex<()> = Mutex::new(());
static FAIL: AtomicBool = AtomicBool::new(false);
static ALLOCATIONS: Mutex<std::collections::BTreeMap<usize, usize>> =
    Mutex::new(std::collections::BTreeMap::new());
unsafe fn malloc(length: usize) -> *mut c_void {
    if FAIL.load(Ordering::Relaxed) {
        return ptr::null_mut();
    }
    let pointer =
        unsafe { std::alloc::alloc(std::alloc::Layout::from_size_align(length, 16).unwrap()) };
    ALLOCATIONS.lock().unwrap().insert(pointer as usize, length);
    pointer.cast()
}
unsafe fn free(pointer: *mut c_void) {
    let length = ALLOCATIONS
        .lock()
        .unwrap()
        .remove(&(pointer as usize))
        .unwrap();
    unsafe {
        std::alloc::dealloc(
            pointer.cast(),
            std::alloc::Layout::from_size_align(length, 16).unwrap(),
        )
    };
}
#[path = "../../../user/crates/newlib-runtime/src/vector_metadata.rs"]
mod implementation;
use implementation::VectorMetadata;

#[test]
fn small_vectors_do_not_allocate_or_consume_a_maximum_size_stack_frame() {
    let _serial = SERIAL.lock().unwrap();
    assert!(std::mem::size_of::<VectorMetadata>() <= 160);
    for count in [0, 1, 8] {
        let mut metadata = VectorMetadata::new(count).unwrap();
        assert!(ALLOCATIONS.lock().unwrap().is_empty());
        for index in 0..count {
            assert_eq!(metadata.get(index), (ptr::null_mut(), 0));
            metadata.set(index, (0x1000 + index) as *mut c_void, index + 1);
            assert_eq!(
                metadata.get(index),
                ((0x1000 + index) as *mut c_void, index + 1)
            );
        }
    }
}
#[test]
fn overflow_is_initialized_bounded_and_reclaimed_for_all_supported_counts() {
    let _serial = SERIAL.lock().unwrap();
    for count in [9, 17, 1024] {
        let mut metadata = VectorMetadata::new(count).unwrap();
        assert_eq!(
            ALLOCATIONS
                .lock()
                .unwrap()
                .values()
                .copied()
                .collect::<Vec<_>>(),
            [(count - 8) * 16]
        );
        for index in 0..count {
            assert_eq!(metadata.get(index), (ptr::null_mut(), 0));
            metadata.set(index, (0x1000 + index) as *mut c_void, index + 1);
        }
        for index in 0..count {
            assert_eq!(
                metadata.get(index),
                ((0x1000 + index) as *mut c_void, index + 1)
            );
        }
        drop(metadata);
        assert!(ALLOCATIONS.lock().unwrap().is_empty());
    }
}
#[test]
fn invalid_counts_and_allocation_failures_do_not_leak() {
    let _serial = SERIAL.lock().unwrap();
    for count in [1025, usize::MAX] {
        assert!(matches!(VectorMetadata::new(count), Err(EINVAL)));
    }
    assert!(ALLOCATIONS.lock().unwrap().is_empty());
    FAIL.store(true, Ordering::Relaxed);
    assert!(VectorMetadata::new(8).is_ok());
    assert!(matches!(VectorMetadata::new(9), Err(ENOMEM)));
    FAIL.store(false, Ordering::Relaxed);
    assert!(ALLOCATIONS.lock().unwrap().is_empty());
}
