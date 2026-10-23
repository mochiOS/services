use posix_service::fifo::{Access, Channel, Error};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    static FAIL_NEXT: Cell<bool> = const { Cell::new(false) };
}

struct FaultAllocator;

unsafe impl GlobalAlloc for FaultAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if FAIL_NEXT.replace(false) {
            std::ptr::null_mut()
        } else {
            unsafe { System.alloc(layout) }
        }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if FAIL_NEXT.replace(false) {
            std::ptr::null_mut()
        } else {
            unsafe { System.realloc(pointer, layout, size) }
        }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: FaultAllocator = FaultAllocator;

#[test]
fn failed_open_admission_does_not_complete_waiters_or_register_a_writer() {
    let mut channel = Channel::default();
    FAIL_NEXT.set(true);
    let result = channel.open(Access::Read, false);
    let unconsumed = FAIL_NEXT.replace(false);
    assert!(!unconsumed);
    assert_eq!(result, Err(Error::NoMemory));
    // Fill spare slots with unmatched readers. The first failed growth leaves
    // no slot for a writer either; retry that allocation with the opposite role.
    let reader = channel.open(Access::Read, false).unwrap();
    for _ in 0..posix_service::fifo::MAX_OPEN_DESCRIPTIONS {
        FAIL_NEXT.set(true);
        let result = channel.open(Access::Read, false);
        let unconsumed = FAIL_NEXT.replace(false);
        if result == Err(Error::NoMemory) {
            assert!(!unconsumed);
            FAIL_NEXT.set(true);
            let result = channel.open(Access::Write, true);
            let unconsumed = FAIL_NEXT.replace(false);
            assert!(!unconsumed);
            assert_eq!(result, Err(Error::NoMemory));
            assert!(!channel.observe(reader).unwrap().open_ready);
            assert_eq!(channel.observe(reader).unwrap().writers, 0);
            return;
        }
        assert!(unconsumed);
        result.unwrap();
    }
    panic!("did not exercise a description allocation failure");
}

#[test]
fn failed_buffer_growth_preserves_queued_bytes_and_peer_counts() {
    let mut channel = Channel::default();
    let reader = channel.open(Access::Read, true).unwrap();
    let writer = channel.open(Access::Write, true).unwrap();
    FAIL_NEXT.set(true);
    let result = channel.write(writer, b"initial");
    let unconsumed = FAIL_NEXT.replace(false);
    assert!(!unconsumed);
    assert_eq!(result, Err(Error::NoMemory));
    assert_eq!(channel.observe(reader).unwrap().buffered_bytes, 0);
    channel.write(writer, b"keep").unwrap();
    let before = channel.observe(reader).unwrap();
    let input = [b'x'; 4096];
    FAIL_NEXT.set(true);
    let result = channel.write(writer, &input);
    let unconsumed = FAIL_NEXT.replace(false);
    assert!(!unconsumed);
    assert_eq!(result, Err(Error::NoMemory));
    assert_eq!(channel.observe(reader).unwrap(), before);
    let mut output = [0; 4];
    assert_eq!(channel.read(reader, &mut output), Ok(4));
    assert_eq!(&output, b"keep");
}
