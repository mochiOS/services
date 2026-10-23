//! Diagnostics run inside allocator growth and must never allocate themselves.
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::ffi::c_int;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

#[path = "../../../user/crates/newlib-runtime/src/io_trace.rs"]
mod implementation;

thread_local! { static CHECK_ALLOCATION: Cell<bool> = const { Cell::new(false) }; }
static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
static NOW: AtomicU64 = AtomicU64::new(0);
static LOG: Mutex<([u8; 4096], usize)> = Mutex::new(([0; 4096], 0));
struct CountingAllocator;
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if CHECK_ALLOCATION.try_with(Cell::get).unwrap_or(false) {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
    }
}
#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;
fn monotonic_nanoseconds() -> Result<u64, c_int> {
    Ok(NOW.fetch_add(10, Ordering::Relaxed))
}
mod syscall {
    #[derive(Debug, PartialEq)]
    pub enum SyscallNumber {
        DebugWrite,
    }
    pub fn raw_syscall2(number: SyscallNumber, source: u64, length: u64) -> u64 {
        assert_eq!(number, SyscallNumber::DebugWrite);
        assert!(length <= 256);
        let bytes = unsafe { std::slice::from_raw_parts(source as *const u8, length as usize) };
        let mut log = super::LOG.lock().unwrap();
        let end = log.1 + bytes.len();
        let start = log.1;
        log.0[start..end].copy_from_slice(bytes);
        log.1 = end;
        length
    }
}

#[test]
fn allocator_context_tracing_is_heap_free_bounded_and_samples_long_read_sequences() {
    CHECK_ALLOCATION.set(true);
    for _ in 0..17 {
        assert!(implementation::read(3, 12).is_none());
        if let Some(trace) = implementation::read(3, 8192) {
            trace.finish(Ok::<_, i32>(8192));
        }
    }
    implementation::open(0).finish(Err::<i32, _>(2));
    assert!(implementation::growth(1024).is_none());
    implementation::growth(4 << 20)
        .unwrap()
        .finish(Ok::<_, i32>(0));
    for _ in 0..65536 {
        implementation::identity(true);
    }
    CHECK_ALLOCATION.set(false);
    assert_eq!(ALLOCATIONS.load(Ordering::Relaxed), 0);
    let log = LOG.lock().unwrap();
    let text = std::str::from_utf8(&log.0[..log.1]).unwrap();
    assert_eq!(text.matches("read begin").count(), 6);
    assert_eq!(text.matches("read end").count(), 6);
    assert!(text.contains("elapsed_ns=10"));
    assert!(text.contains("result=Err(2)"));
    assert!(text.contains("heap end"));
    assert_eq!(text.matches("native identity calls=").count(), 1);
    assert!(text.contains("native identity calls=65536 tls_available=true"));
}
