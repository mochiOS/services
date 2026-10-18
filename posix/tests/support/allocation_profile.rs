//! Test-only requested-allocation counters, not native resident-memory usage.
//! TSC observations include scheduling/waiting and are not CPU-time accounting.
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct Counters {
    calls: AtomicU64,
    bytes: AtomicU64,
    cycles: AtomicU64,
    frees: AtomicU64,
    free_cycles: AtomicU64,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Sample {
    pub calls: u64,
    pub bytes: u64,
    pub cycles: u64,
    pub frees: u64,
    pub free_cycles: u64,
}

impl Sample {
    pub fn since(&self, previous: &Self) -> Self {
        Self {
            calls: self.calls.wrapping_sub(previous.calls),
            bytes: self.bytes.wrapping_sub(previous.bytes),
            cycles: self.cycles.wrapping_sub(previous.cycles),
            frees: self.frees.wrapping_sub(previous.frees),
            free_cycles: self.free_cycles.wrapping_sub(previous.free_cycles),
        }
    }
}

impl Counters {
    pub fn allocation(&self, bytes: usize, cycles: u64) {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(bytes as u64, Ordering::Relaxed);
        self.cycles.fetch_add(cycles, Ordering::Relaxed);
    }

    pub fn deallocation(&self, cycles: u64) {
        self.frees.fetch_add(1, Ordering::Relaxed);
        self.free_cycles.fetch_add(cycles, Ordering::Relaxed);
    }

    pub fn sample(&self) -> Sample {
        Sample {
            calls: self.calls.load(Ordering::Relaxed),
            bytes: self.bytes.load(Ordering::Relaxed),
            cycles: self.cycles.load(Ordering::Relaxed),
            frees: self.frees.load(Ordering::Relaxed),
            free_cycles: self.free_cycles.load(Ordering::Relaxed),
        }
    }
}

pub static COUNTERS: Counters = Counters {
    calls: AtomicU64::new(0),
    bytes: AtomicU64::new(0),
    cycles: AtomicU64::new(0),
    frees: AtomicU64::new(0),
    free_cycles: AtomicU64::new(0),
};

pub fn cycle_counter() -> u64 {
    #[cfg(target_arch = "x86_64")]
    // Safety: x86-64 provides TSC and SSE2; mochiOS permits user TSC reads.
    unsafe {
        std::arch::x86_64::_mm_lfence();
        let value = std::arch::x86_64::_rdtsc();
        std::arch::x86_64::_mm_lfence();
        value
    }
    #[cfg(not(target_arch = "x86_64"))]
    0
}

pub struct MeasuredSystem;

// Safety: all operations delegate unchanged arguments/results to System.
unsafe impl GlobalAlloc for MeasuredSystem {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let start = cycle_counter();
        let result = unsafe { System.alloc(layout) };
        COUNTERS.allocation(layout.size(), cycle_counter().saturating_sub(start));
        result
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let start = cycle_counter();
        let result = unsafe { System.alloc_zeroed(layout) };
        COUNTERS.allocation(layout.size(), cycle_counter().saturating_sub(start));
        result
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let start = cycle_counter();
        let result = unsafe { System.realloc(pointer, layout, size) };
        COUNTERS.allocation(size, cycle_counter().saturating_sub(start));
        result
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        let start = cycle_counter();
        unsafe { System.dealloc(pointer, layout) };
        COUNTERS.deallocation(cycle_counter().saturating_sub(start));
    }
}
