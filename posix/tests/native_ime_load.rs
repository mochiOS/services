//! Compare std I/O and the production IME engine under the same native runtime.
#[cfg(target_os = "mochios")]
#[allow(dead_code)]
#[path = "native_rust_dictionary_read.rs"]
mod dictionary_io;

#[cfg(target_os = "mochios")]
#[path = "support/allocation_profile.rs"]
mod allocation_profile;

#[cfg(target_os = "mochios")]
#[global_allocator]
static ALLOCATOR: allocation_profile::MeasuredSystem = allocation_profile::MeasuredSystem;

#[cfg(target_os = "mochios")]
fn fresh_page_writes() {
    use mochi_user_syscall::{
        MEMORY_ACCESS_READ, MEMORY_ACCESS_WRITE, SyscallNumber, call2, call6,
    };
    // Native self-VM probe, not a bypass in a POSIX allocation implementation.
    // Write first: a preliminary zero read could add a second COW fault.
    const LENGTH: usize = 32 * 1024 * 1024;
    let start = std::time::Instant::now();
    let base = call6(
        SyscallNumber::MemoryMap,
        0,
        LENGTH as u64,
        (MEMORY_ACCESS_READ | MEMORY_ACCESS_WRITE) as u64,
        0,
        0,
        0,
    )
    .expect("native anonymous mapping failed");
    assert!(base != 0 && base % 4096 == 0);
    let map_ms = start.elapsed().as_millis();
    let start = std::time::Instant::now();
    for offset in (0..LENGTH).step_by(4096) {
        // Safety: the live native mapping grants write access to this range.
        unsafe { (base as *mut u8).add(offset).write_volatile(0x7a) };
    }
    let first_ms = start.elapsed().as_millis();
    let start = std::time::Instant::now();
    for offset in (0..LENGTH).step_by(4096) {
        // Safety: each initialized byte is still covered by the same mapping.
        unsafe {
            let byte = (base as *mut u8).add(offset);
            assert_eq!(byte.read_volatile(), 0x7a);
            byte.write_volatile(0x3b);
        }
    }
    let warm_ms = start.elapsed().as_millis();
    call2(SyscallNumber::MemoryUnmap, base, LENGTH as u64).expect("native unmap failed");
    eprintln!(
        "native-ime-load: page_writes bytes={LENGTH} map_ms={map_ms} first_ms={first_ms} warm_ms={warm_ms}"
    );
}

#[cfg(target_os = "mochios")]
fn main() {
    dictionary_io::run().expect("dictionary I/O failed before parser initialization");
    fresh_page_writes();
    eprintln!("native-ime-load: opening production engine");
    let before = allocation_profile::COUNTERS.sample();
    let cycles = allocation_profile::cycle_counter();
    let start = std::time::Instant::now();
    let engine = mochios_ime_engine::Engine::open(input::ime::DICTIONARY_PATH)
        .expect("production dictionary could not be initialized");
    let elapsed_cycles = allocation_profile::cycle_counter().saturating_sub(cycles);
    let allocations = allocation_profile::COUNTERS.sample().since(&before);
    eprintln!(
        "native-ime-load: loaded elapsed_ms={}",
        start.elapsed().as_millis()
    );
    eprintln!(
        "native-ime-load: allocation_profile={allocations:?} elapsed_cycles={elapsed_cycles}"
    );
    let candidates = engine.candidates("こんにちは", 5);
    assert!(!candidates.is_empty());
    eprintln!("native-ime-load: PASS candidate={}", candidates[0].text);
}

#[cfg(not(target_os = "mochios"))]
fn main() {
    eprintln!("native-ime-load: SKIP (requires mochiOS)");
}
