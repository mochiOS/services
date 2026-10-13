use mochi_user_platform::syscall;
use std::time::Duration;

const _: [(); 8] = [(); core::mem::size_of::<libc::time_t>()];
const _: [(); 16] = [(); core::mem::size_of::<libc::timespec>()];

fn now() -> u64 {
    let mut instant = syscall::ClockInstant::default();
    syscall::call2(
        syscall::SyscallNumber::ClockRead,
        syscall::ClockId::Monotonic as u64,
        (&mut instant as *mut syscall::ClockInstant) as u64,
    )
    .unwrap();
    instant.seconds * 1_000_000_000 + u64::from(instant.nanoseconds)
}

fn main() {
    // Nonzero seconds exercise the formerly 32-bit field; Rust passes the
    // same timespec pointer for request and remainder, which must also work.
    for duration in [
        Duration::ZERO,
        Duration::from_nanos(1),
        Duration::from_millis(20),
        Duration::from_secs(1),
    ] {
        let start = now();
        std::thread::sleep(duration);
        assert!(now() - start >= duration.as_nanos() as u64);
    }
    let request = libc::timespec {
        tv_sec: 5_000_000_000,
        tv_nsec: 999_999_999,
    };
    assert_eq!(request.tv_sec, 5_000_000_000);
    let line = b"rust-sleep: PASS time_t=64, zero/subtick/millisecond/second sleeps\n";
    syscall::call2(
        syscall::SyscallNumber::DebugWrite,
        line.as_ptr() as u64,
        line.len() as u64,
    )
    .unwrap();
}
