//! Diagnostic child of the real verified stdio launcher. Never grants rights.
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

unsafe extern "C" {
    fn login_tty(fd: i32) -> i32;
}
static INTERRUPTED: AtomicBool = AtomicBool::new(false);
extern "C" fn interrupted(_: i32) {
    INTERRUPTED.store(true, Ordering::Relaxed);
}
fn ensure(condition: bool, message: &str) -> io::Result<()> {
    if condition {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}
fn write(fd: i32, bytes: &[u8]) -> io::Result<()> {
    let mut remaining = bytes;
    while !remaining.is_empty() {
        let count = unsafe { libc::write(fd, remaining.as_ptr().cast(), remaining.len()) };
        if count < 0 {
            return Err(io::Error::last_os_error());
        }
        ensure(count != 0, "zero-length PTY write")?;
        remaining = &remaining[count as usize..];
    }
    Ok(())
}
fn record(expected: &[u8]) -> io::Result<()> {
    let mut bytes = [0; 128];
    let count = unsafe { libc::read(0, bytes.as_mut_ptr().cast(), bytes.len()) };
    if count < 0 {
        return Err(io::Error::last_os_error());
    }
    ensure(
        &bytes[..count as usize] == expected,
        "PTY canonical record mismatch",
    )
}
fn exercise() -> io::Result<()> {
    ensure(unsafe { login_tty(0) } == 0, "login_tty failed")?;
    let pid = unsafe { libc::getpid() };
    ensure(
        unsafe { libc::getsid(0) } == pid,
        "child did not become session leader",
    )?;
    ensure(
        unsafe { libc::getpgrp() } == pid,
        "child did not become group leader",
    )?;
    for fd in 0..3 {
        ensure(unsafe { libc::isatty(fd) } == 1, "stdio is not a terminal")?;
        ensure(
            unsafe { libc::fcntl(fd, libc::F_GETFL) } & libc::O_ACCMODE == libc::O_RDWR,
            "stdio lost O_RDWR",
        )?;
        ensure(
            unsafe { libc::tcgetpgrp(fd) } == pid,
            "wrong foreground group",
        )?;
        ensure(
            unsafe { libc::tcgetsid(fd) } == pid,
            "wrong controlling session",
        )?;
    }
    write(1, b"pty-launch-310: READY\n")?;
    record("hello 日本語\n".as_bytes())?;
    write(1, b"pty-launch-310: STDOUT\n")?;
    write(2, b"pty-launch-310: STDERR\n")?;
    write(1, b"pty-launch-310: READY_EOF\n")?;
    record(b"")?;
    write(1, b"pty-launch-310: READY_AFTER_EOF\n")?;
    record(b"after\n")?;
    let previous =
        unsafe { libc::signal(libc::SIGINT, interrupted as *const () as libc::sighandler_t) };
    ensure(
        previous != libc::SIG_ERR,
        "signal handler installation failed",
    )?;
    write(1, b"pty-launch-310: READY_SIGNAL\n")?;
    let deadline = Instant::now() + Duration::from_secs(4);
    while !INTERRUPTED.load(Ordering::Relaxed) {
        ensure(Instant::now() < deadline, "PTY did not deliver SIGINT")?;
        std::thread::sleep(Duration::from_millis(5));
    }
    write(1, b"pty-launch-310: PASS_CHILD\n")
}
pub fn run() -> ! {
    unsafe {
        libc::alarm(20);
    }
    let result = exercise();
    if let Err(error) = &result {
        let text = format!("pty-launch-310: FAIL_CHILD {error}\n");
        let _ = mochi_user_platform::syscall::call2(
            mochi_user_platform::syscall::SyscallNumber::DebugWrite,
            text.as_ptr() as u64,
            text.len() as u64,
        );
    }
    unsafe {
        libc::alarm(0);
    }
    std::process::exit(if result.is_ok() { 0 } else { 1 })
}
