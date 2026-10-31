//! Real Terminal -> capability broker -> measured msh with explicit PTY stdio.
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::time::{Duration, Instant};
unsafe extern "C" {
    fn openpty(
        master: *mut i32,
        slave: *mut i32,
        name: *mut i8,
        attributes: *const core::ffi::c_void,
        window: *const core::ffi::c_void,
    ) -> i32;
}
fn ensure(condition: bool, message: &str) -> io::Result<()> {
    if condition {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}
fn trace(text: &str) {
    let _ = mochi_user_platform::syscall::call2(
        mochi_user_platform::syscall::SyscallNumber::DebugWrite,
        text.as_ptr() as u64,
        text.len() as u64,
    );
}
struct Child(Option<i32>);
impl Drop for Child {
    fn drop(&mut self) {
        if let Some(pid) = self.0.take() {
            unsafe {
                libc::kill(pid, libc::SIGKILL);
                libc::waitpid(pid, core::ptr::null_mut(), 0);
            }
        }
    }
}
fn until(master: &mut File, transcript: &mut Vec<u8>, needle: &[u8]) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(6);
    while !transcript
        .windows(needle.len())
        .any(|bytes| bytes == needle)
    {
        ensure(Instant::now() < deadline, "timed out reading PTY response")?;
        let mut bytes = [0; 1024];
        match master.read(&mut bytes) {
            Ok(0) => return Err(io::Error::other("PTY closed before response")),
            Ok(length) => transcript.extend_from_slice(&bytes[..length]),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => return Err(error),
        }
        ensure(transcript.len() < 32768, "unbounded PTY transcript")?;
    }
    Ok(())
}
fn exercise() -> io::Result<()> {
    let (mut master, mut slave) = (-1, -1);
    if unsafe {
        openpty(
            &mut master,
            &mut slave,
            core::ptr::null_mut(),
            core::ptr::null(),
            core::ptr::null(),
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut master = unsafe { File::from_raw_fd(master) };
    let slave = unsafe { File::from_raw_fd(slave) };
    for fd in [master.as_raw_fd(), slave.as_raw_fd()] {
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    let flags = unsafe { libc::fcntl(master.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let pid = crate::native_launch::spawn(
        "/system/bin/msh",
        &["/system/bin/msh", "--stdio-input", "--pty-launch-child-310"],
        [slave.as_raw_fd(); 3],
    )?;
    let mut child = Child(Some(pid));
    drop(slave);
    trace("pty-launch-310: child launched through real stdio broker; testing session\n");
    let mut transcript = Vec::new();
    until(&mut master, &mut transcript, b"pty-launch-310: READY\r\n")?;
    trace("pty-launch-310: session and all O_RDWR descriptors passed\n");
    master.write_all("hello 日本語\n".as_bytes())?;
    until(
        &mut master,
        &mut transcript,
        b"pty-launch-310: READY_EOF\r\n",
    )?;
    ensure(
        transcript
            .windows(b"pty-launch-310: STDOUT\r\n".len())
            .any(|part| part == b"pty-launch-310: STDOUT\r\n"),
        "missing stdout",
    )?;
    ensure(
        transcript
            .windows(b"pty-launch-310: STDERR\r\n".len())
            .any(|part| part == b"pty-launch-310: STDERR\r\n"),
        "missing stderr",
    )?;
    trace("pty-launch-310: canonical UTF-8 input and both output slots passed\n");
    master.write_all(b"\x04")?;
    until(
        &mut master,
        &mut transcript,
        b"pty-launch-310: READY_AFTER_EOF\r\n",
    )?;
    master.write_all(b"after\n")?;
    until(
        &mut master,
        &mut transcript,
        b"pty-launch-310: READY_SIGNAL\r\n",
    )?;
    trace("pty-launch-310: EOF record is not permanent hangup; testing foreground SIGINT\n");
    master.write_all(b"\x03")?;
    until(
        &mut master,
        &mut transcript,
        b"pty-launch-310: PASS_CHILD\r\n",
    )?;
    let mut status = 0;
    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
    if waited == pid {
        child.0 = None;
    }
    ensure(
        waited == pid && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "PTY child failed",
    )?;
    trace(
        "pty-launch-310: PASS actual verified launcher, PTY rights, session/foreground group, canonical UTF-8, stdout/stderr, EOF recovery, SIGINT and wait; no grant\n",
    );
    Ok(())
}
pub fn run() {
    trace("pty-launch-310: starting real Terminal launcher probe\n");
    if let Err(error) = exercise() {
        trace(&format!("pty-launch-310: FAIL {error}\n"));
    }
}
