//! Interrupt fork/exec handshakes while children are still being initialized.
//! A standalone process keeps fork out of a multithreaded test harness.
use std::sync::atomic::{AtomicUsize, Ordering};

static NOTIFICATIONS: AtomicUsize = AtomicUsize::new(0);
extern "C" fn notify(_: i32) {
    NOTIFICATIONS.fetch_add(1, Ordering::Relaxed);
}

fn wait(pid: i32) -> i32 {
    loop {
        let mut status = 0;
        let result = unsafe { libc::waitpid(pid, &mut status, 0) };
        if result == pid {
            return status;
        }
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EINTR)
        );
    }
}

fn exercise(spawn: bool) {
    let parent = unsafe { libc::getpid() };
    let controller = unsafe { libc::fork() };
    assert!(
        controller >= 0,
        "controller fork: {}",
        std::io::Error::last_os_error()
    );
    if controller == 0 {
        // Async-signal-safe C operations only; never unwind the copied Rust frames.
        let delay = libc::timespec {
            tv_sec: 0,
            tv_nsec: 1_000_000,
        };
        for _ in 0..256 {
            unsafe {
                libc::kill(parent, libc::SIGUSR1);
                libc::nanosleep(&delay, core::ptr::null_mut());
            }
        }
        unsafe { libc::_exit(0) }
    }
    let mut failures = Vec::new();
    for _ in 0..12 {
        if spawn {
            match std::process::Command::new(std::env::args_os().next().unwrap())
                .arg("--exit")
                .spawn()
            {
                Ok(mut child) => loop {
                    match child.wait() {
                        Ok(status) => {
                            assert!(status.success());
                            break;
                        }
                        Err(error) if error.raw_os_error() == Some(libc::EINTR) => continue,
                        Err(error) => panic!("child wait: {error}"),
                    }
                },
                Err(error) => failures.push(error.raw_os_error()),
            }
        } else {
            let pid = unsafe { libc::fork() };
            if pid == 0 {
                unsafe { libc::_exit(0) }
            }
            if pid < 0 {
                failures.push(std::io::Error::last_os_error().raw_os_error());
            } else {
                let status = wait(pid);
                assert!(libc::WIFEXITED(status));
                assert_eq!(libc::WEXITSTATUS(status), 0);
            }
        }
    }
    assert!(libc::WIFEXITED(wait(controller)));
    assert!(
        NOTIFICATIONS.load(Ordering::Relaxed) > 0,
        "no signal reached the parent"
    );
    println!(
        "spawn-notifications-312: {} failures={failures:?}",
        if spawn { "spawn" } else { "fork" }
    );
    assert!(
        failures.is_empty(),
        "notification was reported as a child-creation failure"
    );
}

fn main() {
    if std::env::args().any(|argument| argument == "--exit") {
        return;
    }
    unsafe {
        libc::alarm(60);
    }
    assert_ne!(
        unsafe { libc::signal(libc::SIGUSR1, notify as *const () as libc::sighandler_t) },
        libc::SIG_ERR
    );
    exercise(std::env::args().any(|argument| argument == "--spawn"));
    unsafe {
        libc::alarm(0);
    }
    println!("spawn-notifications-312: PASS");
}
