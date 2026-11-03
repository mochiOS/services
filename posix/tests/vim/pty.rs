//! Exercise Terminal's actual transport/parser and verified msh login launch.
use crate::{model::TerminalBuffer, settings::Profile, transport::Transport};
use std::{
    fs,
    path::Path,
    time::{Duration, Instant},
};

fn report(message: &str) {
    println!("native-vim: {message}");
    let line = format!("native-vim: {message}\n");
    use mochi_user_platform::syscall::{self, SyscallNumber};
    syscall::call2(
        SyscallNumber::DebugWrite,
        line.as_ptr() as u64,
        line.len() as u64,
    )
    .unwrap();
}

fn until(
    terminal: &mut Transport,
    buffer: &mut TerminalBuffer,
    stage: &str,
    ready: impl Fn(&vt100::Screen) -> bool,
) {
    let start = Instant::now();
    let deadline = start + Duration::from_secs(30);
    loop {
        terminal.poll(buffer);
        let replies = buffer.replies();
        if !replies.is_empty() {
            terminal.send(&replies).unwrap();
        }
        if ready(buffer.screen()) {
            report(&format!(
                "PTY {stage} after {}ms",
                start.elapsed().as_millis()
            ));
            return;
        }
        if terminal.exited || Instant::now() >= deadline {
            report(&format!(
                "PTY {stage} failed: exited={} status={:?} screen={:?}",
                terminal.exited,
                terminal.exit_status,
                buffer.screen().contents()
            ));
            panic!("PTY {stage} failed");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

pub(super) fn run(directory: &Path) {
    let mut terminal = Transport::start(80, 24, &Profile::default()).unwrap();
    let mut buffer = TerminalBuffer::new(100);
    until(&mut terminal, &mut buffer, "msh prompt", |s| {
        s.contents().trim_end().ends_with(" $")
    });
    let path = directory.join("interactive.txt");
    terminal
        .send(format!("/system/bin/vim -Nu NONE -n -i NONE {}\r", path.display()).as_bytes())
        .unwrap();
    until(&mut terminal, &mut buffer, "Vim alternate screen", |s| {
        s.alternate_screen() && s.contents().contains("interactive.txt")
    });
    terminal.send(b"i").unwrap();
    until(&mut terminal, &mut buffer, "insert mode", |s| {
        s.contents().contains("-- INSERT --")
    });
    terminal
        .send("hello vim\r日本語 second line".as_bytes())
        .unwrap();
    until(&mut terminal, &mut buffer, "typed text", |s| {
        let text = s.contents();
        text.starts_with("hello vim\n日本語 second line")
    });
    // Use the same immediate VT replies and bounded writes as the real app.
    terminal.send(b"\x1b:wq\r").unwrap();
    until(&mut terminal, &mut buffer, "saved and restored msh", |s| {
        !s.alternate_screen() && s.contents().trim_end().ends_with(" $")
    });
    assert_eq!(
        fs::read(&path).unwrap(),
        "hello vim\n日本語 second line\n".as_bytes()
    );
    terminal
        .send(format!("/system/bin/vim -Nu NONE -n -i NONE {}\r", path.display()).as_bytes())
        .unwrap();
    until(&mut terminal, &mut buffer, "reopened saved text", |s| {
        s.alternate_screen() && s.contents().starts_with("hello vim\n日本語 second line")
    });
    terminal.send(b":q\r").unwrap();
    until(&mut terminal, &mut buffer, "reopened Vim exited", |s| {
        !s.alternate_screen() && s.contents().trim_end().ends_with(" $")
    });
    terminal.send(b"exit\r").unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    while !terminal.exited && Instant::now() < deadline {
        terminal.poll(&mut buffer);
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(terminal.exited, "login shell did not exit");
    assert_eq!(terminal.exit_status, Some(0));
    report("PASS actual PTY msh/Vim UTF-8 input, save, reopen and shell exit");
}
