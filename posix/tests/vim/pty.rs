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

fn wait_for(
    terminal: &mut Transport,
    buffer: &mut TerminalBuffer,
    stage: &str,
    ready: impl Fn(&vt100::Screen) -> bool,
) -> bool {
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
            return true;
        }
        if terminal.exited || Instant::now() >= deadline {
            report(&format!(
                "PTY {stage} failed: exited={} status={:?} screen={:?}",
                terminal.exited,
                terminal.exit_status,
                buffer.screen().contents()
            ));
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn until(
    terminal: &mut Transport,
    buffer: &mut TerminalBuffer,
    stage: &str,
    ready: impl Fn(&vt100::Screen) -> bool,
) {
    assert!(
        wait_for(terminal, buffer, stage, ready),
        "PTY {stage} failed"
    );
}

fn document_visible(screen: &vt100::Screen) -> bool {
    let mut rows = screen.rows(0, 80);
    rows.next().is_some_and(|s| s.trim_end() == "hello vim")
        && rows
            .next()
            .is_some_and(|s| s.trim_end() == "日本語 second line")
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
    let typed_visible = wait_for(&mut terminal, &mut buffer, "typed text", document_visible);
    // Use the same immediate VT replies and bounded writes as the real app.
    terminal.send(b"\x1b:wq\r").unwrap();
    until(&mut terminal, &mut buffer, "saved and restored msh", |s| {
        !s.alternate_screen() && s.contents().trim_end().ends_with(" $")
    });
    assert_eq!(
        fs::read(&path).unwrap(),
        "hello vim\n日本語 second line\n".as_bytes()
    );
    report("PASS exact bytes saved by the interactive Vim");
    terminal
        .send(format!("/system/bin/vim -Nu NONE -n -i NONE {}\r", path.display()).as_bytes())
        .unwrap();
    until(&mut terminal, &mut buffer, "reopened saved text", |s| {
        s.alternate_screen() && document_visible(s)
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
    // Even on a display failure, save/read-back and clean child exit above
    // retain evidence instead of interrupting Vim inside its error handler.
    assert!(
        typed_visible,
        "Vim did not display typed text before further input"
    );
    report("PASS actual PTY msh/Vim UTF-8 input, save, reopen and shell exit");
}
