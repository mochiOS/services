//! Run the actual job/terminal code on a host PTY. The local dispatch shims
//! below replace only native IPC/builtin presentation, not process/TTY effects.
use std::{
    io::{self, Read, Write},
    os::fd::{AsRawFd, FromRawFd},
    process::{Command, Stdio},
    sync::atomic::AtomicU64,
    time::{Duration, Instant},
};
#[path = "../../../binaries/msh/src/command.rs"]
mod command;
#[path = "../../../binaries/msh/src/job_state.rs"]
mod job_state;
#[path = "../../../binaries/msh/src/pty_shell.rs"]
mod production;
#[path = "../../../binaries/msh/src/syntax.rs"]
mod syntax;
static SHELL_ENDPOINT: AtomicU64 = AtomicU64::new(0);
struct Policy {
    deny_prompts: bool,
    background: bool,
}
fn parse_external_options(args: &[String]) -> io::Result<(Policy, &[String])> {
    Ok((
        Policy {
            deny_prompts: true,
            background: false,
        },
        args,
    ))
}
fn resolve_command_path(path: &str) -> io::Result<String> {
    Ok(path.to_owned())
}
fn apply_redirects(_: &mut Command, redirects: &[syntax::Redirect]) -> io::Result<()> {
    assert!(redirects.is_empty());
    Ok(())
}
fn builtin_output(redirects: &[syntax::Redirect]) -> io::Result<Box<dyn Write>> {
    assert!(redirects.is_empty());
    Ok(Box::new(io::stdout()))
}
fn drain_terminal_feedback() -> io::Result<()> {
    Ok(())
}
fn print_prompt() -> io::Result<()> {
    print!("msh311$ ");
    io::stdout().flush()
}
fn run_command(line: &str, _: Option<()>) -> io::Result<bool> {
    let parsed = syntax::parse_pipeline(line).unwrap();
    let argv = &parsed.commands[0].argv;
    match argv[0].as_str() {
        "exit" => Ok(false),
        "echo" => {
            println!("{}", argv[1..].join(" "));
            Ok(true)
        }
        _ => Err(io::Error::other("host harness builtin unavailable")),
    }
}
#[test]
fn helper_entry() {
    if std::env::var_os("MOCHIOS_PTY_HOST_311").is_some() {
        // Launcher policy must not make the interactive shell lose children.
        assert_ne!(
            unsafe { libc::signal(libc::SIGCHLD, libc::SIG_IGN) },
            libc::SIG_ERR
        );
        production::run(true).unwrap();
    }
}
struct Child(std::process::Child);
impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn until(master: &mut std::fs::File, expected: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut text = Vec::new();
    while !String::from_utf8_lossy(&text).contains(expected) {
        assert!(
            Instant::now() < deadline,
            "missing {expected:?}; output={:?}",
            String::from_utf8_lossy(&text)
        );
        let mut bytes = [0; 4096];
        match master.read(&mut bytes) {
            Ok(0) => panic!("PTY closed: {:?}", String::from_utf8_lossy(&text)),
            Ok(count) => text.extend_from_slice(&bytes[..count]),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(2))
            }
            Err(error) => panic!("PTY read: {error}; {:?}", String::from_utf8_lossy(&text)),
        }
    }
    String::from_utf8_lossy(&text).into_owned()
}
#[test]
fn real_pty_children_receive_input_signals_pipeline_and_stop_resume_without_shell_theft() {
    let (mut master, mut slave) = (-1, -1);
    assert_eq!(
        unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                core::ptr::null_mut(),
                core::ptr::null(),
                core::ptr::null(),
            )
        },
        0
    );
    let mut master = unsafe { std::fs::File::from_raw_fd(master) };
    let slave = unsafe { std::fs::File::from_raw_fd(slave) };
    let mut child = Child(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "helper_entry", "--nocapture"])
            .env("MOCHIOS_PTY_HOST_311", "1")
            .stdin(Stdio::from(slave.try_clone().unwrap()))
            .stdout(Stdio::from(slave.try_clone().unwrap()))
            .stderr(Stdio::from(slave))
            .spawn()
            .unwrap(),
    );
    let flags = unsafe { libc::fcntl(master.as_raw_fd(), libc::F_GETFL) };
    assert!(flags >= 0);
    assert_eq!(
        unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) },
        0
    );
    until(&mut master, "msh311$ ");
    master
        .write_all(b"/bin/sh -c 'printf \"CHILD_%s\" READY; cat'\n")
        .unwrap();
    until(&mut master, "CHILD_READY");
    master.write_all(b"child-line\n").unwrap();
    let output = until(&mut master, "child-line\r\nchild-line\r\n");
    assert!(!output.contains("msh311$ "));
    master.write_all(&[4]).unwrap();
    until(&mut master, "msh311$ ");
    master
        .write_all(b"/bin/echo pipeline311 | /bin/cat\n")
        .unwrap();
    let output = until(&mut master, "msh311$ ");
    assert!(output.contains("\r\npipeline311\r\n"), "{output}");
    master
        .write_all(b"/bin/sh -c 'kill -STOP $$; echo RESUMED311'\n")
        .unwrap();
    let output = until(&mut master, "msh311$ ");
    assert!(output.contains("Stopped"), "{output}");
    master.write_all(b"fg\n").unwrap();
    let output = until(&mut master, "msh311$ ");
    assert!(output.contains("\r\nRESUMED311\r\n"), "{output}");
    master
        .write_all(b"/bin/sh -c 'printf \"INT_%s\" READY; sleep 30'\n")
        .unwrap();
    until(&mut master, "INT_READY");
    master.write_all(&[3]).unwrap();
    until(&mut master, "msh311$ ");
    master.write_all(b"echo recovered311\n").unwrap();
    let output = until(&mut master, "msh311$ ");
    assert!(output.contains("\r\nrecovered311\r\n"), "{output}");
    master.write_all(b"exit\n").unwrap();
    assert!(child.0.wait().unwrap().success());
}
