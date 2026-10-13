//! KVM probe for the production TTY launcher and Rust std's POSIX backend.
#[path = "../../tty/src/shell_launch.rs"]
mod shell_launch;

const SELF: &str = "/system/services/compositor.service";

fn main() {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if arguments == ["19", "7"] {
        std::process::exit(17);
    }
    if arguments == ["--stdout-child"] {
        println!("captured");
        return;
    }
    let mut child = shell_launch::spawn_shell(SELF, 19, 7).expect("shell-compatible spawn failed");
    assert_eq!(child.wait().expect("child wait failed").code(), Some(17));
    let error = shell_launch::spawn_shell("/system/services/no-such-command.service", 1, 2)
        .expect_err("nonexistent executable was accepted");
    assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    let output = std::process::Command::new(SELF)
        .arg("--stdout-child")
        .output()
        .expect("captured output spawn failed");
    assert!(output.status.success());
    assert_eq!(output.stdout, b"captured\n");
    eprintln!(
        "native-rust-command: PASS production shell argv, wait status, exec failure and output pipes"
    );
}
