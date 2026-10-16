//! Execute production error-handling functions with controlled transport calls.
use std::io::Write;
use std::process::{Command, Stdio};

pub fn between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let start = source.find(start).unwrap();
    let end = start + source[start..].find(end).unwrap();
    &source[start..end]
}

pub fn program() -> String {
    let syscall = include_str!("../../../../user/crates/syscall/src/lib.rs");
    let mut program =
        String::from("#![allow(dead_code)]\nextern crate alloc;\nmod mnu_abi {pub mod status {\n");
    program.push_str(include_str!("../../../../core/crates/abi/src/status.rs"));
    program.push_str(
        "}\n}\nmod mochi_user_syscall {\nuse crate::mnu_abi::status::Error as NativeError;\n",
    );
    program.push_str(between(
        syscall,
        "#[derive(Clone, Copy, Debug, PartialEq, Eq)]",
        "#[derive(Clone, Copy, Debug, PartialEq, Eq)]\npub struct RawSyscallResult",
    ));
    for line in include_str!("../../../../core/crates/abi/src/lib.rs").lines() {
        if line.starts_with("pub const E") && line.contains(": u64 = (-") {
            program.push_str(line);
            program.push('\n');
        }
    }
    program.push_str("}\nuse mochi_user_syscall::*;\nmod mochios_posix_protocol {\n");
    constants(
        &mut program,
        include_str!("../../../../user/crates/posix-protocol/src/lib.rs"),
        &["STATUS_ENOTDIR", "STATUS_EISDIR"],
    );
    program.push_str("}\n");
    program
}

pub fn constants(program: &mut String, source: &str, names: &[&str]) {
    for name in names {
        let suffix = format!("const {name}:");
        program.push_str(source.lines().find(|line| line.contains(&suffix)).unwrap());
        program.push('\n');
    }
}

struct Temporary(std::path::PathBuf);
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn run(program: &str) {
    run_with(program, None);
}

pub fn run_with_toolchain(program: &str, toolchain: &str) {
    run_with(program, Some(toolchain));
}

fn run_with(program: &str, toolchain: Option<&str>) {
    let temporary = Temporary(std::env::temp_dir().join(format!(
        "mochios-native-error-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )));
    std::fs::create_dir(&temporary.0).unwrap();
    let binary = temporary.0.join("probe");
    let mut command = match toolchain {
        Some(toolchain) => {
            let mut command = Command::new("rustup");
            command.args(["run", toolchain, "rustc"]);
            command
        }
        None => Command::new("rustc"),
    };
    let mut compiler = command
        .args(["--edition=2024", "-", "-o"])
        .arg(&binary)
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    compiler
        .stdin
        .take()
        .unwrap()
        .write_all(program.as_bytes())
        .unwrap();
    let output = compiler.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = Command::new(binary).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
