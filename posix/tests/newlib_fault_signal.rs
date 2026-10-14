use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn production_runtime_maps_native_causes_only_inside_posix_userspace() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/fault_signal.rs");
    let abi = include_str!("../../../core/crates/abi/src/lib.rs");
    let protocol = include_str!("../../../user/crates/posix-protocol/src/lib.rs");
    let mut program = String::from("type c_int=i32; const EINVAL:i32=22; mod syscall {\n");
    let start = abi.find("pub enum MemoryFaultCause {").unwrap();
    let end = start + abi[start..].find("\n}\n").unwrap() + 3;
    program.push_str("#[repr(u64)]\n");
    program.push_str(&abi[start..end]);
    program.push_str("}\nmod posix_protocol {\n");
    for signal in ["SIGNAL_BUS", "SIGNAL_SEGV"] {
        program.push_str(
            protocol
                .lines()
                .find(|line| line.starts_with(&format!("pub const {signal}:")))
                .unwrap(),
        );
        program.push('\n');
    }
    program.push_str("}\n");
    let start = runtime.find("fn signal_for_cause(").unwrap();
    let end = start + runtime[start..].find("\n}\n").unwrap() + 3;
    program.push_str(&runtime[start..end]);
    program.push_str(
        r#"
fn main() {
    use syscall::MemoryFaultCause::*;
    for cause in [Unmapped,AccessDenied,Unresolved] {
        assert_eq!(signal_for_cause(cause as u64),Ok(posix_protocol::SIGNAL_SEGV));
    }
    for cause in [OutsideBacking,BackingFailure,ResourceUnavailable] {
        assert_eq!(signal_for_cause(cause as u64),Ok(posix_protocol::SIGNAL_BUS));
    }
    for invalid in [0,7,u64::MAX] { assert_eq!(signal_for_cause(invalid),Err(EINVAL)); }
}
"#,
    );
    let directory = std::env::temp_dir().join(format!(
        "mochios-posix-fault-mapping-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    let binary = directory.join("probe");
    let mut compiler = Command::new("rustc")
        .args(["--edition=2024", "-Awarnings", "-", "-o"])
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
    let compiled = compiler.wait_with_output().unwrap();
    if !compiled.status.success() {
        std::fs::remove_dir_all(&directory).unwrap();
        panic!("{}", String::from_utf8_lossy(&compiled.stderr));
    }
    let result = Command::new(binary).output().unwrap();
    std::fs::remove_dir_all(directory).unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn native_probe_numbers_and_runtime_exception_opt_in_match_the_current_abi() {
    let probe = include_str!("posix_memory_fault.c");
    for (name, value) in [
        ("MEMORY_MAP", mnu_abi::SyscallNumber::MemoryMap),
        ("MEMORY_UNMAP", mnu_abi::SyscallNumber::MemoryUnmap),
        ("MEMORY_CREATE", mnu_abi::SyscallNumber::MemoryObjectCreate),
        ("MEMORY_RESIZE", mnu_abi::SyscallNumber::MemoryObjectResize),
        ("HANDLE_CLOSE", mnu_abi::SyscallNumber::HandleClose),
    ] {
        assert!(probe.contains(&format!("{name} = {}", value as u64)));
    }
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let setup = runtime.split("fn setup_signal_delivery(").nth(1).unwrap();
    assert!(
        setup
            .split("let install =")
            .next()
            .unwrap()
            .contains("flags: syscall::THREAD_UPCALL_EXCEPTIONS")
    );
    assert!(runtime.contains("fault_signal::deliver(cause)"));
}
