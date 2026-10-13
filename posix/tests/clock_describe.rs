use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn actual_native_clock_description_reports_source_quantum_and_rejects_bad_inputs() {
    assert_eq!(std::mem::size_of::<mnu_abi::ClockInfo>(), 8);
    assert_eq!(std::mem::offset_of!(mnu_abi::ClockInfo, quantum_nanoseconds), 0);
    assert_eq!(mnu_abi::SyscallNumber::ClockDescribe as u64, 685);
    let source = include_str!("../../../core/src/syscall/time.rs");
    let start = source.find("pub fn clock_describe(").unwrap();
    let end = start + source[start..].find("\n}\n").unwrap() + 3;
    let abi = include_str!("../../../core/crates/abi/src/lib.rs");
    let clock_start = abi.find("pub enum ClockId {").unwrap();
    let clock_end = abi[clock_start..].find("\n#[repr(C)]").unwrap() + clock_start;
    let mut program = String::from(
        r#"
extern crate self as mnu_abi;
#[repr(C)] pub struct ClockInfo { pub quantum_nanoseconds: u64 }
const SUCCESS: u64 = 0;
const EINVAL: u64 = (-22i64) as u64;
const EFAULT: u64 = (-14i64) as u64;
const EAGAIN: u64 = (-11i64) as u64;
mod interrupt { pub mod timer {
    pub static MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(7);
    pub fn tick_ms() -> u64 { MS.load(std::sync::atomic::Ordering::Relaxed) }
} }
mod syscall {
    pub fn copy_to_user(pointer: u64, bytes: &[u8]) -> Result<(), u64> {
        if pointer == 1 { return Err(super::EFAULT); }
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), pointer as *mut u8, bytes.len()); }
        Ok(())
    }
}
"#,
    );
    program.push_str(&abi[clock_start..clock_end]);
    program.push_str(&source[start..end]);
    program.push_str(
        r#"
fn main() {
    let mut output = 123u64;
    let pointer = &mut output as *mut u64 as u64;
    for clock in [ClockId::Realtime, ClockId::Monotonic, ClockId::ProcessCpu, ClockId::ThreadCpu] {
        assert_eq!(clock_describe(clock as u64, pointer, 8), SUCCESS);
        assert_eq!(output, 7_000_000);
    }
    output = 123;
    for clock in [0, 1, 2, 3, 4, u64::MAX] {
        assert_eq!(clock_describe(clock, pointer, 8), EINVAL);
        assert_eq!(output, 123);
    }
    let clock = ClockId::Monotonic as u64;
    assert_eq!(clock_describe(clock, pointer, 7), EINVAL);
    assert_eq!(clock_describe(clock, 0, 8), EFAULT);
    assert_eq!(clock_describe(clock, 1, 8), EFAULT);
    interrupt::timer::MS.store(0, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(clock_describe(clock, pointer, 8), EAGAIN);
    interrupt::timer::MS.store(u64::MAX, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(clock_describe(clock, pointer, 8), EAGAIN);
    assert_eq!(output, 123);
}
"#,
    );
    let directory = std::env::temp_dir().join(format!(
        "mochios-clock-describe-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    let executable = directory.join("probe");
    let mut compiler = Command::new("rustc")
        .args(["--edition=2024", "-"])
        .arg("-o")
        .arg(&executable)
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
    let result = compiler.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let result = Command::new(&executable).output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    std::fs::remove_dir_all(directory).unwrap();
}
