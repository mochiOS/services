use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn public_clock_gettime_preserves_the_full_newlib_clock_id() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let start = source.find("pub extern \"C\" fn clock_gettime(").unwrap();
    let end = start + source[start..].find("\n}\n").unwrap() + 3;
    let mut program = String::from(
        r#"
type c_int = i32;
const EFAULT: i32 = 14;
const EINVAL: i32 = 22;
const EIO: i32 = 5;
const EOVERFLOW: i32 = 75;
#[repr(C)] struct Timespec { tv_sec: i64, tv_nsec: i64 }
mod time_memory {
    pub fn write_timespec(output:*mut super::Timespec,value:super::Timespec)->Result<(),i32>{
        unsafe {output.write_unaligned(value);} Ok(())
    }
}
static mut ERRNO: i32 = 123;
static mut CALLS: usize = 0;
fn set_errno(error: i32) { unsafe { ERRNO = error; } }
fn result_with_errno(value: Result<i32, i32>, failure: i32) -> i32 {
    match value { Ok(value) => value, Err(error) => { set_errno(error); failure } }
}
fn syscall_errno(raw: u64) -> Result<u64, i32> { Ok(raw) }
mod mnu_abi {
    #[derive(Default)] #[repr(C)] pub struct ClockInstant { pub seconds: u64, pub nanoseconds: u32, pub reserved: u32 }
    #[repr(u64)] pub enum ClockId { Realtime = 1, Monotonic = 2, ProcessCpu = 3, ThreadCpu = 4 }
}
mod syscall {
    pub enum SyscallNumber { ClockRead }
    pub fn raw_syscall2(_: SyscallNumber, selector: u64, output: u64) -> u64 {
        assert_eq!(selector, crate::mnu_abi::ClockId::Monotonic as u64);
        unsafe {
            crate::CALLS += 1;
            (output as *mut crate::mnu_abi::ClockInstant).write(crate::mnu_abi::ClockInstant { seconds: 7, nanoseconds: 5, reserved: 0 });
        }
        0
    }
}
mod mochios_posix_client { pub mod time {
    pub enum ClockKind { Realtime, Monotonic, ProcessCpu, ThreadCpu }
    pub fn classify_clock_id(id: i32) -> Option<ClockKind> {
        match id { 1 => Some(ClockKind::Realtime), 4 => Some(ClockKind::Monotonic),
            2 => Some(ClockKind::ProcessCpu), 3 => Some(ClockKind::ThreadCpu), _ => None }
    }
} }
"#,
    );
    program.push_str(&source[start..end]);
    program.push_str(r#"
const _: extern "C" fn(u64, *mut Timespec) -> i32 = clock_gettime;
fn main() {
    let mut output = Timespec { tv_sec: 99, tv_nsec: 98 };
    for invalid in [u64::MAX, 1u64 << 32 | 1, 1u64 << 32 | 4, 1u64 << 32 | 2, 1u64 << 32 | 3, i32::MAX as u64 + 1] {
        unsafe { ERRNO = 123; }
        assert_eq!(clock_gettime(invalid, &mut output), -1);
        assert_eq!(unsafe { ERRNO }, EINVAL);
        assert_eq!(unsafe { CALLS }, 0);
        assert_eq!((output.tv_sec, output.tv_nsec), (99, 98));
    }
    unsafe { ERRNO = 123; }
    assert_eq!(clock_gettime(4, &mut output), 0);
    assert_eq!(unsafe { ERRNO }, 123);
    assert_eq!(unsafe { CALLS }, 1);
    assert_eq!((output.tv_sec, output.tv_nsec), (7, 5));
}
"#);
    let directory = std::env::temp_dir().join(format!(
        "mochios-clock-id-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    let executable = directory.join("probe");
    let mut compiler = Command::new("rustc")
        .args(["--edition=2021", "-Awarnings", "-"])
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
    let result = Command::new(executable).output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    std::fs::remove_dir_all(directory).unwrap();
}
