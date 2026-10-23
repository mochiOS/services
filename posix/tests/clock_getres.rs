use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn source_quantum_is_positive_and_normalized_without_truncating_large_values() {
    use mochios_posix_client::time::clock_resolution;
    assert_eq!(clock_resolution(0), Err(5));
    assert_eq!(clock_resolution(1), Ok((0, 1)));
    assert_eq!(clock_resolution(7_000_000), Ok((0, 7_000_000)));
    assert_eq!(clock_resolution(1_000_000_001), Ok((1, 1)));
    assert_eq!(
        clock_resolution(u64::MAX),
        Ok((18_446_744_073, 709_551_615))
    );
}

#[test]
fn actual_public_clock_getres_handles_null_full_width_ids_and_error_propagation() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let start = source.find("pub extern \"C\" fn clock_getres(").unwrap();
    let end = start + source[start..].find("\n}\n").unwrap() + 3;
    let mut program = String::from(
        r#"
type c_int = i32;
const EINVAL: i32 = 22;
mod process_clock {
    pub fn target(id:u64)->Option<u64>{(id==((1<<31)|7)).then_some(7)}
    pub fn resolution(id:u64,output:*mut super::Timespec)->Result<i32,i32>{
        assert_eq!(target(id),Some(7));
        if !output.is_null(){unsafe{output.write(super::Timespec{tv_sec:0,tv_nsec:84})}}
        Ok(0)
    }
}
mod thread_clock {
    pub fn is_id(id:u64)->bool{id>=1<<32}
    pub fn resolution(id:u64,output:*mut super::Timespec)->Result<i32,i32>{
        if id!=1<<32{return Err(super::EINVAL)}
        if !output.is_null(){unsafe{output.write(super::Timespec{tv_sec:0,tv_nsec:42})}}
        Ok(0)
    }
}
#[repr(C)] struct Timespec { tv_sec: i64, tv_nsec: i64 }
static mut ERRNO: i32 = 123;
static mut CALLS: usize = 0;
static mut STATUS: u64 = 0;
static mut QUANTUM: u64 = 1_000_000_003;
static mut OUTPUT_ERROR: i32 = 0;
mod time_memory {
    pub fn write_timespec(destination: *mut super::Timespec, value: super::Timespec) -> Result<(), i32> {
        let error = unsafe { super::OUTPUT_ERROR };
        if error != 0 { return Err(error); }
        unsafe { destination.write(value); }
        Ok(())
    }
}
fn set_errno(error: i32) { unsafe { ERRNO = error; } }
fn syscall_errno(raw: u64) -> Result<u64, i32> {
    if (raw as i64) < 0 { Err(-(raw as i64) as i32) } else { Ok(raw) }
}
fn result_with_errno(value: Result<i32, i32>, failure: i32) -> i32 {
    match value { Ok(value) => value, Err(error) => { set_errno(error); failure } }
}
mod newlib_errno { pub const EIO: i32 = 5; pub const EINVAL: i32 = 22; pub const ENOTSUP: i32 = 95; }
mod mnu_abi {
    #[derive(Default)] #[repr(C)] pub struct ClockInfo { pub quantum_nanoseconds: u64 }
    #[repr(u64)] pub enum ClockId { Realtime = 101, Monotonic = 102, ProcessCpu = 103, ThreadCpu = 104 }
}
mod syscall {
    pub enum SyscallNumber { ClockDescribe }
    pub fn raw_syscall3(_: SyscallNumber, selector: u64, output: u64, length: u64) -> u64 {
        assert!((101..=104).contains(&selector)); assert_eq!(length, 8);
        unsafe {
            crate::CALLS += 1;
            if crate::STATUS == 0 { (output as *mut crate::mnu_abi::ClockInfo).write(crate::mnu_abi::ClockInfo { quantum_nanoseconds: crate::QUANTUM }); }
            crate::STATUS
        }
    }
}
mod mochios_posix_client { pub mod time {
"#,
    );
    program.push_str(include_str!(
        "../../../user/crates/posix-client/src/time.rs"
    ));
    program.push_str("\n} pub mod process_clock {pub use crate::process_clock::target;} }\n");
    program.push_str(&source[start..end]);
    program.push_str(
        r#"
const _: extern "C" fn(u64, *mut Timespec) -> i32 = clock_getres;
fn main() {
    let mut output = Timespec { tv_sec: 99, tv_nsec: 98 };
    for invalid in [u64::MAX, (1u64 << 32) | 1, (1u64 << 32) | 4, i32::MAX as u64 + 1, 10] {
        unsafe { ERRNO = 123; }
        assert_eq!(clock_getres(invalid, &mut output), -1);
        assert_eq!(clock_getres(invalid, std::ptr::null_mut()), -1);
        assert_eq!(unsafe { ERRNO }, 22); assert_eq!(unsafe { CALLS }, 0);
        assert_eq!((output.tv_sec, output.tv_nsec), (99, 98));
    }
    for clock in 0..=9 {
        unsafe { ERRNO = 123; }
        assert_eq!(clock_getres(clock, &mut output), 0);
        assert_eq!(unsafe { ERRNO }, 123);
        assert_eq!((output.tv_sec, output.tv_nsec), (1, 3));
        assert_eq!(clock_getres(clock, std::ptr::null_mut()), 0);
    }
    assert_eq!(clock_getres(1<<32,&mut output),0);
    assert_eq!((output.tv_sec,output.tv_nsec),(0,42));
    assert_eq!(clock_getres(1<<32,std::ptr::null_mut()),0);
    assert_eq!(clock_getres((1<<31)|7,&mut output),0);
    assert_eq!((output.tv_sec,output.tv_nsec),(0,84));
    assert_eq!(clock_getres((1<<31)|7,std::ptr::null_mut()),0);
    output = Timespec { tv_sec: 99, tv_nsec: 98 };
    unsafe { STATUS = (-11i64) as u64; }
    assert_eq!(clock_getres(4, &mut output), -1);
    assert_eq!(unsafe { ERRNO }, 11);
    assert_eq!((output.tv_sec, output.tv_nsec), (99, 98));
    unsafe { STATUS = 0; QUANTUM = 0; }
    assert_eq!(clock_getres(4, &mut output), -1);
    assert_eq!(unsafe { ERRNO }, 5);
    assert_eq!((output.tv_sec, output.tv_nsec), (99, 98));
    unsafe { QUANTUM = 1; OUTPUT_ERROR = 14; }
    assert_eq!(clock_getres(4, &mut output), -1);
    assert_eq!(unsafe { ERRNO }, 14);
    assert_eq!((output.tv_sec, output.tv_nsec), (99, 98));
    assert_eq!(clock_getres(4, std::ptr::null_mut()), 0);
}
"#,
    );
    let directory = std::env::temp_dir().join(format!(
        "mochios-clock-res-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    let executable = directory.join("probe");
    let mut compiler = Command::new("rustc")
        .args(["--edition=2024", "-Awarnings", "-"])
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
