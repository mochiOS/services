use mochios_posix_client::{
    accounting::cpu_timeval,
    newlib_errno::{EIO, EOVERFLOW},
};
use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn cpu_timevals_preserve_wide_aggregates_and_normalize_without_intermediate_overflow() {
    assert_eq!(cpu_timeval(0, 0), Ok((0, 0)));
    assert_eq!(cpu_timeval(1, 0), Err(EIO));
    assert_eq!(cpu_timeval(1, 3), Ok((0, 333_333)));
    assert_eq!(cpu_timeval(3, 3), Ok((1, 0)));
    assert_eq!(cpu_timeval(15, 2), Ok((7, 500_000)));
    assert_eq!(cpu_timeval(2 * u128::from(u64::MAX), u64::MAX), Ok((2, 0)));
    let rate = u128::from(u64::MAX);
    let largest = i64::MAX as u128 * rate + rate - 1;
    assert_eq!(cpu_timeval(largest, u64::MAX), Ok((i64::MAX, 999_999)));
    assert_eq!(cpu_timeval(largest + 1, u64::MAX), Err(EOVERFLOW));
    assert_eq!(cpu_timeval(u128::MAX, 1), Err(EOVERFLOW));
}

#[test]
fn actual_runtime_routes_self_natively_and_children_through_authenticated_aggregation() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/process_accounting.rs");
    let conversion = include_str!("../../../user/crates/posix-client/src/accounting.rs");
    let mut program = String::from(
        r#"
use core::{ffi::c_int,sync::atomic::{AtomicU32,Ordering}};
type CLong=i64;
const EINVAL:i32=22;const EFAULT:i32=14;const EIO:i32=5;const EOVERFLOW:i32=75;
static MODE:AtomicU32=AtomicU32::new(0);static NATIVE:AtomicU32=AtomicU32::new(0);
static CLIENT:AtomicU32=AtomicU32::new(0);static CHILD:AtomicU32=AtomicU32::new(0);static ERRNO:AtomicU32=AtomicU32::new(0);
#[repr(C)]struct Timeval{tv_sec:i64,tv_usec:i64}
struct NativeError;impl NativeError{fn raw(self)->i64{-5}}
fn map_kernel_errno(_:i64)->i32{5}
fn map_posix_client_error(error:i32)->i32{error}
fn result_with_errno<T>(result:Result<T,i32>,failure:T)->T{match result{Ok(value)=>value,Err(error)=>{ERRNO.store(error as u32,Ordering::Release);failure}}}
mod posix_protocol{
    pub struct WaitedChildCpuUsage{pub user_ticks:u128,pub kernel_ticks:u128,pub ticks_per_second:u64}
    pub mod wait_usage{pub struct Usage{pub cpu:super::WaitedChildCpuUsage,pub peak_resident_bytes:u64}}
}
mod user_copy{pub fn write(dst:*mut u8,src:&[u8])->Result<(),i32>{if super::MODE.load(super::Ordering::Acquire)==13{return Err(super::EFAULT)}unsafe{core::ptr::copy_nonoverlapping(src.as_ptr(),dst,src.len())};Ok(())}}
mod syscall{pub mod execution{use super::super::*;
    pub struct Memory{pub current_bytes:u64,pub peak_bytes:u64}
    pub fn memory_usage(handle:Option<u32>)->Result<Memory,NativeError>{
        assert_eq!(handle,None);
        if MODE.load(Ordering::Acquire)==10{return Err(NativeError)}
        Ok(Memory{current_bytes:if MODE.load(Ordering::Acquire)==12{u64::MAX}else{4096},peak_bytes:12*1024+1})
    }
    pub struct Usage{pub user_ticks:u64,pub kernel_ticks:u64,pub ticks_per_second:u64,pub reserved:u64}
    pub fn usage(handle:Option<u32>)->Result<Usage,NativeError>{
        assert_eq!(handle,None);NATIVE.fetch_add(1,Ordering::AcqRel);
        if MODE.load(Ordering::Acquire)==1{return Err(NativeError)}
        Ok(Usage{reserved:if MODE.load(Ordering::Acquire)==11{1}else{0},user_ticks:17,kernel_ticks:23,ticks_per_second:if MODE.load(Ordering::Acquire)==2{0}else{500}})
    }
}}
struct Client;fn posix_client()->Result<Client,i32>{
    CLIENT.fetch_add(1,Ordering::AcqRel);if MODE.load(Ordering::Acquire)==3{Err(32)}else{Ok(Client)}
}
type ChildUsage=posix_protocol::WaitedChildCpuUsage;
impl Client{fn waited_child_usage(&self)->Result<posix_protocol::wait_usage::Usage,i32>{
    CHILD.fetch_add(1,Ordering::AcqRel);let mode=MODE.load(Ordering::Acquire);
    if mode==4{return Err(5)}
    let cpu=match mode{
        5=>ChildUsage{user_ticks:u128::MAX,kernel_ticks:0,ticks_per_second:1},
        6=>ChildUsage{user_ticks:0,kernel_ticks:u128::MAX,ticks_per_second:1},
        7=>ChildUsage{user_ticks:0,kernel_ticks:0,ticks_per_second:0},
        8=>ChildUsage{user_ticks:0,kernel_ticks:1,ticks_per_second:0},
        9=>ChildUsage{user_ticks:2*u64::MAX as u128,kernel_ticks:4*u64::MAX as u128,ticks_per_second:u64::MAX},
        _=>ChildUsage{user_ticks:17,kernel_ticks:23,ticks_per_second:500},
    };
    Ok(posix_protocol::wait_usage::Usage{cpu,peak_resident_bytes:if mode==7{0}else{12*1024+1}})
}}
mod newlib_errno{pub const EIO:i32=5;pub const EOVERFLOW:i32=75;}
mod mochios_posix_client{pub mod accounting{
"#,
    );
    program.push_str(conversion);
    program.push_str("\n}}\nmod resource_usage_output{\n");
    program.push_str(include_str!(
        "../../../user/crates/newlib-runtime/src/resource_usage_output.rs"
    ));
    program.push_str("\n}\nmod actual{\n");
    program.push_str(runtime);
    program.push_str(r#"
pub fn run(){
    #[repr(C,align(8))]struct Output([u8;40]);
    for (who,mode,error,expected) in [
        (0,0,0,(0,34000,0,46000)),(0,10,5,(0,0,0,0)),(0,11,5,(0,0,0,0)),(0,12,5,(0,0,0,0)),(0,13,14,(0,0,0,0)),(-1,13,14,(0,0,0,0)),(0,1,5,(0,0,0,0)),(0,2,5,(0,0,0,0)),
        (-1,0,0,(0,34000,0,46000)),(-1,3,32,(0,0,0,0)),(-1,4,5,(0,0,0,0)),
        (-1,5,75,(0,0,0,0)),(-1,6,75,(0,0,0,0)),(-1,7,0,(0,0,0,0)),
        (-1,8,5,(0,0,0,0)),(-1,9,0,(2,0,4,0)),
    ]{
        MODE.store(mode,Ordering::Release);NATIVE.store(0,Ordering::Release);CLIENT.store(0,Ordering::Release);CHILD.store(0,Ordering::Release);ERRNO.store(99,Ordering::Release);
        let mut output=Output([0x5a;40]);let pointer=output.0.as_mut_ptr().cast::<Rusage>();
        assert_eq!(unsafe{getrusage(who,pointer)},if error==0{0}else{-1},"who {who} mode {mode}");
        assert_eq!(NATIVE.load(Ordering::Acquire),if who==0{1}else{0});
        assert_eq!(CLIENT.load(Ordering::Acquire),if who==0{0}else{1});
        assert_eq!(CHILD.load(Ordering::Acquire),if who==0||mode==3{0}else{1});
        assert_eq!(ERRNO.load(Ordering::Acquire),if error==0{99}else{error});
        if error==0{
            let value=unsafe{&*pointer};assert_eq!((value.ru_utime.tv_sec,value.ru_utime.tv_usec,value.ru_stime.tv_sec,value.ru_stime.tv_usec),expected);assert_eq!(value.ru_maxrss,if mode==7{0}else{13});
        }else{assert_eq!(output.0,[0x5a;40],"partial output on error");}
    }
    for who in [1,-2,i32::MIN,i32::MAX]{
        let mut output=Output([0x5a;40]);
        NATIVE.store(0,Ordering::Release);CLIENT.store(0,Ordering::Release);
        assert_eq!(unsafe{getrusage(who,output.0.as_mut_ptr().cast())},-1);
        assert_eq!(ERRNO.load(Ordering::Acquire),22);assert_eq!(output.0,[0x5a;40]);
        assert_eq!(NATIVE.load(Ordering::Acquire)+CLIENT.load(Ordering::Acquire),0);
    }
    for who in [0,-1]{
        assert_eq!(unsafe{getrusage(who,core::ptr::null_mut())},-1);
        assert_eq!(ERRNO.load(Ordering::Acquire),14);
        assert_eq!(NATIVE.load(Ordering::Acquire)+CLIENT.load(Ordering::Acquire),0);
    }
}
}
fn main(){actual::run()}
"#);
    let directory = std::env::temp_dir().join(format!("mochios-rusage-{}", std::process::id()));
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
    let output = compiler.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = Command::new(&binary).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::remove_dir_all(directory).unwrap();
}
