#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn actual_c_boundary_preserves_errno_checks_copyout_and_keeps_parent_clock_ids_after_fork() {
    let mut program = String::from(
        r#"
#![allow(dead_code)]
use std::{ffi::c_int,sync::atomic::{AtomicU64,AtomicUsize,Ordering},cell::UnsafeCell};
const EFAULT:i32=14;const ESRCH:i32=3;const EINVAL:i32=22;const EOVERFLOW:i32=75;const EIO:i32=5;
static PID:AtomicU64=AtomicU64::new(7);static REMOTE:AtomicUsize=AtomicUsize::new(0);
static REMOTE_ERROR:AtomicUsize=AtomicUsize::new(0);
thread_local!{static ERRNO:UnsafeCell<i32>=const{UnsafeCell::new(33)};}
unsafe fn __errno()->*mut i32{ERRNO.with(UnsafeCell::get)}
fn set_errno(e:i32){unsafe{*__errno()=e}}
#[derive(Clone,Copy)]struct SysError(i64);impl SysError{fn raw(self)->i64{self.0}}
fn map_kernel_errno(e:i64)->i32{(-e) as i32}
fn map_posix_client_error(e:i32)->i32{e}
fn native_process_id()->Result<u64,SysError>{Ok(PID.load(Ordering::SeqCst))}
#[derive(Default,Clone,Copy,Debug,PartialEq)]struct Timespec{tv_sec:i64,tv_nsec:i64}
mod posix_protocol{#[derive(Debug)]pub enum ProtocolError{InvalidLength}pub mod process_clock{
"#,
    );
    program.push_str(
        include_str!("../../../user/crates/posix-protocol/src/process_clock.rs")
            .split_once('\n')
            .unwrap()
            .1,
    );
    program.push_str(
        r#"
}}
pub use posix_protocol::ProtocolError;
mod mochios_posix_client{
 pub mod newlib_errno{pub const EIO:i32=5;pub const EOVERFLOW:i32=75;}
 pub mod protocol{pub use crate::posix_protocol::*;}
 pub mod process_clock{use super::*;
"#,
    );
    let client = include_str!("../../../user/crates/posix-client/src/process_clock.rs");
    program.push_str(probe::between(
        client,
        "pub const FIRST_ID",
        "impl<T: Transport>",
    ));
    program.push_str(r#"
 }
 pub mod time{pub fn clock_resolution(n:u64)->Result<(i64,i64),i32>{Ok(((n/1_000_000_000)as i64,(n%1_000_000_000)as i64))}}
}
mod syscall{pub mod execution{use super::super::*;
 pub struct Usage{pub user_ticks:u64,pub kernel_ticks:u64,pub ticks_per_second:u64}
 pub fn usage(handle:Option<u32>)->Result<Usage,SysError>{assert!(handle.is_none());Ok(Usage{user_ticks:1001,kernel_ticks:2,ticks_per_second:500})}
}}
struct Client;
fn posix_client()->Result<Client,i32>{REMOTE.fetch_add(1,Ordering::SeqCst);Ok(Client)}
impl Client{fn process_cpu_clock(&self,pid:u64)->Result<posix_protocol::process_clock::Sample,i32>{
 set_errno(72);let error=REMOTE_ERROR.load(Ordering::SeqCst);if error!=0{return Err(error as i32)}
 Ok(posix_protocol::process_clock::Sample{process_id:pid,user_ticks:500,kernel_ticks:0,ticks_per_second:500})
}}
mod user_copy{pub fn write(p:*mut u8,b:&[u8])->Result<(),i32>{if(p as usize)<4096{return Err(14)}unsafe{std::ptr::copy_nonoverlapping(b.as_ptr(),p,b.len())};Ok(())}}
mod time_memory{use super::*;pub fn write_timespec(p:*mut Timespec,t:Timespec)->Result<(),i32>{if(p as usize)<4096{return Err(14)}unsafe{p.write(t)};Ok(())}}
mod actual{use super::*;
"#);
    program.push_str(
        include_str!("../../../user/crates/newlib-runtime/src/process_clock.rs")
            .split("use super::*;")
            .nth(1)
            .unwrap(),
    );
    program.push_str(r#"
}
fn main(){
 let mut clock=0;assert_eq!(actual::clock_getcpuclockid(0,&mut clock),0);
 assert_eq!(clock,(1<<31)|7);assert_eq!(REMOTE.load(Ordering::SeqCst),0);assert_eq!(unsafe{*__errno()},33);
 let mut own=0;assert_eq!(actual::clock_getcpuclockid(7,&mut own),0);assert_eq!(own,clock);
 let mut time=Timespec::default();assert_eq!(actual::read(clock,&mut time),Ok(0));assert_eq!(time,Timespec{tv_sec:2,tv_nsec:6_000_000});
 assert_eq!(actual::resolution(clock,&mut time),Ok(0));assert_eq!(time,Timespec{tv_sec:0,tv_nsec:2_000_000});
 assert_eq!(actual::resolution(clock,std::ptr::null_mut()),Ok(0));
 assert_eq!(actual::clock_getcpuclockid(-1,&mut own),ESRCH);assert_eq!(own,clock);
 assert_eq!(actual::clock_getcpuclockid(0,1usize as *mut _),EFAULT);
 assert_eq!(unsafe{*__errno()},33);
 // Fork copies the selected process ID, not a token meaning "current".
 PID.store(8,Ordering::SeqCst);assert_eq!(actual::read(clock,&mut time),Ok(0));
 assert_eq!(time.tv_sec,1);assert_eq!(REMOTE.load(Ordering::SeqCst),1);
 set_errno(33);let mut parent=0;assert_eq!(actual::clock_getcpuclockid(7,&mut parent),0);assert_eq!(parent,clock);assert_eq!(unsafe{*__errno()},33);
 REMOTE_ERROR.store(1,Ordering::SeqCst);assert_eq!(actual::clock_getcpuclockid(7,&mut parent),1);assert_eq!(unsafe{*__errno()},33);
 REMOTE_ERROR.store(ESRCH as usize,Ordering::SeqCst);assert_eq!(actual::read(clock,&mut time),Err(EINVAL));assert_eq!(actual::resolution(clock,std::ptr::null_mut()),Err(EINVAL));
 set_errno(33);assert_eq!(actual::clock_getcpuclockid(7,&mut parent),ESRCH);assert_eq!(unsafe{*__errno()},33);
}
"#);
    probe::run(&program);
}
