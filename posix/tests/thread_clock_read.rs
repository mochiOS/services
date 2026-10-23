#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn production_thread_clock_requires_a_wait_handle_and_copies_outside_the_queue() {
    let mut program =
        String::from("#![allow(dead_code)]\nextern crate self as mnu_abi;\nmod status {\n");
    program.push_str(include_str!("../../../core/crates/abi/src/status.rs"));
    program.push_str(r#"
}
use status::Error;
use std::cell::{Cell,RefCell};
const SUCCESS:u64=0;
#[repr(C)]struct ClockInstant{seconds:u64,nanoseconds:u32,reserved:u32}
#[derive(Debug,PartialEq)]enum HandleRights{WAIT}
enum KernelObject{Thread(u64),Other}
thread_local!{
 static RATE:Cell<u64>=const{Cell::new(10)};
 static TICKS:Cell<u64>=const{Cell::new(42)};
 static PRESENT:Cell<bool>=const{Cell::new(true)};
 static HELD:Cell<bool>=const{Cell::new(false)};
 static COPY_ERROR:Cell<Option<Error>>=const{Cell::new(None)};
 static LOOKUPS:Cell<usize>=const{Cell::new(0)};
 static OUTPUT:RefCell<Vec<u8>>=const{RefCell::new(Vec::new())};
}
mod handle{
 pub fn object_native(raw:u64,rights:crate::HandleRights)->Result<crate::KernelObject,crate::Error>{
  assert_eq!(rights,crate::HandleRights::WAIT);crate::LOOKUPS.set(crate::LOOKUPS.get()+1);
  match raw{42=>Ok(crate::KernelObject::Thread(701)),43=>Err(crate::Error::AccessDenied),44=>Ok(crate::KernelObject::Other),_=>Err(crate::Error::InvalidArgument)}
 }
}
mod interrupt{pub mod timer{pub fn ticks_per_second()->u64{crate::RATE.get()}}}
mod task{
 pub struct Thread;impl Thread{pub fn cpu_ticks(&self)->u64{crate::TICKS.get()}}
 pub fn with_thread<T>(id:u64,f:impl FnOnce(&Thread)->T)->Option<T>{
  assert_eq!(id,701);if !crate::PRESENT.get(){return None}
  assert!(!crate::HELD.replace(true));let value=f(&Thread);crate::HELD.set(false);Some(value)
 }
}
fn copy_to_user_native(output:u64,bytes:&[u8])->Result<(),Error>{
 assert!(!HELD.get());if output==0{return Err(Error::InvalidAddress)}
 if let Some(error)=COPY_ERROR.get(){return Err(error)}
 OUTPUT.with_borrow_mut(|out|out.extend_from_slice(bytes));Ok(())
}
mod actual{use crate::{HandleRights,KernelObject,SUCCESS};
"#);
    program.push_str(probe::between(
        include_str!("../../../core/src/syscall/upcall.rs"),
        "pub fn thread_clock_read(",
        "pub fn return_from_context(",
    ));
    program.push_str(r#"
}
fn main(){
 assert_eq!(core::mem::size_of::<ClockInstant>(),16);
 for length in [0,15,17,u64::MAX]{assert_eq!(actual::thread_clock_read(42,1,length),Error::InvalidArgument.into_raw())}
 assert_eq!(LOOKUPS.get(),0);
 for(raw,error)in [(0,Error::InvalidArgument),(999,Error::InvalidArgument),(43,Error::AccessDenied),(44,Error::InvalidArgument)]{
  assert_eq!(actual::thread_clock_read(raw,1,16),error.into_raw());
 }
 assert!(OUTPUT.with_borrow(|out|out.is_empty()));
 RATE.set(0);assert_eq!(actual::thread_clock_read(42,1,16),Error::NotReady.into_raw());RATE.set(10);
 PRESENT.set(false);assert_eq!(actual::thread_clock_read(42,1,16),Error::NotFound.into_raw());PRESENT.set(true);
 assert_eq!(actual::thread_clock_read(42,0,16),Error::InvalidAddress.into_raw());
 for error in [Error::InvalidAddress,Error::BackingFailure,Error::ResourceUnavailable]{
  COPY_ERROR.set(Some(error));assert_eq!(actual::thread_clock_read(42,1,16),error.into_raw());
 }
 COPY_ERROR.set(None);assert!(OUTPUT.with_borrow(|out|out.is_empty()));
 for(ticks,rate)in [(0,10),(42,10),(8,3),(u64::MAX,3),(u64::MAX,u64::MAX),(u64::MAX,u64::MAX-1)]{
  TICKS.set(ticks);RATE.set(rate);assert_eq!(actual::thread_clock_read(42,1,16),0);
  OUTPUT.with_borrow_mut(|out|{
   assert_eq!(out.len(),16);
   assert_eq!(u64::from_le_bytes(out[..8].try_into().unwrap()),ticks/rate);
   assert_eq!(u32::from_le_bytes(out[8..12].try_into().unwrap())as u128,(ticks as u128%rate as u128)*1_000_000_000/rate as u128);
   assert_eq!(out[12..],[0;4]);out.clear();
  });
 }
}
"#);
    probe::run(&program);
}

#[test]
fn production_thread_clock_wrapper_rejects_zero_and_malformed_native_records() {
    let mut program = probe::program().replace(
        "mod mnu_abi {pub mod status {",
        "mod mnu_abi {pub const SUCCESS:u64=0;pub mod status {",
    );
    program.push_str(r#"
use mnu_abi::status::Error;
use std::cell::Cell;
#[derive(Default,Clone,Copy,PartialEq,Debug)]struct ClockInstant{seconds:u64,nanoseconds:u32,reserved:u32}
enum SyscallNumber{ThreadClockRead}
thread_local!{
 static CALLS:Cell<usize>=const{Cell::new(0)};
 static ERROR:Cell<Option<Error>>=const{Cell::new(None)};
 static RECORD:Cell<ClockInstant>=const{Cell::new(ClockInstant{seconds:9,nanoseconds:3,reserved:0})};
 static STATUS:Cell<u64>=const{Cell::new(0)};
}
fn call3(_:SyscallNumber,handle:u64,output:u64,length:u64)->SysResult<u64>{
 assert_eq!(handle,42);assert_eq!(length,16);CALLS.set(CALLS.get()+1);
 if let Some(error)=ERROR.get(){return Err(SysError::from_raw(error.into_raw()as i64))}
 unsafe{*(output as *mut ClockInstant)=RECORD.get()};Ok(STATUS.get())
}
mod actual{use crate::{mnu_abi,Error,SysError,SysResult,SyscallNumber};
"#);
    let source = include_str!("../../../user/crates/syscall/src/execution.rs");
    program.push_str(&source[source.find("pub fn thread_clock(").unwrap()..]);
    program.push_str(r#"
}
fn main(){
 assert_eq!(actual::thread_clock(0).unwrap_err().native_error(),Some(Error::InvalidArgument));assert_eq!(CALLS.get(),0);
 assert_eq!(actual::thread_clock(42).unwrap(),RECORD.get());
 for error in [Error::InvalidArgument,Error::AccessDenied,Error::NotFound,Error::NotReady,Error::InvalidAddress,Error::ResourceUnavailable]{
  ERROR.set(Some(error));assert_eq!(actual::thread_clock(42).unwrap_err().native_error(),Some(error));
 }
 ERROR.set(None);
 for record in [ClockInstant{seconds:0,nanoseconds:1_000_000_000,reserved:0},ClockInstant{seconds:0,nanoseconds:0,reserved:1}]{
  RECORD.set(record);assert_eq!(actual::thread_clock(42).unwrap_err().native_error(),Some(Error::BackingFailure));
 }
 RECORD.set(ClockInstant::default());STATUS.set(1);
 assert_eq!(actual::thread_clock(42).unwrap_err().native_error(),Some(Error::BackingFailure));
}
"#);
    probe::run(&program);
}

#[test]
fn thread_clock_abi_has_an_explicit_handle_without_posix_policy() {
    assert_eq!(mnu_abi::SyscallNumber::ThreadClockRead as u64, 701);
    assert_eq!(size_of::<mnu_abi::ClockInstant>(), 16);
    let source = include_str!("../../../core/src/syscall/mod.rs");
    assert!(source.contains("upcall::thread_clock_read(arg0, arg1, arg2)"));
    let native = include_str!("native_thread_clock.c");
    assert!(native.contains(&format!(
        "THREAD_CLOCK = {}",
        mnu_abi::SyscallNumber::ThreadClockRead as u64
    )));
    assert_eq!(mnu_abi::HANDLE_RIGHT_WAIT, 0x10);
    assert_eq!(mnu_abi::HANDLE_RIGHT_SIGNAL, 0x20);
    for (name, error) in [
        ("ACCESS_DENIED", mnu_abi::status::Error::AccessDenied),
        ("INVALID_ARGUMENT", mnu_abi::status::Error::InvalidArgument),
    ] {
        assert!(native.contains(&format!(
            "#define {name} INT64_C({})",
            error.into_raw() as i64
        )));
    }
}
