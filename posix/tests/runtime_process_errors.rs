//! Compile the complete target-only process adapter with real error codecs.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn process_adapters_translate_native_failures_and_reject_unknown_lifecycle_metadata() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let mut program = format!(
        r#"
#![allow(dead_code)]
extern crate self as mnu_abi;
extern crate self as mochi_user_platform;
extern crate self as mochios_posix_protocol;
extern crate self as posix_service;
#[path={:?}]mod abi;
pub use abi::*;
pub mod status {{
 pub use crate::abi::status::*;
 #[path={:?}]mod wire;
 pub use wire::normalize_failure;
}}
pub const STATUS_EIO:i32=-5;pub const STATUS_ESRCH:i32=-3;pub const STATUS_EAGAIN:i32=-11;
pub const STATUS_EINVAL:i32=-22;
#[path={:?}]mod process_control;
use std::cell::{{Cell,RefCell}};
thread_local! {{
 static FAILURE:Cell<i64>=const{{Cell::new(0)}};
 static METADATA:Cell<ProcessStatus>=const{{Cell::new(ProcessStatus{{process_id:37,state:PROCESS_STATE_RUNNING,reserved:0,exit_code:0,image_revision:3}})}};
 static CALLS:RefCell<Vec<(&'static str,u32)>>=const{{RefCell::new(Vec::new())}};
}}
#[derive(Debug)]pub struct NativeError(i64);
impl NativeError{{fn raw(&self)->i64{{self.0}}}}
fn operation(name:&'static str,handle:u32)->Result<(),NativeError>{{
 assert_eq!(handle,42);CALLS.with_borrow_mut(|calls|calls.push((name,handle)));
 let error=FAILURE.get();if error==0{{Ok(())}}else{{Err(NativeError(error))}}
}}
pub mod process {{
 use super::*;
 pub fn handle_status(handle:u32)->Result<ProcessStatus,NativeError>{{operation("status",handle)?;Ok(METADATA.get())}}
 pub fn execution_usage(handle:Option<u32>)->Result<ProcessExecutionUsage,NativeError>{{
  assert_eq!(handle,Some(42));operation("usage",handle.unwrap())?;
  Ok(ProcessExecutionUsage{{user_ticks:u64::MAX,kernel_ticks:7,ticks_per_second:500,reserved:0}})
 }}
 pub fn suspend_handle(handle:u32)->Result<(),NativeError>{{operation("suspend",handle)}}
 pub fn resume_handle(handle:u32)->Result<(),NativeError>{{operation("resume",handle)}}
 pub fn terminate_handle(handle:u32,value:u64)->Result<(),NativeError>{{assert_eq!(value,u64::MAX);operation("terminate",handle)}}
}}
pub mod handle {{
 pub use crate::{{HANDLE_RIGHT_WAIT,HANDLE_RIGHT_SIGNAL}};
 pub fn close(handle:u32)->Result<(),crate::NativeError>{{crate::operation("close",handle)}}
}}
pub mod syscall{{pub use crate::{{PROCESS_STATE_RUNNING,PROCESS_STATE_EXITED}};
 pub mod execution{{pub fn memory_usage(handle:Option<u32>)->Result<crate::ProcessMemoryUsage,crate::NativeError>{{
 assert_eq!(handle,Some(42));crate::operation("memory",42)?;Ok(crate::ProcessMemoryUsage{{current_bytes:4096,peak_bytes:8192}})
 }}}}
}}
#[derive(Debug,PartialEq)]pub enum ProcessLifecycle{{Running,Exited{{exit_code:u64}}}}
#[derive(Debug)]pub struct AttachedObject<H>{{pub handle:H,pub rights:u64}}
#[derive(Debug,PartialEq)]pub struct AuthenticatedProcess<H>{{pub handle:H,pub process_id:u64}}
pub trait ProcessBackend<H:Copy>{{
 fn image_status(&mut self,handle:H)->Result<ProcessStatus,i32>;
 fn status(&mut self,handle:H)->Result<ProcessLifecycle,i32>;
 fn execution_usage(&mut self,handle:H)->Result<ProcessExecutionUsage,i32>;
 fn memory_usage(&mut self,handle:H)->Result<ProcessMemoryUsage,i32>;
 fn suspend(&mut self,handle:H)->Result<(),i32>;
 fn resume(&mut self,handle:H)->Result<(),i32>;
 fn terminate(&mut self,handle:H,value:u64)->Result<(),i32>;
 fn release(&mut self,handle:H);
}}
struct RuntimeProcesses;
"#,
        root.join("core/crates/abi/src/lib.rs"),
        root.join("user/crates/posix-protocol/src/status.rs"),
        root.join("services/posix/src/process_control.rs"),
    );
    program.push_str(probe::between(
        include_str!("../src/main.rs"),
        "impl posix_service::ProcessBackend<u32> for RuntimeProcesses {",
        "#[cfg",
    ));
    program.push_str(
        r#"
fn main(){
 use status::Error;
 let mut backend=RuntimeProcesses;
 for (error,expected) in [
  (Error::LimitExceeded,-75),(Error::InvalidAddress,-14),(Error::ResourceUnavailable,-12),
  (Error::BackingFailure,-5),(Error::InvalidArgument,-22),(Error::AccessDenied,-13),
  (Error::NotReady,-11),(Error::AlreadyExists,-17),(Error::NotFound,-3),
  (Error::PeerClosed,-32),(Error::Unsupported,-95)
 ]{
  FAILURE.set(error.into_raw() as i64);
  assert_eq!(backend.status(42),Err(expected));
  assert_eq!(backend.image_status(42).unwrap_err(),expected);
  assert_eq!(backend.execution_usage(42).unwrap_err(),expected);
  assert_eq!(backend.memory_usage(42).unwrap_err(),expected);
  assert_eq!(backend.suspend(42),Err(expected));
  assert_eq!(backend.resume(42),Err(expected));
  assert_eq!(backend.terminate(42,u64::MAX),Err(expected));
  assert_eq!(process_control::authenticated_tree_root(AttachedObject{
   handle:42,rights:HANDLE_RIGHT_WAIT|HANDLE_RIGHT_SIGNAL
  }),Err(expected));
 }
 for error in [i64::MIN,(Error::NotFound.into_raw()|0xffff) as i64]{
  FAILURE.set(error);assert_eq!(backend.status(42),Err(-5));
  assert_eq!(backend.execution_usage(42).unwrap_err(),-5);
 }
 FAILURE.set(0);
 assert_eq!(backend.status(42),Ok(ProcessLifecycle::Running));
 assert_eq!(backend.image_status(42).unwrap().process_id,37);
 assert_eq!(backend.execution_usage(42).unwrap().user_ticks,u64::MAX);
 let valid=METADATA.get();
 METADATA.set(ProcessStatus{state:PROCESS_STATE_EXITED,exit_code:u64::MAX,..valid});
 assert_eq!(backend.status(42),Ok(ProcessLifecycle::Exited{exit_code:u64::MAX}));
 for state in [0,3,u32::MAX]{
  METADATA.set(ProcessStatus{state,..valid});assert_eq!(backend.status(42),Err(-5));
 }
 METADATA.set(ProcessStatus{reserved:1,..valid});assert_eq!(backend.status(42),Err(-5));
 METADATA.set(ProcessStatus{process_id:0,..valid});assert_eq!(backend.status(42),Err(-5));
 METADATA.set(valid);
 assert_eq!(backend.suspend(42),Ok(()));assert_eq!(backend.resume(42),Ok(()));
 assert_eq!(backend.terminate(42,u64::MAX),Ok(()));backend.release(42);
 assert_eq!(CALLS.with_borrow(|calls|calls.last().copied()),Some(("close",42)));
}
"#,
    );
    probe::run(&program);
}
