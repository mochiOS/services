#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn inspection_snapshot_checks_native_authority_allocation_and_copy_prefixes() {
    let mut program = probe::program();
    probe::constants(
        &mut program,
        include_str!("../../../core/crates/abi/src/lib.rs"),
        &["PROCESS_INFO_RECORD_SIZE"],
    );
    program = program.replacen(
        "mod mnu_abi {",
        &format!(
            "mod mnu_abi {{pub const PROCESS_INFO_RECORD_SIZE:usize={};",
            mnu_abi::PROCESS_INFO_RECORD_SIZE
        ),
        1,
    );
    program.push_str(r#"
use std::cell::{Cell,RefCell};
use alloc::vec::Vec;
use mnu_abi::status::Error;
thread_local!{
 static PERMITTED:Cell<bool>=const{Cell::new(true)};
 static LOCKED:Cell<bool>=const{Cell::new(false)};
 static VISITS:Cell<usize>=const{Cell::new(0)};
 static COPY_ERROR:Cell<Option<Error>>=const{Cell::new(None)};
 static COPY_AFTER:Cell<usize>=const{Cell::new(0)};
 static FAIL_ALLOC:Cell<Option<usize>>=const{Cell::new(None)};
 static COPIES:RefCell<Vec<Vec<u8>>>=const{RefCell::new(Vec::new())};
}
struct Allocator;
fn fail()->bool{FAIL_ALLOC.try_with(|slot|match slot.get(){
 Some(0)=>{slot.set(None);true},Some(n)=>{slot.set(Some(n-1));false},None=>false
}).unwrap_or(false)}
unsafe impl std::alloc::GlobalAlloc for Allocator{
 unsafe fn alloc(&self,l:std::alloc::Layout)->*mut u8{if fail(){std::ptr::null_mut()}else{unsafe{std::alloc::System.alloc(l)}}}
 unsafe fn realloc(&self,p:*mut u8,l:std::alloc::Layout,n:usize)->*mut u8{if fail(){std::ptr::null_mut()}else{unsafe{std::alloc::System.realloc(p,l,n)}}}
 unsafe fn dealloc(&self,p:*mut u8,l:std::alloc::Layout){unsafe{std::alloc::System.dealloc(p,l)}}
}
#[global_allocator]static ALLOCATOR:Allocator=Allocator;
fn caller_has_process_inspect_capability()->bool{PERMITTED.get()}
mod task{
 #[derive(Copy,Clone,PartialEq,Eq)]pub struct ProcessId(pub u64);
 impl ProcessId{pub fn as_u64(self)->u64{self.0}}
 #[derive(Copy,Clone)]pub enum ProcessState{Running,Sleeping,Zombie,Terminated}
 pub struct Thread(u64);impl Thread{pub fn process_id(&self)->ProcessId{ProcessId(self.0)}}
 pub struct Process(pub u64);
 pub struct Object(pub u64);impl Object{pub fn cpu_ticks(&self)->u64{10*self.0}}
 pub struct Identity;impl Identity{pub fn package_id(&self)->&str{"test.package"}}
 impl Process{
  pub fn id(&self)->ProcessId{ProcessId(self.0)}
  pub fn state(&self)->ProcessState{match self.0{1=>ProcessState::Running,2=>ProcessState::Sleeping,3=>ProcessState::Zombie,_=>ProcessState::Terminated}}
  pub fn process_object(&self)->Object{Object(self.0)}
  pub fn mapped_memory_bytes(&self)->u64{4096*self.0}
  pub fn application_identity(&self)->Option<&Identity>{if self.0==1{Some(&Identity)}else{None}}
  pub fn name(&self)->&str{"native"}
 }
 pub fn for_each_thread(mut f:impl FnMut(&Thread)){
  assert!(!crate::LOCKED.replace(true));crate::VISITS.set(crate::VISITS.get()+1);
  for id in [1,1,2,2,2,4]{f(&Thread(id));}assert!(crate::LOCKED.replace(false));
 }
 pub fn for_each_process(mut f:impl FnMut(&Process)){
  assert!(!crate::LOCKED.replace(true));crate::VISITS.set(crate::VISITS.get()+1);
  for id in 1..=4{f(&Process(id));}assert!(crate::LOCKED.replace(false));
 }
}
mod kernel{
 use crate::*;
 pub fn copy_to_user_native(address:u64,data:&[u8])->Result<(),Error>{
  assert!(!LOCKED.get());assert_eq!(data.len(),mnu_abi::PROCESS_INFO_RECORD_SIZE);
  let count=COPIES.with_borrow(|v|v.len());assert_eq!(address,0x1000+(count*data.len())as u64);
  if count>=COPY_AFTER.get(){if let Some(e)=COPY_ERROR.get(){return Err(e);}}
  COPIES.with_borrow_mut(|v|v.push(data.to_vec()));Ok(())
 }
 pub mod process{use crate::*;
"#);
    program.push_str(probe::between(
        include_str!("../../../core/src/syscall/process.rs"),
        "pub fn list_processes(",
        "/// Creates a VM image",
    ));
    program.push_str(r#"
}}
fn reset(){assert!(!LOCKED.get());PERMITTED.set(true);VISITS.set(0);COPY_ERROR.set(None);COPY_AFTER.set(0);
 FAIL_ALLOC.set(None);COPIES.with_borrow_mut(Vec::clear);}
fn run()->u64{kernel::process::list_processes(0x1000,4*PROCESS_INFO_RECORD_SIZE as u64)}
fn main(){
 reset();assert_eq!(run(),4);
 COPIES.with_borrow(|records|{assert_eq!(records.len(),4);
  for (i,r) in records.iter().enumerate(){let id=(i+1)as u64;
   let field=|offset|u64::from_ne_bytes(r[offset..offset+8].try_into().unwrap());
   assert_eq!((field(0),field(8),field(16),field(24),field(32),field(40)),(id,id,[1,3,4,4][i],10*id,4096*id,[2,3,0,1][i]));
   let name=if i==0{b"test.package" as &[u8]}else{b"native"};
   assert_eq!(&r[48..48+name.len()],name);assert!(r[48+name.len()..].iter().all(|&b|b==0));
  }
 });
 reset();assert_eq!(kernel::process::list_processes(0x1000,2*PROCESS_INFO_RECORD_SIZE as u64+1),2);
 reset();PERMITTED.set(false);assert_eq!(run(),Error::AccessDenied.into_raw());assert_eq!(VISITS.get(),0);
 reset();for (pointer,len,expected) in [(0,104,Error::InvalidAddress),(u64::MAX,104,Error::InvalidAddress),(0x1000,u64::MAX,Error::LimitExceeded)]{
  assert_eq!(kernel::process::list_processes(pointer,len),expected.into_raw());assert_eq!(VISITS.get(),0);
 }
 for (pointer,len) in [(0,0),(0,103),(u64::MAX,103)]{reset();assert_eq!(kernel::process::list_processes(pointer,len),0);assert_eq!(VISITS.get(),0);}
 for index in [0,1]{reset();FAIL_ALLOC.set(Some(index));let result=run();FAIL_ALLOC.set(None);
  assert_eq!(result,Error::ResourceUnavailable.into_raw());assert_eq!(VISITS.get(),index+1);assert!(!LOCKED.get());assert!(COPIES.with_borrow(|v|v.is_empty()));
  reset();assert_eq!(run(),4);
 }
 for error in [Error::InvalidAddress,Error::ResourceUnavailable,Error::BackingFailure,Error::NotReady]{
  reset();COPY_ERROR.set(Some(error));assert_eq!(run(),error.into_raw());
  reset();COPY_ERROR.set(Some(error));COPY_AFTER.set(2);assert_eq!(run(),2);assert_eq!(COPIES.with_borrow(|v|v.len()),2);
 }
}
"#);
    probe::run(&program);
}

#[test]
fn system_monitor_keeps_native_inspection_permission_and_memory_failures_distinct() {
    let mut program = probe::program();
    program.push_str("use std::io;\n");
    program.push_str(probe::between(
        include_str!("../../../applications/system-monitor/src/processes.rs"),
        "fn inspection_error(",
        "#[cfg(target_os = \"mochios\")]\npub fn snapshot(",
    ));
    program.push_str(r#"
fn main(){
 for (error,kind) in [(NativeError::AccessDenied,io::ErrorKind::PermissionDenied),(NativeError::ResourceUnavailable,io::ErrorKind::OutOfMemory)]{
  assert_eq!(inspection_error(SysError::from_raw(error.into_raw()as i64)).kind(),kind);
 }
 assert_eq!(inspection_error(SysError::from_raw(-5)).raw_os_error(),Some(5));
 assert_eq!(inspection_error(SysError::from_raw(NativeError::BackingFailure.into_raw()as i64)).raw_os_error(),Some(5));
}
"#);
    probe::run(&program);
}
