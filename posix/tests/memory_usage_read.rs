#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn production_reader_enforces_handle_authority_shape_and_faultable_output() {
    let mut program = probe::program();
    program.push_str(r#"
use mnu_abi::status::Error;
use std::{cell::Cell,sync::Arc};
const SUCCESS:u64=0;
thread_local!{static CALLER:Cell<bool>=const{Cell::new(true)};static VALID:Cell<bool>=const{Cell::new(true)};static COPIES:Cell<u32>=const{Cell::new(0)};}
mod mem {pub mod residency {pub struct Snapshot{pub current_bytes:u64,pub peak_bytes:u64}}}
struct Object(bool);
impl Object {fn memory_usage(&self)->Option<mem::residency::Snapshot>{
 VALID.get().then_some(mem::residency::Snapshot{current_bytes:if self.0{4096}else{0},peak_bytes:if self.0{8192}else{16384}})
}}
enum KernelObject {Process(Arc<Object>),Other}
#[derive(PartialEq,Debug)]struct HandleRights;impl HandleRights {const WAIT:Self=Self;}
fn object_native(raw:u64,rights:HandleRights)->Result<KernelObject,Error>{
 assert_eq!(rights,HandleRights::WAIT);
 match raw {42=>Ok(KernelObject::Process(Arc::new(Object(false)))),43=>Err(Error::AccessDenied),44=>Ok(KernelObject::Other),_=>Err(Error::NotFound)}
}
mod task {use super::*;pub struct Process;impl Process{pub fn process_object(&self)->Arc<Object>{Arc::new(Object(true))}}
 pub fn with_process<T>(id:u64,f:impl FnOnce(&Process)->T)->Option<T>{assert_eq!(id,1);Some(f(&Process))}
}
mod syscall {pub mod security {pub fn current_process_id()->Option<u64>{crate::CALLER.get().then_some(1)}}
 pub fn copy_to_user_native(output:u64,bytes:&[u8])->Result<(),crate::Error>{
  crate::COPIES.set(crate::COPIES.get()+1);if output<4096||output.checked_add(bytes.len()as u64).is_none(){return Err(crate::Error::InvalidAddress)}
  unsafe{std::ptr::copy_nonoverlapping(bytes.as_ptr(),output as *mut u8,bytes.len())}Ok(())
 }
}
"#);
    let abi = include_str!("../../../core/crates/abi/src/lib.rs");
    let definition = abi
        .split("pub struct ProcessMemoryUsage {")
        .nth(1)
        .unwrap()
        .split('}')
        .next()
        .unwrap();
    program = program.replace("mod mnu_abi {", &format!("mod mnu_abi {{#[repr(C)]#[derive(Default)]pub struct ProcessMemoryUsage {{{definition}}}\n"));
    program.push_str(probe::between(
        include_str!("../../../core/src/syscall/handle.rs"),
        "pub fn process_memory_read(",
        "fn process_status_for(",
    ));
    program.push_str(r#"
fn main(){
 let mut bytes=[0xa5;18];let output=bytes.as_mut_ptr().wrapping_add(1)as u64;
 assert_eq!(process_memory_read(0,output,16),0);
 assert_eq!(&bytes[1..9],4096u64.to_ne_bytes());assert_eq!(&bytes[9..17],8192u64.to_ne_bytes());
 assert_eq!((bytes[0],bytes[17]),(0xa5,0xa5));
 assert_eq!(process_memory_read(42,output,16),0);assert_eq!(&bytes[1..9],0u64.to_ne_bytes());assert_eq!(&bytes[9..17],16384u64.to_ne_bytes());
 for (raw,error) in [(43,Error::AccessDenied),(44,Error::InvalidArgument),(99,Error::NotFound)]{assert_eq!(process_memory_read(raw,output,16),error.into_raw());}
 for length in [0,8,15,17,32]{assert_eq!(process_memory_read(0,1,length),Error::InvalidArgument.into_raw());}
 let copies=COPIES.get();VALID.set(false);assert_eq!(process_memory_read(42,output,16),Error::NotReady.into_raw());
 CALLER.set(false);assert_eq!(process_memory_read(0,output,16),Error::NotReady.into_raw());assert_eq!(COPIES.get(),copies);
 CALLER.set(true);VALID.set(true);for output in [0,1,u64::MAX]{assert_eq!(process_memory_read(0,output,16),Error::InvalidAddress.into_raw());}
}
"#);
    probe::run(&program);
}
