#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn ordinary_open_special_handles_probe_actual_terminal_control_and_preserve_errors() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let mut program = format!(
        r#"
#![allow(dead_code,non_camel_case_types)]
extern crate self as mnu_abi;
#[path={:?}]mod abi;pub use abi::*;pub use abi::status;
#[path={:?}]mod posix_protocol;pub use posix_protocol::*;
type c_int=i32;
const ENOTTY:i32=25;const ENOTSUP:i32=95;const ENOSYS:i32=38;
const EIO:i32=5;const EOVERFLOW:i32=75;const EFAULT:i32=14;
#[derive(Clone,Copy,PartialEq)]enum FdKind{{Stdin,Stdout,Stderr,ObjectPty,ObjectSpecial,ObjectFile}}
#[derive(Clone,Copy)]struct Object{{kind:FdKind,lower_handle:u64}}
#[derive(Clone,Copy)]struct FdEntry{{handle:Object}}
thread_local!{{
 static KIND:std::cell::Cell<FdKind>=const{{std::cell::Cell::new(FdKind::ObjectSpecial)}};
 static ERROR:std::cell::Cell<i32>=const{{std::cell::Cell::new(0)}};
 static ERRNO:std::cell::Cell<i32>=const{{std::cell::Cell::new(0)}};
 static SHORT:std::cell::Cell<bool>=const{{std::cell::Cell::new(false)}};
 static CALLS:std::cell::Cell<u32>=const{{std::cell::Cell::new(0)}};
 static LEASES:std::cell::Cell<u32>=const{{std::cell::Cell::new(0)}};
}}
struct Lease(FdEntry);
impl std::ops::Deref for Lease{{type Target=FdEntry;fn deref(&self)->&FdEntry{{&self.0}}}}
impl Drop for Lease{{fn drop(&mut self){{LEASES.set(LEASES.get()-1)}}}}
fn with_fd_entry(fd:i32)->Result<Lease,i32>{{if fd!=4{{return Err(9)}}LEASES.set(LEASES.get()+1);Ok(Lease(FdEntry{{handle:Object{{kind:KIND.get(),lower_handle:41}}}}))}}
mod io_resources{{pub fn with<T,R>(get:impl FnOnce()->Result<T,i32>,run:impl FnOnce(&T)->Result<R,i32>)->Result<R,i32>{{let owned=get()?;run(&owned)}}}}
fn result_with_errno(result:Result<i32,i32>,failure:i32)->i32{{result.unwrap_or_else(|e|{{ERRNO.set(e);failure}})}}
fn set_errno(error:i32){{ERRNO.set(error)}}
fn retry_terminal_operation<T>(signal:u32,mut op:impl FnMut()->Result<T,i32>)->Result<T,i32>{{assert_eq!(signal,posix_protocol::SIGNAL_TTOU);op()}}
fn syscall_errno(result:Result<u64,i32>)->Result<u64,i32>{{result}}
mod syscall{{
 pub enum SyscallNumber{{HandleControl}}
 pub fn raw_syscall6(_:SyscallNumber,handle:u64,code:u64,_input:u64,input_len:u64,output:u64,capacity:u64)->Result<u64,i32>{{
  assert_eq!(handle,41);assert_eq!(code,super::posix_protocol::PTY_CONTROL_GET_ATTRIBUTES);assert_eq!(input_len,0);
  assert_eq!(capacity,super::posix_protocol::TERMINAL_ATTRIBUTES_LEN as u64);
  super::CALLS.set(super::CALLS.get()+1);
  if super::ERROR.get()!=0{{return Err(super::ERROR.get())}}
  let buffer=unsafe{{std::slice::from_raw_parts_mut(output as *mut u8,capacity as usize)}};
  super::posix_protocol::encode_terminal_attributes(Default::default(),buffer).unwrap();
  Ok(if super::SHORT.get(){{1}}else{{capacity}})
 }}
}}
type NewlibTermios=posix_protocol::TerminalAttributes;
fn terminal_attributes_to_newlib(value:NewlibTermios)->NewlibTermios{{value}}
mod terminal_memory{{pub fn write_attributes(ptr:*mut super::NewlibTermios,value:super::NewlibTermios)->Result<(),i32>{{unsafe{{ptr.write(value)}};Ok(())}}}}
"#,
        root.join("core/crates/abi/src/lib.rs"),
        root.join("user/crates/posix-protocol/src/lib.rs")
    );
    program.push_str(probe::between(
        runtime,
        "fn terminal_control(",
        "#[unsafe(no_mangle)]\npub unsafe extern \"C\" fn tcgetwinsize",
    ));
    program.push_str(probe::between(
        runtime,
        "pub extern \"C\" fn _isatty(",
        "#[unsafe(no_mangle)]\npub extern \"C\" fn isatty(",
    ));
    program.push_str(probe::between(
        runtime,
        "pub extern \"C\" fn tcgetattr(",
        "#[unsafe(no_mangle)]\npub extern \"C\" fn tcsetattr(",
    ));
    program.push_str(r#"
fn main(){
 for kind in [FdKind::ObjectSpecial,FdKind::ObjectPty]{
  KIND.set(kind);CALLS.set(0);ERROR.set(0);SHORT.set(false);
  assert_eq!(_isatty(4),1);assert_eq!(CALLS.get(),1);assert_eq!(LEASES.get(),0);
  let mut attributes=NewlibTermios::default();
  assert_eq!(tcgetattr(4,&mut attributes),0);assert_eq!(attributes,NewlibTermios::default());assert_eq!(LEASES.get(),0);
 }
 KIND.set(FdKind::ObjectSpecial);
 for (error,expected) in [(95,25),(38,25),(25,25),(13,13),(5,5),(32,32),(9,9)]{
  ERROR.set(error);assert_eq!(_isatty(4),0);assert_eq!(ERRNO.get(),expected);assert_eq!(LEASES.get(),0);
  let mut attributes=NewlibTermios::default();
  assert_eq!(tcgetattr(4,&mut attributes),-1);assert_eq!(ERRNO.get(),expected);assert_eq!(LEASES.get(),0);
 }
 ERROR.set(0);SHORT.set(true);assert_eq!(_isatty(4),0);assert_eq!(ERRNO.get(),5);
 KIND.set(FdKind::ObjectFile);CALLS.set(0);assert_eq!(_isatty(4),0);assert_eq!(ERRNO.get(),25);assert_eq!(CALLS.get(),0);
 assert_eq!(_isatty(-1),0);assert_eq!(ERRNO.get(),9);assert_eq!(LEASES.get(),0);
 assert_eq!(tcgetattr(4,std::ptr::null_mut()),-1);assert_eq!(ERRNO.get(),14);
}
"#);
    probe::run(&program);
}
