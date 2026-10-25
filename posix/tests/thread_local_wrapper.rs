#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn wrapper_preserves_native_errors_and_checks_the_success_contract() {
    let mut program = probe::program().replace(
        "mod mnu_abi {pub mod status {",
        "mod mnu_abi {pub const SUCCESS:u64=0;pub mod status {",
    );
    program.push_str(r#"
use std::cell::Cell;
use mnu_abi::status::Error;
enum SyscallNumber{ThreadLocalBaseSet}
thread_local!{static FAILURE:Cell<Option<Error>>=const{Cell::new(None)};static STATUS:Cell<u64>=const{Cell::new(0)};static CALLS:Cell<usize>=const{Cell::new(0)};}
fn call2(_:SyscallNumber,base:u64,reserved:u64)->SysResult<u64>{assert_eq!(base,8192);assert_eq!(reserved,0);CALLS.set(CALLS.get()+1);match FAILURE.get(){Some(e)=>Err(SysError::from_raw(e.into_raw() as i64)),None=>Ok(STATUS.get())}}
mod actual{use crate::{mnu_abi,SysError,SysResult,SyscallNumber,Error};
"#);
    let wrapper = include_str!("../../../user/crates/syscall/src/thread_local.rs");
    program.push_str(&wrapper[wrapper.find("pub fn set_base(").unwrap()..]);
    program.push_str("\n}\n");
    let kernel = include_str!("../../../core/src/syscall/mod.rs");
    let start = kernel.find("fn is_canonical_user_range(").unwrap();
    let end = start + kernel[start..].find("\n}\n").unwrap() + 2;
    program.push_str(&kernel[start..end]);
    program.push_str(r#"
fn main(){
 assert_eq!(actual::set_base(8192),Ok(()));
 for error in [Error::InvalidArgument,Error::InvalidAddress,Error::NotReady,Error::BackingFailure]{
  FAILURE.set(Some(error));assert_eq!(actual::set_base(8192).unwrap_err().native_error(),Some(error));
 }
 FAILURE.set(None);STATUS.set(1);
 assert_eq!(actual::set_base(8192).unwrap_err().native_error(),Some(Error::BackingFailure));
 assert_eq!(CALLS.get(),6);
 for base in [1,4096,0x7fff_ffff_ffff]{assert!(is_canonical_user_range(base,0));}
 for base in [0,0x8000_0000_0000,0xffff_8000_0000_0000,u64::MAX]{assert!(!is_canonical_user_range(base,0));}
}
"#);
    probe::run(&program);
}
