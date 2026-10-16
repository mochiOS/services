#[path = "support/native_error_probe.rs"]
#[allow(dead_code)]
mod probe;

#[test]
fn actual_getentropy_checks_address_overflow_and_advances_only_completed_bytes() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let mut program = String::from(
        "#![allow(dead_code)]\nuse std::{ffi::{c_void,c_int},cell::RefCell,collections::VecDeque};\n",
    );
    probe::constants(
        &mut program,
        include_str!("../../../user/crates/posix-client/src/newlib_errno.rs"),
        &["EIO", "EINTR", "EFAULT", "EACCES"],
    );
    program.push_str(
        r#"
mod newlib_errno {pub use super::{EIO,EINTR};}
mod mochios_posix_client {pub mod random {
"#,
    );
    program.push_str(include_str!(
        "../../../user/crates/posix-client/src/random.rs"
    ));
    program.push_str(r#"
}}
#[derive(Default)] struct State{errno:i32,replies:VecDeque<Result<u64,i32>>,calls:Vec<(u64,u64)>}
thread_local!{static STATE:RefCell<State>=RefCell::new(State::default());}
fn set_errno(error:i32){STATE.with_borrow_mut(|s|s.errno=error);}
fn result_with_errno(result:Result<i32,i32>,failure:i32)->i32{match result{Ok(value)=>value,Err(error)=>{set_errno(error);failure}}}
fn syscall_errno(value:Result<u64,i32>)->Result<u64,i32>{value}
mod syscall {
    pub enum SyscallNumber{RandomFill}
    pub fn raw_syscall2(_:SyscallNumber,address:u64,length:u64)->Result<u64,i32>{crate::STATE.with_borrow_mut(|s|{s.calls.push((address,length));s.replies.pop_front().expect("extra native call")})}
}
"#);
    program.push_str(probe::between(
        runtime,
        "pub extern \"C\" fn getentropy(",
        "#[unsafe(no_mangle)]",
    ));
    program.push_str(r#"
fn main(){
    for (pointer,length,expected) in [(usize::MAX-1,4,EFAULT),(0,1,EFAULT),(4096,257,EIO)] {
        STATE.set(State::default());assert_eq!(getentropy(pointer as *mut c_void,length),-1);
        STATE.with_borrow(|s|{assert_eq!(s.errno,expected);assert!(s.calls.is_empty());});
    }
    STATE.set(State{errno:123,..State::default()});assert_eq!(getentropy(usize::MAX as *mut c_void,0),0);
    STATE.with_borrow(|s|{assert_eq!(s.errno,123);assert!(s.calls.is_empty());});
    STATE.set(State{errno:123,replies:vec![Ok(3),Err(EINTR),Ok(2),Ok(3)].into(),..State::default()});
    assert_eq!(getentropy(4096 as *mut c_void,8),0);
    STATE.with_borrow(|s|{assert_eq!(s.errno,123);assert_eq!(s.calls,[(4096,8),(4099,5),(4099,5),(4101,3)]);assert!(s.replies.is_empty());});
    STATE.set(State{replies:vec![Ok(3),Err(EACCES)].into(),..State::default()});
    assert_eq!(getentropy(4096 as *mut c_void,8),-1);
    STATE.with_borrow(|s|{assert_eq!(s.errno,EACCES);assert_eq!(s.calls,[(4096,8),(4099,5)]);});
}
"#);
    probe::run(&program);
}
