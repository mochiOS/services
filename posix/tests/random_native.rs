#[path = "support/native_error_probe.rs"]
#[allow(dead_code)]
mod probe;

#[test]
fn native_random_keeps_authority_bounds_and_distinct_failures() {
    let source = include_str!("../../../core/src/syscall/process.rs");
    let mut program =
        String::from("#![allow(dead_code)]\nextern crate self as mnu_abi;\nmod status {\n");
    program.push_str(include_str!("../../../core/crates/abi/src/status.rs"));
    program.push_str(r#"
}
use status::Error;
use std::cell::RefCell;
const BASE:u64=4096;
struct State {authorized:bool,fill_error_at:Option<usize>,copy_error:Option<Error>,fills:usize,copies:Vec<(u64,usize)>,bytes:Vec<u8>}
impl Default for State {fn default()->Self{Self{authorized:true,fill_error_at:None,copy_error:None,fills:0,copies:vec![],bytes:vec![0x71;1024]}}}
thread_local!{static STATE:RefCell<State>=RefCell::new(State::default());}
fn validate_user_ptr(pointer:u64,length:u64)->bool{pointer>=BASE&&pointer.checked_add(length).is_some_and(|end|end<=BASE+1024)}
mod capability {#[derive(Debug,PartialEq)] pub enum Capability{SystemRandomRead}}
mod syscall {
    pub mod security {pub fn caller_has_any_capability(caps:&[crate::capability::Capability])->bool{
        assert_eq!(caps,[crate::capability::Capability::SystemRandomRead]);crate::STATE.with_borrow(|s|s.authorized)
    }}
    pub fn copy_to_user_native(pointer:u64,bytes:&[u8])->Result<(),crate::Error>{
        crate::STATE.with_borrow_mut(|s|{s.copies.push((pointer,bytes.len()));if let Some(error)=s.copy_error{return Err(error);}
            let start=(pointer-crate::BASE)as usize;s.bytes[start..start+bytes.len()].copy_from_slice(bytes);Ok(())
        })
    }
}
mod random {pub fn fill(bytes:&mut[u8])->Result<(),()>{
    assert!(bytes.len()<=256);
    crate::STATE.with_borrow_mut(|s|{let index=s.fills;s.fills+=1;if s.fill_error_at==Some(index){return Err(());}bytes.fill(0x5a);Ok(())})
}}
mod implementation {
    use crate::{mnu_abi,validate_user_ptr};
"#);
    program.push_str(probe::between(
        source,
        "fn fill_random_buffer(",
        "/// FindProcessByName",
    ));
    program.push_str(r#"
}
fn main(){
    use implementation::random_fill;
    STATE.set(State::default());assert_eq!(random_fill(0,0),0);STATE.with_borrow(|s|assert_eq!(s.fills,0));
    for (pointer,length,expected) in [(0,1,Error::InvalidAddress),(BASE,u64::MAX,Error::LimitExceeded),(BASE+1023,2,Error::InvalidAddress)] {
        STATE.set(State::default());assert_eq!(random_fill(pointer,length),expected.into_raw());
        STATE.with_borrow(|s|{assert_eq!(s.fills,0);assert!(s.copies.is_empty());});
    }
    STATE.set(State{authorized:false,..State::default()});
    for (pointer,length) in [(BASE,641),(0,0),(0,u64::MAX)] {assert_eq!(random_fill(pointer,length),Error::AccessDenied.into_raw());}
    STATE.with_borrow(|s|{assert_eq!(s.fills,0);assert!(s.copies.is_empty());assert_eq!(s.bytes,vec![0x71;1024]);});
    STATE.set(State::default());assert_eq!(random_fill(BASE,641),641);
    STATE.with_borrow(|s|{assert_eq!(s.fills,3);assert_eq!(s.copies,[(BASE,256),(BASE+256,256),(BASE+512,129)]);assert_eq!(s.bytes[..641],vec![0x5a;641]);assert_eq!(s.bytes[641..],vec![0x71;383]);});
    for fail_at in [0,1] {
        STATE.set(State{fill_error_at:Some(fail_at),..State::default()});assert_eq!(random_fill(BASE,641),Error::NotReady.into_raw());
        STATE.with_borrow(|s|{assert_eq!(s.fills,fail_at+1);assert_eq!(s.copies.len(),fail_at);});
    }
    for error in [Error::InvalidAddress,Error::ResourceUnavailable,Error::BackingFailure] {
        STATE.set(State{copy_error:Some(error),..State::default()});assert_eq!(random_fill(BASE,641),error.into_raw());
        STATE.with_borrow(|s|{assert_eq!(s.fills,1);assert_eq!(s.copies.len(),1);assert_eq!(s.bytes,vec![0x71;1024]);});
    }
}
"#);
    probe::run(&program);
}

#[test]
fn native_probe_uses_the_published_random_operation_and_failure_codes() {
    let source = include_str!("native_random_status.c");
    assert!(source.contains(&format!(
        "RANDOM_FILL = {}",
        mnu_abi::SyscallNumber::RandomFill as u64
    )));
    for (name, error) in [
        (
            "NATIVE_LIMIT_EXCEEDED",
            mnu_abi::status::Error::LimitExceeded,
        ),
        (
            "NATIVE_INVALID_ADDRESS",
            mnu_abi::status::Error::InvalidAddress,
        ),
        ("NATIVE_ACCESS_DENIED", mnu_abi::status::Error::AccessDenied),
    ] {
        assert!(source.contains(&format!("{name} INT64_C({})", error.into_raw() as i64)));
    }
}
