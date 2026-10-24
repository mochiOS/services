#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn captured_image_authorization_replies_cross_the_real_wire_to_newlib_boundary() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let mut program = String::from(
        "#![allow(dead_code)]\nextern crate alloc;\nextern crate self as mochios_posix_client;\nmod mnu_abi {pub mod status {\n",
    );
    program.push_str(include_str!("../../../core/crates/abi/src/status.rs"));
    program.push_str("}\npub mod exec {\n");
    program.push_str(include_str!("../../../core/crates/abi/src/exec.rs"));
    program.push_str("}}\nmod mochios_posix_protocol {\n");
    probe::constants(
        &mut program,
        include_str!("../../../user/crates/posix-protocol/src/lib.rs"),
        &["STATUS_EIO", "STATUS_EAGAIN"],
    );
    program.push_str("pub mod status {\n");
    program.push_str(
        &include_str!("../../../user/crates/posix-protocol/src/status.rs")
            .replace("mnu_abi::", "crate::mnu_abi::")
            .replace("crate::STATUS_", "super::STATUS_"),
    );
    program.push_str("}}\nmod newlib_errno {\n");
    program.push_str(include_str!(
        "../../../user/crates/posix-client/src/newlib_errno.rs"
    ));
    program.push_str("use crate::mochios_posix_protocol;\n}\nmod mochios_capability_protocol {\n");
    program.push_str(
        &include_str!("../../../user/crates/capability-protocol/src/lib.rs")
            .strip_prefix("#![cfg_attr(not(feature = \"std\"), no_std)]\n")
            .unwrap()
            .replace("#[cfg(feature = \"alloc\")]\n", ""),
    );
    program.push_str("}\n");
    program.push_str(r#"
use core::ffi::c_int;
use newlib_errno::{EIO,EINVAL,ENOENT};
const CAPABILITY_SERVICE_NAME:&[u8]=b"capability.service";
#[derive(Default)]struct State{status:u64,mode:u32,calls:usize}
thread_local!{static STATE:std::cell::RefCell<State>=std::cell::RefCell::new(State::default());}
fn syscall_errno(result:Result<u64,c_int>)->Result<u64,c_int>{result}
mod syscall {
use super::*;
pub enum SyscallNumber{FindProcessByName,IpcCall}
pub fn raw_syscall2(op:SyscallNumber,name:u64,length:u64)->Result<u64,c_int>{
assert!(matches!(op,SyscallNumber::FindProcessByName));
assert_eq!(unsafe{std::slice::from_raw_parts(name as *const u8,length as usize)},CAPABILITY_SERVICE_NAME);
STATE.with_borrow_mut(|state|{
state.calls+=1;
match state.mode {1=>Ok(0),2=>Err(newlib_errno::EAGAIN),_=>Ok(7)}
})}
pub fn raw_syscall5(op:SyscallNumber,endpoint:u64,request:u64,length:u64,reply:u64,capacity:u64)->Result<u64,c_int>{
assert!(matches!(op,SyscallNumber::IpcCall));assert_eq!(endpoint,7);
let request=unsafe{std::slice::from_raw_parts(request as *const u8,length as usize)};
let opcode=u32::from_le_bytes(request[..4].try_into().unwrap());
assert_eq!(opcode,mochios_capability_protocol::AUTHORIZE_CAPTURED_IMAGE_OPCODE);
{
assert_eq!(mochios_capability_protocol::decode_authorize_captured_image_request(request).unwrap(),"opaque:unregistered");
}
STATE.with_borrow_mut(|state|{
state.calls+=1;
if state.mode==3{return Err(newlib_errno::ENOTSUP)}
let bytes=state.status.to_le_bytes().to_vec();
assert!(bytes.len()<=capacity as usize);
unsafe{std::ptr::copy_nonoverlapping(bytes.as_ptr(),reply as *mut u8,bytes.len());}
Ok((7u64<<32)|if state.mode==4{1}else{bytes.len() as u64})
})}
}
"#);
    program.push_str(probe::between(
        runtime,
        "fn map_kernel_errno(",
        "fn map_posix_client_error(",
    ));
    program.push_str(probe::between(
        runtime,
        "fn authorize_captured_image(",
        "fn replace_process_image(",
    ));
    program.push_str(
        r#"
fn call(status:u64,mode:u32)->Result<(),c_int>{
STATE.set(State{status,mode,..Default::default()});
let result=authorize_captured_image("opaque:unregistered");
STATE.with_borrow(|state|assert_eq!(state.calls,if mode==1||mode==2{1}else{2}));
result
}
fn main(){
assert_eq!(call(0,0),Ok(()));
for (wire,expected) in [
(13,newlib_errno::EACCES),(36,newlib_errno::ENAMETOOLONG),(38,newlib_errno::ENOSYS),
(75,newlib_errno::EOVERFLOW),(95,newlib_errno::ENOTSUP),(35,newlib_errno::EDEADLK),
(90,122),(91,107),(122,132),(139,newlib_errno::EIO),
(i32::MAX as u64,newlib_errno::EIO),(u64::MAX,newlib_errno::EIO),
]{
assert_eq!(call(wire,0),Err(expected),"wire={wire}");
}
assert_eq!(call(0,1),Err(ENOENT));
assert_eq!(call(0,2),Err(newlib_errno::EAGAIN));
assert_eq!(call(0,3),Err(newlib_errno::ENOTSUP));
assert_eq!(call(0,4),Err(EIO));
STATE.set(State::default());
assert_eq!(authorize_captured_image(""),Err(EINVAL));
STATE.with_borrow(|state|assert_eq!(state.calls,0));
}
"#,
    );
    probe::run(&program);
}
