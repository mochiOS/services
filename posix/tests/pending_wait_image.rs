#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn production_deferred_waits_validate_image_and_endpoint_before_consuming_events() {
    let main = include_str!("../src/main.rs");
    let mut program = String::from(
        r#"
#![allow(dead_code)]
extern crate self as posix_service;
extern crate self as mochi_user_platform;
extern crate self as mochios_posix_protocol;
use std::cell::Cell;
thread_local! {
static IMAGE:Cell<u64>=const{Cell::new(0)};
static FAILURE:Cell<i32>=const{Cell::new(0)};
static ENDPOINT_FAILURE:Cell<bool>=const{Cell::new(false)};
static ENDPOINT_OWNER:Cell<u64>=const{Cell::new(1)};
static IMAGE_READS:Cell<u32>=const{Cell::new(0)};
static CONSUMED:Cell<u32>=const{Cell::new(0)};
static REPLIES:Cell<u32>=const{Cell::new(0)};
static REPLY_FAILURE:Cell<bool>=const{Cell::new(false)};
static ENCODE_FAILURE:Cell<bool>=const{Cell::new(false)};
static PAYLOAD_FAILURE:Cell<bool>=const{Cell::new(false)};
static STATUS:Cell<i32>=const{Cell::new(0)};
}
pub const STATUS_EAGAIN:i32=-11;pub const STATUS_ESRCH:i32=-3;
pub const STATUS_EPERM:i32=-1;pub const STATUS_EIO:i32=-5;
pub const HEADER_LEN:usize=24;pub const MAX_MESSAGE_LEN:usize=256;
pub mod signal_wait {pub const LEN:usize=64;}
pub mod mnu_abi {
#[derive(Clone,Copy,PartialEq,Eq)]pub struct ExecutionIdentity{pub process_id:u64,pub thread_id:u64}
}
#[derive(Clone,Copy)]pub struct PeerIdentity{pub process_id:u64}
#[derive(Clone,Copy)]pub struct RequestImage(u64);
#[derive(Clone,Copy)]pub struct WaitRequest;
pub type WaitInfo=i32;
pub struct PosixService<T=u32>(std::marker::PhantomData<T>);
impl PosixService<u32> {
fn validate_request_image(&mut self,_:PeerIdentity,image:RequestImage,_:&mut RuntimeProcesses)->Result<(),i32>{
 IMAGE_READS.set(IMAGE_READS.get()+1);
 if FAILURE.get()!=0 {return Err(FAILURE.get())}
 if image.0!=IMAGE.get(){Err(STATUS_ESRCH)}else{Ok(())}
}
fn validate_wait_delivery_epoch(&self,_:PeerIdentity,_:mnu_abi::ExecutionIdentity,_:u64)->Result<(),i32>{Ok(())}
fn wait_child_info_with_reply<R:FnOnce(i32)->bool>(&mut self,_:PeerIdentity,_:WaitRequest,_:&mut RuntimeFilesystem,_:&mut RuntimeProcesses,reply:R)->Result<Option<i32>,i32>{
 if reply(37){CONSUMED.set(CONSUMED.get()+1);Ok(Some(37))}else{Ok(None)}
}
fn poll_wait_signal_info(&mut self,_:PeerIdentity,_:mnu_abi::ExecutionIdentity,_:u64,_:u64,_:Option<u64>,_:u64)->Result<Option<u32>,i32>{
 CONSUMED.set(CONSUMED.get()+1);Ok(Some(10))
}
}
pub struct RuntimeProcesses;pub struct RuntimeFilesystem;
struct NativeError;impl NativeError{fn raw(&self)->i64{-3}}
mod process_control {pub fn lifecycle_failure(error:i64)->i32{error as i32}}
mod ipc {
pub fn endpoint_execution_identity(_:u64)->Result<crate::mnu_abi::ExecutionIdentity,crate::NativeError>{
 if crate::ENDPOINT_FAILURE.get(){Err(crate::NativeError)}else{Ok(crate::mnu_abi::ExecutionIdentity{process_id:crate::ENDPOINT_OWNER.get(),thread_id:11})}
}
pub fn reply(_:u64,bytes:&[u8])->Result<u64,crate::NativeError>{
 crate::REPLIES.set(crate::REPLIES.get()+1);crate::STATUS.set(i32::from_le_bytes(bytes[..4].try_into().unwrap()));
 if crate::REPLY_FAILURE.get(){Err(crate::NativeError)}else{Ok(0)}
}}
mod time {pub fn monotonic_nanoseconds()->Result<u64,crate::NativeError>{Ok(100)}}
pub struct Header{status:i32}pub struct Response{header:Header,payload:Vec<u8>}
pub fn encode(header:Header,_:&[u8],out:&mut[u8])->Result<usize,()> {if ENCODE_FAILURE.get(){return Err(())}out[..4].copy_from_slice(&header.status.to_le_bytes());Ok(4)}
fn wait_info_response(_:u64,result:Result<i32,i32>,_:bool)->Response{if PAYLOAD_FAILURE.get(){response(Err(-22))}else{response(result.map(|_|()))}}
fn signal_wait_response(_:u64,result:Result<u32,i32>)->Response{response(result.map(|_|()))}
fn response(result:Result<(),i32>)->Response{Response{header:Header{status:result.err().unwrap_or(0)},payload:vec![]}}
#[derive(Clone,Copy)]struct PendingWait {
sender:u64,peer:PeerIdentity,request_id:u64,request:WaitRequest,
guard:Option<(mnu_abi::ExecutionIdentity,u64)>,detailed:bool,image:RequestImage,
}
#[derive(Clone,Copy)]struct PendingSignalWait {
sender:u64,peer:PeerIdentity,identity:mnu_abi::ExecutionIdentity,request_id:u64,
mask:u64,epoch:u64,deadline:Option<u64>,image:RequestImage,
}
"#,
    );
    program.push_str(probe::between(
        main,
        "fn validate_pending_request_image(",
        "#[cfg(target_os = \"mochios\")]\nfn complete_pending_signal_waits(",
    ));
    program.push_str(probe::between(
        main,
        "fn complete_pending_signal_waits(",
        "#[cfg(target_os = \"mochios\")]\nfn signal_wait_response(",
    ));
    program.push_str(probe::between(
        main,
        "fn reply_wait_info(",
        "#[cfg(target_os = \"mochios\")]\nfn complete_pending_waits(",
    ));
    program.push_str(probe::between(
        main,
        "fn complete_pending_waits(",
        "#[cfg(target_os = \"mochios\")]\nfn wait_for_request_or_child(",
    ));
    program.push_str(
        r#"
fn main(){
for signal in [false,true] {for guarded in [false,true] {for mode in 0..9 {
 if signal&&mode>=6{continue}
 IMAGE.set(if mode==1{1}else{0});FAILURE.set(match mode{2=>-5,5=>-3,_=>0});
 ENDPOINT_OWNER.set(if mode==4{2}else{1});IMAGE_READS.set(0);
 REPLY_FAILURE.set(mode==6);
 ENCODE_FAILURE.set(mode==7);PAYLOAD_FAILURE.set(mode==8);
 ENDPOINT_FAILURE.set(mode==3);CONSUMED.set(0);REPLIES.set(0);STATUS.set(99);
 let mut service=PosixService(std::marker::PhantomData);let mut processes=RuntimeProcesses;
 if signal {
 let mut pending=vec![PendingSignalWait{sender:5,peer:PeerIdentity{process_id:1},
 identity:mnu_abi::ExecutionIdentity{process_id:1,thread_id:11},request_id:7,
 mask:1<<9,epoch:0,deadline:None,image:RequestImage(0)}];
"#,
    );
    program.push_str("complete_pending_signal_waits(&mut pending,&mut service,&mut processes);");
    program.push_str(
        r#"
 assert!(pending.is_empty());
 } else {
 let mut pending=vec![PendingWait{sender:5,peer:PeerIdentity{process_id:1},request_id:7,
 request:WaitRequest,guard:if guarded{Some((mnu_abi::ExecutionIdentity{process_id:1,thread_id:11},0))}else{None},
 detailed:guarded,image:RequestImage(0)}];
 complete_pending_waits(&mut pending,&mut service,&mut RuntimeFilesystem,&mut processes);
 assert!(pending.is_empty());
 }
 assert_eq!(CONSUMED.get(),u32::from(mode==0),"signal={signal}, mode={mode}");
 assert_eq!(REPLIES.get(),u32::from(mode!=7));
 assert_eq!(STATUS.get(),match mode{0|6=>0,2=>-5,4=>-1,7=>99,8=>-22,_=>-3});
 assert_eq!(IMAGE_READS.get(),u32::from(![3,4].contains(&mode)));
}}}
}
"#,
    );
    probe::run(&program);
}
