use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn production_endpoint_adapters_never_return_borrowed_request_handles_on_failure() {
    let source = include_str!("../../../user/crates/posix-client/src/lib.rs");
    let mut program = String::from(
        r#"
extern crate self as mochi_user_platform;
extern crate self as mochi_user_syscall;
const MAX_OBJECT_HANDLES:usize=4;
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
struct ObjectHandleAttachment<H>{handle:H,rights:u64}
trait Transport {type Error;fn call(&self,request:&[u8],response:&mut[u8])->Result<usize,Self::Error>;}
trait ObjectTransport:Transport {type Handle:Copy;
fn close_received_handle(&self,handle:Self::Handle);
fn call_with_handles(&self,request:&[u8],response:&mut[u8],handles:&mut ObjectHandles<Self::Handle>)->Result<usize,Self::Error>;}
struct EndpointTransport{endpoint:u32} struct SyscallEndpointTransport{endpoint:u32}
thread_local!{
static MODE:std::cell::Cell<u32>=const{std::cell::Cell::new(0)};
static CLOSED:std::cell::RefCell<Vec<u32>>=const{std::cell::RefCell::new(Vec::new())};}
pub mod syscall {
pub use crate::native_status::Error as NativeError;
#[derive(Debug)]pub struct SysError(pub i64);impl SysError{pub fn from_raw(raw:i64)->Self{Self(raw)}}
pub const EINVAL:u64=22;
#[derive(Clone,Copy)]pub enum SyscallNumber{IpcCall,IpcCallObjectHandles,HandleClose}
}
pub use syscall::{SysError,SyscallNumber,EINVAL,NativeError};
pub mod handle {pub type Handle=u32;pub fn close(h:u32)->Result<(),super::SysError>{
super::CLOSED.with(|v|v.borrow_mut().push(h));Ok(())}}
pub mod ipc {
pub fn call(_:u64,_:&[u8],output:&mut[u8])->Result<u64,super::SysError>{Ok(output.len() as u64+1)}
#[derive(Clone,Copy,Default)]pub struct IpcObjectHandle{pub handle:u32,pub reserved:u32,pub rights:u64}
#[derive(Default)]pub struct IpcObjectHandles{pub count:u32,pub delivery_flags:u32,pub handles:[IpcObjectHandle;4]}
pub fn call_object_handles(_:u32,_:&[u8],output:&mut[u8],native:&mut IpcObjectHandles)->Result<u64,super::SysError>{
assert_eq!(native.count,1);assert_eq!(native.handles[0].handle,99);assert_eq!(native.handles[0].rights,1);
let mode=super::MODE.with(|v|v.get());if mode==0{return Err(super::SysError(-5))}
*native=IpcObjectHandles::default();native.count=if mode==4{5}else{1};
for (i,entry) in native.handles.iter_mut().enumerate(){entry.handle=7+i as u32;entry.rights=1;}
if mode==2{native.delivery_flags=1;}if mode==3{native.handles[0].reserved=1;}
Ok(if mode==5{output.len() as u64+1}else{0})
}}
pub use ipc::IpcObjectHandles;
pub fn call6(_:SyscallNumber,_:u64,request:u64,request_len:u64,reply:u64,reply_len:u64,handles:u64)->Result<u64,SysError>{
unsafe{ipc::call_object_handles(1,std::slice::from_raw_parts(request as *const u8,request_len as usize),
std::slice::from_raw_parts_mut(reply as *mut u8,reply_len as usize),&mut *(handles as *mut IpcObjectHandles))}}
pub fn call1(_:SyscallNumber,handle:u64)->Result<u64,SysError>{handle::close(handle as u32).map(|_|0)}
pub fn call5(_:SyscallNumber,_:u64,_:u64,_:u64,_:u64,length:u64)->Result<u64,SysError>{Ok(length+1)}
"#,
    );
    program.push_str("mod native_status {\n");
    program.push_str(include_str!("../../../core/crates/abi/src/status.rs"));
    program.push_str("}\n");
    let start = source.find("pub struct ObjectHandles<H>").unwrap();
    let end = source[start..].find("\npub trait ObjectTransport").unwrap() + start;
    program.push_str(&source[start..end]);
    for (start_marker, end_marker) in [
        (
            "impl Transport for EndpointTransport {",
            "#[cfg(feature = \"endpoint\")]\nimpl ObjectTransport",
        ),
        (
            "impl Transport for SyscallEndpointTransport {",
            "#[cfg(feature = \"syscall-endpoint\")]\nimpl ObjectTransport",
        ),
        (
            "impl ObjectTransport for EndpointTransport {",
            "#[cfg(feature = \"syscall-endpoint\")]",
        ),
        (
            "impl ObjectTransport for SyscallEndpointTransport {",
            "/// Native fast-path backend",
        ),
    ] {
        let start = source.find(start_marker).unwrap();
        let end = source[start..].find(end_marker).unwrap() + start;
        program.push_str(&source[start..end].replace("#[cfg(feature = \"syscall-endpoint\")]", ""));
    }
    program.push_str(r#"
fn check<T:ObjectTransport<Handle=u32,Error=SysError>>(transport:T){
for mode in 0..6{
MODE.with(|v|v.set(mode));CLOSED.with(|v|v.borrow_mut().clear());
let mut handles=ObjectHandles::new();handles.push(ObjectHandleAttachment{handle:99,rights:1}).unwrap();
let result=transport.call_with_handles(&[],&mut[0;4],&mut handles);
assert_eq!(result.is_ok(),mode==1);
if mode==5{assert_eq!(result.unwrap_err().0,NativeError::LimitExceeded.into_raw() as i64);}
if mode==1||mode==5{assert_eq!(handles.get(0).unwrap().handle,7);}else{assert!(handles.is_empty());}
CLOSED.with(|v|assert_eq!(*v.borrow(),match mode{2|3=>vec![7],4=>vec![7,8,9,10],_=>vec![]}));
assert!(!handles.iter().any(|h|h.handle==99));}}
fn main(){check(EndpointTransport{endpoint:1});check(SyscallEndpointTransport{endpoint:1});
assert_eq!(EndpointTransport{endpoint:1}.call(&[],&mut[0;4]).unwrap_err().0,NativeError::LimitExceeded.into_raw() as i64);
assert_eq!(SyscallEndpointTransport{endpoint:1}.call(&[],&mut[0;4]).unwrap_err().0,NativeError::LimitExceeded.into_raw() as i64);
CLOSED.with(|v|v.borrow_mut().clear());
EndpointTransport{endpoint:1}.close_received_handle(77);
SyscallEndpointTransport{endpoint:1}.close_received_handle(78);
CLOSED.with(|v|assert_eq!(*v.borrow(),vec![77,78]));}
"#);
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "mochios-object-transport-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir(&directory).unwrap();
    let executable = directory.join("probe");
    let mut compile = Command::new("rustc")
        .args(["--edition=2024", "--crate-name=object_transport", "-", "-o"])
        .arg(&executable)
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    compile
        .stdin
        .take()
        .unwrap()
        .write_all(program.as_bytes())
        .unwrap();
    let output = compile.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(Command::new(executable).status().unwrap().success());
    std::fs::remove_dir_all(directory).unwrap();
}
