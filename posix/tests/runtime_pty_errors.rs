//! Execute target-only PTY/native-reference adapters with real status codecs.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn pty_and_retained_object_failures_use_wire_status_without_leaking_owned_handles() {
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
pub const STATUS_EIO:i32=-5;pub const STATUS_EAGAIN:i32=-11;pub const SIGNAL_HUP:u32=1;
use std::cell::{{Cell,RefCell}};
thread_local!{{
 static TRANSPORT:Cell<i64>=const{{Cell::new(0)}};
 static WIRE:Cell<i64>=const{{Cell::new(0)}};
 static LENGTH:Cell<u64>=const{{Cell::new(8)}};
 static RETURNED:Cell<u32>=const{{Cell::new(0)}};
 static CREATE_AT:Cell<u32>=const{{Cell::new(0)}};
 static CREATED:Cell<u32>=const{{Cell::new(0)}};
 static NATIVE:Cell<i64>=const{{Cell::new(0)}};
 static POLICY:Cell<i32>=const{{Cell::new(0)}};
 static SENDS:Cell<u32>=const{{Cell::new(0)}};
 static DISCARDS:Cell<u32>=const{{Cell::new(0)}};
 static CLOSED:RefCell<Vec<u32>>=const{{RefCell::new(Vec::new())}};
}}
#[derive(Debug)]pub struct NativeError(i64);impl NativeError{{fn raw(&self)->i64{{self.0}}}}
pub mod pty {{
 #[derive(Clone,Copy)]pub struct PtyPair{{pub master_object_id:u64,pub slave_object_id:u64}}
 pub struct TerminalSignal{{pub terminal_id:u64,pub signal:u32}}
 pub struct PtyManager;
 impl PtyManager{{
  pub fn open(&mut self)->Result<PtyPair,i32>{{Ok(PtyPair{{master_object_id:37,slave_object_id:38}})}}
  pub fn discard(&mut self,pair:PtyPair){{assert_eq!((pair.master_object_id,pair.slave_object_id),(37,38));crate::DISCARDS.set(crate::DISCARDS.get()+1)}}
 }}
}}
pub struct PosixService<H>(std::marker::PhantomData<H>);
impl PosixService<u32>{{
 fn hangup_terminal(&mut self,id:u64)->Result<(),i32>{{assert_eq!(id,37);let error=POLICY.get();if error==0{{Ok(())}}else{{Err(error)}}}}
 fn signal_terminal_foreground_group(&mut self,id:u64,_:u32)->Result<(),i32>{{self.hangup_terminal(id)}}
}}
pub mod handle {{
 pub type Handle=u32;
 pub use crate::{{HANDLE_RIGHT_READ,HANDLE_RIGHT_WRITE,HANDLE_RIGHT_WAIT,HANDLE_RIGHT_CONTROL,HANDLE_RIGHT_DUPLICATE,HANDLE_RIGHT_TRANSFER}};
 pub fn close(handle:u32)->Result<(),crate::NativeError>{{crate::CLOSED.with_borrow_mut(|closed|closed.push(handle));Ok(())}}
 pub fn create_provider_object(endpoint:u32,id:u64,rights:u64)->Result<u32,crate::NativeError>{{
  assert_eq!(endpoint,11);
  assert_eq!(rights,HANDLE_RIGHT_READ|HANDLE_RIGHT_WRITE|HANDLE_RIGHT_WAIT|HANDLE_RIGHT_CONTROL|HANDLE_RIGHT_DUPLICATE|HANDLE_RIGHT_TRANSFER);
  let call=crate::CREATED.get()+1;crate::CREATED.set(call);assert_eq!(id,36+u64::from(call));
  if crate::CREATE_AT.get()==call{{Err(crate::NativeError(crate::NATIVE.get()))}}else{{Ok(100+call)}}
 }}
 pub fn duplicate(handle:u32,rights:u64)->Result<u32,crate::NativeError>{{
  assert_eq!((handle,rights),(44,HANDLE_RIGHT_READ|HANDLE_RIGHT_DUPLICATE));
  let error=crate::NATIVE.get();if error==0{{Ok(55)}}else{{Err(crate::NativeError(error))}}
 }}
}}
pub mod ipc {{
 use super::*;
 #[derive(Clone,Copy,Default)]pub struct IpcObjectHandle{{pub handle:u32,pub reserved:u32,pub rights:u64}}
 #[derive(Default)]pub struct IpcObjectHandles{{pub count:u32,pub handles:[IpcObjectHandle;4]}}
 pub fn call(endpoint:u64,request:&[u8],response:&mut[u8])->Result<u64,NativeError>{{
  assert_eq!(endpoint,11);assert_eq!(request.len(),20);assert_eq!(&request[..4],b"PTYS");
  let error=TRANSPORT.get();if error!=0{{return Err(NativeError(error))}}
  response.copy_from_slice(&WIRE.get().to_le_bytes());Ok(LENGTH.get())
 }}
 pub fn call_object_handles(endpoint:u32,request:&[u8],response:&mut[u8],objects:&mut IpcObjectHandles)->Result<u64,NativeError>{{
  assert_eq!((endpoint,request),(11,&b"PTYI"[..]));
  assert_eq!((objects.count,objects.handles[0].handle,objects.handles[0].rights),(1,77,HANDLE_RIGHT_TRANSFER));
  let error=TRANSPORT.get();if error!=0{{return Err(NativeError(error))}}
  objects.count=u32::from(RETURNED.get()!=0);objects.handles[0].handle=RETURNED.get();
  response.copy_from_slice(&WIRE.get().to_le_bytes());Ok(LENGTH.get())
 }}
 pub fn send(endpoint:u64,request:&[u8])->Result<u64,NativeError>{{
  assert_eq!((endpoint,request),(11,&b"PTYW"[..]));SENDS.set(SENDS.get()+1);
  let error=TRANSPORT.get();if error==0{{Ok(4)}}else{{Err(NativeError(error))}}
 }}
}}
pub struct Header{{status:i32,request_id:u64}}
pub struct Response{{header:Header}}
pub struct OpenedObject<H>{{handle:H,rights:u64}}
pub struct ObjectResponse<H>{{response:Response,handles:Vec<OpenedObject<H>>}}
pub struct AttachedObject<H>{{handle:H,rights:u64}}
fn status_response(request_id:u64,status:i32)->Response{{Response{{header:Header{{request_id,status}}}}}}
fn success_response(request_id:u64)->Response{{status_response(request_id,0)}}
"#,
        root.join("core/crates/abi/src/lib.rs"),
        root.join("user/crates/posix-protocol/src/status.rs"),
    );
    let source = include_str!("../src/main.rs");
    probe::constants(
        &mut program,
        source,
        &["PTY_SYNC_MAGIC", "PTY_IDENTIFY_MAGIC", "PTY_WAKE_MAGIC"],
    );
    for (start, end) in [
        ("fn notify_terminal_signal(", "#[cfg"),
        ("fn identify_pty_terminal(", "#[cfg"),
        ("fn sync_pty_provider(", "#[cfg"),
        ("fn open_pty_response(", "#[cfg"),
    ] {
        program.push_str(probe::between(source, start, end));
    }
    program.push_str("struct RuntimeFilesystem;impl RuntimeFilesystem {");
    program.push_str(probe::between(
        source,
        "    fn retain_object(",
        "    fn release_object(",
    ));
    program.push_str(
        r#"
}
fn reset(){
 TRANSPORT.set(0);WIRE.set(0);LENGTH.set(8);RETURNED.set(0);CREATE_AT.set(0);
 CREATED.set(0);NATIVE.set(0);POLICY.set(0);SENDS.set(0);DISCARDS.set(0);CLOSED.with_borrow_mut(Vec::clear);
}
fn closed(expected:&[u32]){CLOSED.with_borrow(|closed|assert_eq!(closed,expected))}
fn main(){
 use status::Error;
 let manager=std::sync::Mutex::new(pty::PtyManager);
 let state=std::sync::Mutex::new(PosixService(std::marker::PhantomData));
 for (error,expected) in [
  (Error::LimitExceeded,-75),(Error::InvalidAddress,-14),(Error::ResourceUnavailable,-12),
  (Error::BackingFailure,-5),(Error::InvalidArgument,-22),(Error::AccessDenied,-13),
  (Error::NotReady,-11),(Error::AlreadyExists,-17),(Error::NotFound,-2),
  (Error::PeerClosed,-32),(Error::Unsupported,-95)
 ]{
  let raw=error.into_raw() as i64;
  for stage in [1,2]{
   reset();CREATE_AT.set(stage);NATIVE.set(raw);
   let result=open_pty_response(&manager,11,9, |_|Ok(()));
   assert_eq!((result.response.header.request_id,result.response.header.status),(9,expected));
   assert!(result.handles.is_empty());assert_eq!(DISCARDS.get(),1);
   if stage==1{closed(&[])}else{closed(&[101])}
  }
  reset();TRANSPORT.set(raw);assert_eq!(sync_pty_provider(11,pty::PtyPair{master_object_id:37,slave_object_id:38}),Err(expected));
  assert_eq!(identify_pty_terminal(11,77),Err(expected));closed(&[]);
  assert_eq!(notify_terminal_signal(&state,11,pty::TerminalSignal{terminal_id:37,signal:SIGNAL_HUP}),Err(expected));
  reset();WIRE.set(raw);
  let result=open_pty_response(&manager,11,9, |_|Ok(()));
  assert_eq!(result.response.header.status,expected);assert!(result.handles.is_empty());
  closed(&[101,102]);assert_eq!(DISCARDS.get(),1);
  reset();NATIVE.set(raw);
  let result=RuntimeFilesystem.retain_object(AttachedObject{handle:44,rights:HANDLE_RIGHT_READ|HANDLE_RIGHT_DUPLICATE});
  assert_eq!(result.err(),Some(expected));closed(&[]);
 }
 for value in [1,7,i64::MAX]{
  reset();WIRE.set(value);assert_eq!(sync_pty_provider(11,pty::PtyPair{master_object_id:37,slave_object_id:38}),Err(-5));
 }
 for value in [-11,-22,i64::MIN,(Error::NotFound.into_raw()|0xffff) as i64]{
  reset();WIRE.set(value);
  let expected=if value<=i32::MIN as i64 || status::is_error(value as u64){-5}else{value as i32};
  assert_eq!(identify_pty_terminal(11,77),Err(expected));
 }
 reset();assert_eq!(identify_pty_terminal(11,77),Err(-5));
 WIRE.set(37);assert_eq!(identify_pty_terminal(11,77),Ok(37));
 RETURNED.set(99);assert_eq!(identify_pty_terminal(11,77),Err(-5));closed(&[99]);
 reset();LENGTH.set(7);WIRE.set(37);assert_eq!(identify_pty_terminal(11,77),Err(-5));
 assert_eq!(sync_pty_provider(11,pty::PtyPair{master_object_id:37,slave_object_id:38}),Err(-5));
 reset();POLICY.set(-1);
 assert_eq!(notify_terminal_signal(&state,11,pty::TerminalSignal{terminal_id:37,signal:SIGNAL_HUP}),Err(-1));
 assert_eq!(SENDS.get(),0);
 reset();let result=open_pty_response(&manager,11,9, |_|Ok(()));
 assert_eq!(result.response.header.status,0);
 assert_eq!(result.handles.iter().map(|object|object.handle).collect::<Vec<_>>(),[101,102]);
 assert_eq!(DISCARDS.get(),0);closed(&[]);
 reset();let result=open_pty_response(&manager,11,9, |_|Err(-13));
 assert_eq!(result.response.header.status,-13);assert!(result.handles.is_empty());
 assert_eq!(DISCARDS.get(),1);closed(&[101,102]);
 reset();let retained=RuntimeFilesystem.retain_object(AttachedObject{handle:44,rights:HANDLE_RIGHT_READ|HANDLE_RIGHT_DUPLICATE}).unwrap();
 assert_eq!((retained.handle,retained.rights),(55,HANDLE_RIGHT_READ|HANDLE_RIGHT_DUPLICATE));closed(&[]);
 assert_eq!(RuntimeFilesystem.retain_object(AttachedObject{handle:44,rights:HANDLE_RIGHT_READ}).err(),Some(-13));
 closed(&[]);
}
"#,
    );
    probe::run(&program);
}
