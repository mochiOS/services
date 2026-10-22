//! Execute the real operation owner, including explicit callback abandonment.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn streams_and_children_stay_owned_through_wait_failures_handoff_and_abandonment() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let mut program = format!(
        r#"
#![allow(dead_code)]
use std::ffi::c_int;
use std::sync::{{Mutex,atomic::{{AtomicU32,AtomicU64,Ordering}}}};
const EAGAIN:i32=11;const EINTR:i32=4;const EIO:i32=5;const EBADF:i32=9;const EOVERFLOW:i32=139;
const SPAWN_FAIL_EXIT_STATUS:i32=127;
const ABANDON_POINT:u32=0;
extern crate self as mochios_posix_client;
#[path={:?}]pub mod upcall_guard;
pub mod spawn{{#[derive(Clone,Copy,Debug,PartialEq)]pub enum ExecStatus{{Succeeded,Failed(i32)}}}}
pub mod newlib_errno{{pub const EINTR:i32=4;pub const EIO:i32=5;}}
#[path={:?}]mod child_startup;
mod syscall{{
 #[derive(Default)]pub struct StreamPair{{pub read:u32,pub write:u32}}
 #[derive(PartialEq)]pub enum SyscallNumber{{HandleRead,HandleWrite,DebugWrite,Sleep,ThreadYield}}
 pub fn raw_syscall0(_:SyscallNumber)->Result<u64,i32>{{Ok(0)}}
 pub fn raw_syscall1(_:SyscallNumber,_:u64)->Result<u64,i32>{{Ok(0)}}
 pub fn raw_syscall2(_:SyscallNumber,_:u64,_:u64)->Result<u64,i32>{{Ok(0)}}
 pub fn raw_syscall3(number:SyscallNumber,handle:u64,bytes:u64,length:u64)->Result<u64,i32>{{
  assert_eq!(crate::CONTROL.native.load(crate::Ordering::Relaxed),0);
  assert!(!crate::CONTROL.callback_resources.is_empty());
  if number==SyscallNumber::HandleRead{{
   assert_eq!(handle,33);assert!(length>=4);
   if crate::MODE.load(crate::Ordering::Relaxed)==10{{crate::escape_now()}}
   if crate::MODE.load(crate::Ordering::Relaxed)==9{{return Err(5)}}
   unsafe{{(bytes as *mut i32).write_unaligned(0)}};
   Ok(4)
  }}else{{assert_eq!(handle,44);
   if crate::MODE.load(crate::Ordering::Relaxed)==12{{crate::escape_now()}}
   Ok(length)
  }}
 }}
}}
fn syscall_errno(result:Result<u64,i32>)->Result<u64,i32>{{result}}
#[path={:?}]mod callback_resources;
#[path={:?}]mod io_resources;
#[path={:?}]mod fork_policy;
struct SyscallEndpointTransport;
struct PosixClient<T>(std::marker::PhantomData<T>);
static CLIENT:PosixClient<SyscallEndpointTransport>=PosixClient(std::marker::PhantomData);
enum PosixClientError<T>{{Transport(T),Remote(i32)}}
struct ObjectHandleAttachment<T>{{handle:T,rights:u32}}
mod posix_protocol{{pub const STATUS_ESRCH:i32=-3;}}
fn map_posix_client_error(error:PosixClientError<i32>)->i32{{
 match error{{PosixClientError::Transport(error)=>error,PosixClientError::Remote(error)=>-error}}
}}
impl PosixClient<SyscallEndpointTransport>{{
 fn prepare_fork(&self)->Result<u64,PosixClientError<i32>>{{Ok(77)}}
 fn commit_fork(&self,token:u64,child:ObjectHandleAttachment<u32>)->Result<(),PosixClientError<i32>>{{
  assert_eq!((token,child.handle),(77,42));
  if MODE.load(Ordering::Relaxed)==33{{escape_now()}}
  Ok(())
 }}
 fn cancel_fork(&self,token:u64)->Result<(),PosixClientError<i32>>{{
  assert_eq!(token,77);assert!(CONTROL.native.load(Ordering::Relaxed)>0);
  event("cancel".into());Ok(())
 }}
}}
struct ThreadControl{{callback_resources:callback_resources::Chain,active_signal_scope_id:AtomicU64,native:AtomicU32}}
static CONTROL:ThreadControl=ThreadControl{{callback_resources:callback_resources::Chain::new(),active_signal_scope_id:AtomicU64::new(0),native:AtomicU32::new(0)}};
static MODE:AtomicU32=AtomicU32::new(0);
static PAIRS:AtomicU32=AtomicU32::new(0);
static LIVE:Mutex<std::collections::BTreeSet<u32>>=Mutex::new(std::collections::BTreeSet::new());
static EVENTS:Mutex<Vec<String>>=Mutex::new(Vec::new());
fn register_current_thread()->Option<(u32,&'static ThreadControl)>{{Some((1,&CONTROL))}}
fn defer_native_delivery()->Option<upcall_guard::Guard<'static>>{{upcall_guard::Guard::enter(&CONTROL.native)}}
fn event(text:String){{EVENTS.lock().unwrap().push(text)}}
fn escape_now()->!{{
 let guard=defer_native_delivery();
 unsafe{{CONTROL.callback_resources.abandon_from(0)}};
 drop(guard);
 assert!(LIVE.lock().unwrap().is_empty(),"all stream references must already be reclaimed before leaving Rust frames");
 assert!(CONTROL.callback_resources.is_empty());
 assert_eq!(CONTROL.native.load(Ordering::Relaxed),0);
 if MODE.load(Ordering::Relaxed)!=12{{
  let registered=MODE.load(Ordering::Relaxed)!=30;
  assert_eq!(EVENTS.lock().unwrap().last(),Some(&format!("cleanup 42 {{registered}}")));
 }}
 let mode=MODE.load(Ordering::Relaxed);
 let cancelled=EVENTS.lock().unwrap().iter().filter(|event|event.as_str()=="cancel").count();
 assert_eq!(cancelled,usize::from(matches!(mode,30|31|33)));
 // Do not return through any abandoned Rust operation frame.
 std::process::exit(0)
}}
fn create_spawn_status_stream()->Result<syscall::StreamPair,i32>{{
 assert!(CONTROL.native.load(Ordering::Relaxed)>0);
 let second=PAIRS.fetch_add(1,Ordering::Relaxed)!=0;
 if !second{{event("create".into());}}
 if second&&MODE.load(Ordering::Relaxed)==8{{return Err(EIO)}}
 let result=if second{{Ok(syscall::StreamPair{{read:33,write:44}})}}else{{match MODE.load(Ordering::Relaxed){{
  1=>Err(EIO),2=>Ok(syscall::StreamPair{{read:0,write:22}}),
  3=>Ok(syscall::StreamPair{{read:11,write:0}}),4=>Ok(syscall::StreamPair{{read:11,write:11}}),
  _=>Ok(syscall::StreamPair{{read:11,write:22}})
 }}}};
 if let Ok(pair)=&result{{for handle in [pair.read,pair.write]{{if handle!=0{{LIVE.lock().unwrap().insert(handle);}}}}}}
 result
}}
fn close_object_handle(handle:u32){{assert!(CONTROL.native.load(Ordering::Relaxed)>0);
 if handle!=42{{assert!(LIVE.lock().unwrap().remove(&handle),"reference closed exactly once");}}
 if handle!=33&&handle!=44{{event(format!("close {{handle}}"));}}
}}
fn cleanup_failed_child(handle:u64,registered:bool){{assert!(CONTROL.native.load(Ordering::Relaxed)>0);event(format!("cleanup {{handle}} {{registered}}"));}}
fn read_spawn_status(handle:u32)->Result<mochios_posix_client::spawn::ExecStatus,i32>{{
 assert_eq!(handle,11);assert!(!CONTROL.callback_resources.is_empty());
 // Ordinary waiting must leave application callbacks enabled.
 assert_eq!(CONTROL.native.load(Ordering::Relaxed),0);
 event("wait".into());
 if MODE.load(Ordering::Relaxed)==11{{escape_now()}}
 match MODE.load(Ordering::Relaxed){{
  5=>Err(EIO),6=>Ok(mochios_posix_client::spawn::ExecStatus::Failed(13)),
  _=>Ok(mochios_posix_client::spawn::ExecStatus::Succeeded)
 }}
}}
mod spawn_output{{pub fn publish(pid:u64,handle:u32,output:*mut i32)->i32{{
 assert_eq!(pid,37);assert_eq!(handle,42);assert!(crate::CONTROL.native.load(crate::Ordering::Relaxed)>0);
 crate::event("publish".into());
 // The real nested publication owner is covered separately; model its two
 // terminal ownership outcomes without returning a second live reference.
 if crate::MODE.load(crate::Ordering::Relaxed)==7{{crate::cleanup_failed_child(42,true);14}}
 else{{unsafe{{output.write(37)}};crate::close_object_handle(42);0}}
}}}}
fn process_exit(_:i32)->!{{panic!("unexpected exit")}}
fn report_spawn_error(_:u32,_:i32)->!{{panic!("unexpected report")}}
struct FdObject;struct FdTable<T>(std::marker::PhantomData<T>);
fn clone_registered_process_owned(startup:&mut CloneStartup,policy:&mut Option<fork_policy::Preparation>,mut track:impl FnMut(Option<(u64,bool)>))->Result<(u64,FdTable<FdObject>,Option<u32>),i32>{{
 {{
  let guard=defer_native_delivery();
  *policy=Some(fork_policy::Preparation::new(&CLIENT)?);
  drop(guard);
 }}
 let preparation=policy.as_mut().unwrap();
 let mode=MODE.load(Ordering::Relaxed);
 if mode==20{{preparation.disarm_child();startup.ready();return Ok((0,FdTable(std::marker::PhantomData),None))}}
 if mode==21{{return Err(13)}}
 {{let guard=defer_native_delivery();track(Some((42,false)));drop(guard);}}
 if mode==30{{escape_now()}}
 if mode==22{{return Err(13)}}
 {{let guard=defer_native_delivery();track(Some((42,true)));drop(guard);}}
 if mode==31{{escape_now()}}
 if mode==23{{return Err(13)}}
 preparation.commit(ObjectHandleAttachment{{handle:42,rights:0}})?;
 startup.wait()?;
 let pid=match mode{{24=>u64::MAX,25=>0,_=>37}};
 let handle=if mode==26{{None}}else if mode==27{{Some(43)}}else{{Some(42)}};
 if mode==28{{let guard=defer_native_delivery();track(Some((42,false)));drop(guard);}}
 Ok((pid,FdTable(std::marker::PhantomData),handle))
}}
"#,
        root.join("user/crates/posix-client/src/upcall_guard.rs"),
        root.join("user/crates/newlib-runtime/src/child_startup.rs"),
        root.join("user/crates/newlib-runtime/src/callback_resources.rs"),
        root.join("user/crates/newlib-runtime/src/io_resources.rs"),
        root.join("user/crates/newlib-runtime/src/fork_policy.rs")
    );
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    program.push_str(probe::between(
        runtime,
        "struct CloneStartup {",
        "fn create_spawn_status_stream()",
    ));
    program.push_str("mod actual{");
    program.push_str(
        include_str!("../../../user/crates/newlib-runtime/src/spawn_resources.rs")
            .trim_start_matches(
                "//! Operation-local ownership through child creation and exec-status waiting.",
            ),
    );
    program.push_str(r#"
pub fn abandon(registered:bool){
 let guard=defer_native_delivery();
 let mut scope=core::pin::pin!(callback_resources::Scope::new(
  &CONTROL.callback_resources,0,Resources::new().unwrap()));
 unsafe{scope.as_mut().activate()};
 scope.as_mut().resource_mut().unwrap().track_child(Some((42,registered)));
 drop(guard);
 // No borrowed resource or operation frame survives this simulated escape.
 let guard=defer_native_delivery();
 unsafe{CONTROL.callback_resources.abandon_from(0)};
 assert!(scope.as_ref().get_ref().resource().is_none());
 drop(guard);
}
pub fn child_ready(){
 with(|resources|{
  resources.startup.as_mut().unwrap().ready();
  resources.child_writer().unwrap();
  0
 });
}
}
fn reset(mode:u32){assert!(LIVE.lock().unwrap().is_empty());PAIRS.store(0,Ordering::Relaxed);assert!(CONTROL.callback_resources.is_empty());assert_eq!(CONTROL.native.load(Ordering::Relaxed),0);MODE.store(mode,Ordering::Relaxed);EVENTS.lock().unwrap().clear();}
fn check(expected:&[&str]){assert!(LIVE.lock().unwrap().is_empty());assert!(CONTROL.callback_resources.is_empty());assert_eq!(CONTROL.native.load(Ordering::Relaxed),0);let actual=EVENTS.lock().unwrap();assert_eq!(actual.iter().map(String::as_str).collect::<Vec<_>>(),expected);}
fn main(){
 for mode in 1..=4{
  reset(mode);assert_eq!(actual::with(|_|panic!("invalid pair must not execute")),EIO);
  match mode{1=>check(&["create"]),2=>check(&["create","close 22"]),_=>check(&["create","close 11"])}
 }
 reset(8);assert_eq!(actual::with(|_|panic!("ACK creation failed")),EIO);
 check(&["create","close 11","close 22"]);
 reset(0);assert_eq!(actual::with(|_|EIO),EIO);check(&["create","close 11","close 22"]);
 for registered in [false,true]{
  reset(0);assert_eq!(actual::with(|r|{let guard=defer_native_delivery();r.track_child(Some((42,registered)));drop(guard);EIO}),EIO);
  if registered{check(&["create","close 11","close 22","cleanup 42 true"])}else{check(&["create","close 11","close 22","cleanup 42 false"])}
  reset(0);actual::abandon(registered);
  if registered{check(&["create","close 11","close 22","cleanup 42 true"])}else{check(&["create","close 11","close 22","cleanup 42 false"])}
 }
 // Internal clone cleanup disarms the operation owner exactly once.
 reset(0);actual::with(|r|{
  let guard=defer_native_delivery();r.track_child(Some((42,true)));
  cleanup_failed_child(42,true);r.track_child(None);drop(guard);EIO
 });check(&["create","cleanup 42 true","close 11","close 22"]);
 for mode in [5,6]{
  reset(mode);let result=actual::with(|r|{
   let guard=defer_native_delivery();r.track_child(Some((42,true)));drop(guard);
   match r.wait(){Err(error)=>error,Ok(mochios_posix_client::spawn::ExecStatus::Failed(error))=>error,_=>panic!("wrong outcome")}
  });assert_eq!(result,if mode==5{5}else{13});
  check(&["create","close 22","wait","close 11","cleanup 42 true"]);
 }
 for mode in [0,7]{
  reset(mode);let mut pid=-37;let result=actual::with(|r|{
   let guard=defer_native_delivery();r.track_child(Some((42,true)));drop(guard);
   assert_eq!(r.wait(),Ok(mochios_posix_client::spawn::ExecStatus::Succeeded));r.publish(37,&mut pid)
  });
  if mode==0{assert_eq!(result,0);assert_eq!(pid,37);check(&["create","close 22","wait","close 11","publish","close 42"]);}
  else{assert_eq!(result,14);assert_eq!(pid,-37);check(&["create","close 22","wait","close 11","publish","cleanup 42 true"]);}
 }
 // Child continuation owns only its copied writer, never the parent's child reference.
 reset(0);assert_eq!(actual::with(|r|{r.child_writer().unwrap();0}),0);
 check(&["create","close 11","close 22"]);
 reset(0);actual::child_ready();check(&["create","close 11","close 22"]);
 for mode in [0,9]{
  reset(mode);let mut pid=-37;let result=actual::with(|resources|{
   match resources.clone_registered(){
    Err(error)=>error,
    Ok((id,_,_))=>{assert_eq!(resources.wait(),Ok(mochios_posix_client::spawn::ExecStatus::Succeeded));resources.publish(id,&mut pid)}
   }
  });
  if mode==0{assert_eq!(result,0);assert_eq!(pid,37);check(&["create","close 22","wait","close 11","publish","close 42"]);}
  else{assert_eq!(result,5);assert_eq!(pid,-37);check(&["create","close 11","close 22","cleanup 42 true"]);}
 }
 // fork uses the same owner without creating an exec-status stream. The
 // factory's second pair denotes startup ACKs, so only 33/44 may be issued.
 for mode in [0,8,9,20,21,22,23,24,25,26,27,28]{
  reset(mode);PAIRS.store(1,Ordering::Relaxed);
  let result=actual::fork();
  assert_eq!(PAIRS.load(Ordering::Relaxed),2);
  match mode{
   0=>{assert_eq!(result,Ok(37));check(&["close 42"]);},
   20=>{assert_eq!(result,Ok(0));check(&[]);},
   8=>{assert_eq!(result,Err(EIO));check(&[]);},
   21=>{assert_eq!(result,Err(13));check(&["cancel"]);},
   22=>{assert_eq!(result,Err(13));check(&["cancel","cleanup 42 false"]);},
   23=>{assert_eq!(result,Err(13));check(&["cancel","cleanup 42 true"]);},
   9=>{assert_eq!(result,Err(EIO));check(&["cleanup 42 true"]);},
   24=>{assert_eq!(result,Err(EOVERFLOW));check(&["cleanup 42 true"]);},
   28=>{assert_eq!(result,Err(EIO));check(&["cleanup 42 false"]);},
   _=>{assert_eq!(result,Err(EIO));check(&["cleanup 42 true"]);},
  }
 }
 if ABANDON_POINT>=30{
  reset(if ABANDON_POINT==32{10}else{ABANDON_POINT});
  PAIRS.store(1,Ordering::Relaxed);
  actual::fork().unwrap();
  panic!("abandoned fork must never return")
 }
 if ABANDON_POINT!=0{
  reset(ABANDON_POINT);
  if ABANDON_POINT==12{actual::child_ready();}
  else{actual::with(|resources|{
   resources.clone_registered().unwrap();
   resources.wait().unwrap();
   panic!("callback escape was not exercised")
  });}
  panic!("an abandoned operation must never return")
 }
}
"#);
    probe::run(&program);
    for point in [10, 11, 12, 30, 31, 32, 33] {
        let escaped = program.replace(
            "const ABANDON_POINT:u32=0;",
            &format!("const ABANDON_POINT:u32={point};"),
        );
        probe::run(&escaped);
    }
}

#[test]
fn actual_clone_handoff_publishes_ownership_before_delivery_reopens() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let clone = probe::between(
        source,
        "fn clone_registered_process_owned(",
        "struct CloneStartup",
    );
    let guard = clone
        .find("let creation_delivery = defer_native_delivery()")
        .unwrap();
    let create = clone.find("syscall::SyscallNumber::ProcessCreate").unwrap();
    let adopt = clone.find("track_child(Some((handle, false)))").unwrap();
    let reopen = clone.rfind("drop(creation_delivery)").unwrap();
    assert!(guard < create && create < adopt && adopt < reopen);
    assert!(guard < clone.find("drop(allocator_guard)").unwrap());
    assert!(clone.contains("if image == 0 {\n        drop(creation_delivery);"));
    let prepare = clone
        .find("policy.insert(fork_policy::Preparation::new(client)?)")
        .unwrap();
    assert!(clone.find("atfork::freeze_allocator()").unwrap() < prepare);
    assert!(prepare < clone.find("snapshot::capture_native(").unwrap());
    assert!(reopen < clone.find("preparation.commit(").unwrap());
    assert!(reopen < clone.find("startup.wait()").unwrap());
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let mut program = format!(
        r#"
use std::sync::atomic::{{AtomicU32,Ordering}};
use std::ffi::c_int;
#[path={:?}]mod upcall_guard;
const EOVERFLOW:i32=139;
static DEPTH:AtomicU32=AtomicU32::new(0);
thread_local!{{static EVENTS:std::cell::RefCell<Vec<String>>=const{{std::cell::RefCell::new(Vec::new())}};}}
fn event(value:String){{EVENTS.with_borrow_mut(|v|v.push(value))}}
fn defer_native_delivery()->Option<upcall_guard::Guard<'static>>{{upcall_guard::Guard::enter(&DEPTH)}}
fn close_object_handle(handle:u32){{assert_eq!(DEPTH.load(Ordering::Relaxed),1);event(format!("close {{handle}}"));}}
fn cleanup_failed_child(handle:u64,registered:bool){{assert_eq!(DEPTH.load(Ordering::Relaxed),1);event(format!("cleanup {{handle}} {{registered}}"));}}
struct Capture;impl Drop for Capture{{fn drop(&mut self){{assert_eq!(DEPTH.load(Ordering::Relaxed),1);event("capture".into());}}}}
fn handoff(created:Result<u64,c_int>,mut track_child:impl FnMut(Option<(u64,bool)>))->Result<u32,c_int>{{
 let creation_delivery=defer_native_delivery();let image=99u32;let capture=Capture;
"#,
        root.join("user/crates/posix-client/src/upcall_guard.rs")
    );
    program.push_str(probe::between(
        clone,
        "    close_object_handle(image);",
        "    let mut registration_attempted = false;",
    ));
    program.push_str(r#"
 Ok(handle)
}
fn main(){
 for created in [Ok(42),Ok(u32::MAX as u64),Ok(u32::MAX as u64+1),Err(5),Err(13)]{
  EVENTS.with_borrow_mut(Vec::clear);
  let result=handoff(created,|owner|{
   assert_eq!(DEPTH.load(Ordering::Relaxed),1);
   event(format!("owner {owner:?}"));
  });
  assert_eq!(DEPTH.load(Ordering::Relaxed),0);
  let expected=match created{
   Ok(handle) if handle<=u32::MAX as u64=>{assert_eq!(result,Ok(handle as u32));vec!["close 99".into(),"capture".into(),format!("owner Some(({handle}, false))")]},
   Ok(handle)=>{assert_eq!(result,Err(EOVERFLOW));vec!["close 99".into(),"capture".into(),format!("owner Some(({handle}, false))"),format!("cleanup {handle} false"),"owner None".into()]},
   Err(error)=>{assert_eq!(result,Err(error));vec!["close 99".into(),"capture".into()]},
  };
  EVENTS.with_borrow(|events|assert_eq!(*events,expected));
 }
}
"#);
    probe::run(&program);
}
