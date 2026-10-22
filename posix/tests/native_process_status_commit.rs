//! Execute native status/commit code across an externally visible Handle release.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn released_handles_cannot_expose_an_uncommitted_image_revision() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let process = include_str!("../../../core/src/task/process.rs");
    let handles = include_str!("../../../core/src/syscall/handle.rs");
    let exec = include_str!("../../../core/src/syscall/exec.rs");
    let mut program = format!(
        r#"
#![allow(dead_code)]
extern crate self as mnu_abi;
#[path={:?}]mod abi;pub use abi::*;
use std::sync::{{Arc,Mutex,OnceLock,mpsc,atomic::{{AtomicBool,AtomicUsize,Ordering}}}};
#[derive(Debug,Clone,Copy)]pub struct ProcessId(u64);impl ProcessId{{pub fn as_u64(self)->u64{{self.0}}}}
static LOCK:Mutex<()>=Mutex::new(());
static PRESENT:AtomicBool=AtomicBool::new(true);
static ALLOWED:AtomicBool=AtomicBool::new(true);
static QUERIES:AtomicUsize=AtomicUsize::new(0);
static CLOSED:OnceLock<mpsc::Sender<()>>=OnceLock::new();
static ATTEMPT:OnceLock<mpsc::Sender<()>>=OnceLock::new();
static REQUEST:OnceLock<Mutex<mpsc::Receiver<()>>>=OnceLock::new();
mod task {{
 pub use crate::ProcessId;
 pub mod process {{
  use crate::{{mnu_abi,ProcessId}};
  use std::sync::{{Arc,atomic::{{AtomicU8,AtomicU64,Ordering}}}};
"#,
        root.join("core/crates/abi/src/lib.rs")
    );
    program.push_str(probe::between(
        process,
        "#[derive(Debug)]\npub struct ProcessObject",
        "#[derive(Clone, Copy, Debug, PartialEq, Eq)]",
    ));
    program.push_str(r#"
pub fn object()->Arc<ProcessObject>{
 static OBJECT:std::sync::OnceLock<Arc<ProcessObject>>=std::sync::OnceLock::new();
 OBJECT.get_or_init(||Arc::new(ProcessObject::new(ProcessId(17)))).clone()
}
pub fn exit(){object().mark_exited(37);}
 }
 pub use crate::Process;
 struct Table; static PROCESS_TABLE:Table=Table;
 struct TableGuard(std::sync::MutexGuard<'static,()>);
 impl Table {
  fn lock(&self)->TableGuard {
   crate::QUERIES.fetch_add(1,crate::Ordering::Relaxed);
   crate::ATTEMPT.get().unwrap().send(()).unwrap();
   TableGuard(crate::LOCK.lock().unwrap())
  }
 }
 impl TableGuard {
  fn get(&self,id:ProcessId)->Option<&'static Process>{
   assert_eq!(id.as_u64(),17);
   static RECORD:std::sync::OnceLock<Process>=std::sync::OnceLock::new();
   crate::PRESENT.load(crate::Ordering::Relaxed).then(||RECORD.get_or_init(||Process{object:process::object()}))
  }
 }
"#);
    program.push_str(probe::between(
        process,
        "pub fn with_process<F, R>(",
        "/// プロセスIDでプロセス情報を可変操作",
    ));
    program.push_str(r#"
}
pub struct Process{object:Arc<task::process::ProcessObject>}
impl Process {
 fn process_object(&self)->Arc<task::process::ProcessObject>{self.object.clone()}
 fn retain_launch_context_handles_for_exec(&mut self){
  CLOSED.get().unwrap().send(()).unwrap();
  // Hold the actual commit lock until a native status reader has reached it.
  REQUEST.get().unwrap().lock().unwrap().recv_timeout(std::time::Duration::from_secs(2)).unwrap();
 }
}
#[derive(Debug,PartialEq)]struct HandleRights;impl HandleRights{const WAIT:Self=Self;}
enum KernelObject{Process(Arc<task::process::ProcessObject>),Other}
fn object_native(raw:u64,right:HandleRights)->Result<KernelObject,status::Error>{
 assert_eq!(right,HandleRights::WAIT);
 if !ALLOWED.load(Ordering::Relaxed){return Err(status::Error::AccessDenied)}
 match raw{42=>Ok(KernelObject::Process(task::process::object())),43=>Ok(KernelObject::Other),_=>Err(status::Error::InvalidArgument)}
}
"#);
    program.push_str(probe::between(
        handles,
        "fn process_status_for(",
        "fn write_process_status(",
    ));
    program.push_str("fn commit(process:&mut Process,next_image_revision:u64){\n");
    program.push_str(probe::between(
        exec,
        "        process.retain_launch_context_handles_for_exec();",
        "        previous\n",
    ));
    program.push_str(r#"
}
fn main(){
 let (closed_tx,closed_rx)=mpsc::channel();CLOSED.set(closed_tx).unwrap();
 let (query_tx,query_rx)=mpsc::channel();ATTEMPT.set(query_tx).unwrap();REQUEST.set(Mutex::new(query_rx)).unwrap();
 let writer=std::thread::spawn(||{
  let _commit=LOCK.lock().unwrap();
  let mut process=Process{object:task::process::object()};
  commit(&mut process,1);
 });
 closed_rx.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
 let observed=process_status_for(42).unwrap();
 writer.join().unwrap();
 assert_eq!(observed.process_id,17);assert_eq!(observed.image_revision,1);
 assert_eq!(observed.state,PROCESS_STATE_RUNNING);assert_eq!(observed.reserved,0);
 assert_eq!(QUERIES.load(Ordering::Relaxed),1);
 // Native capability/type rejection never enters the process table at all.
 ALLOWED.store(false,Ordering::Relaxed);
 assert_eq!(process_status_for(42),Err(status::Error::AccessDenied.into_raw()));
 ALLOWED.store(true,Ordering::Relaxed);
 for handle in [0,43,u64::MAX]{assert_eq!(process_status_for(handle),Err(status::Error::InvalidArgument.into_raw()));}
 assert_eq!(QUERIES.load(Ordering::Relaxed),1);
 // Removal does not turn a retained WAIT reference into a PID lookup failure.
 task::process::exit();PRESENT.store(false,Ordering::Relaxed);
 let observed=process_status_for(42).unwrap();
 assert_eq!(observed.state,PROCESS_STATE_EXITED);assert_eq!(observed.exit_code,37);
 assert_eq!(observed.image_revision,1);assert_eq!(observed.process_id,17);
}
"#);
    probe::run(&program);
}
