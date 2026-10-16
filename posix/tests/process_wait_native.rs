//! Execute production wait admission/cleanup, exit-waiter storage and the
//! retained lifecycle object. Scheduler/timer callbacks are controlled host
//! boundaries, not an end-to-end context-switch test.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn native_wait_pins_target_and_releases_registrations_on_every_return() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let process = include_str!("../../../core/src/task/process.rs");
    let handle = include_str!("../../../core/src/syscall/handle.rs");
    let mut program = String::from(
        r#"
#![allow(dead_code,unused_attributes)]
extern crate self as mnu_abi;
use std::{cell::{Cell,RefCell},sync::{Arc,atomic::{AtomicBool,AtomicU8,AtomicU64,Ordering}}};
static FAIL_NEXT:AtomicBool=AtomicBool::new(false);
struct Allocator;
unsafe impl std::alloc::GlobalAlloc for Allocator{
    unsafe fn alloc(&self,layout:std::alloc::Layout)->*mut u8{
        if FAIL_NEXT.swap(false,Ordering::Relaxed){return std::ptr::null_mut();}
        unsafe{std::alloc::System.alloc(layout)}
    }
    unsafe fn realloc(&self,p:*mut u8,layout:std::alloc::Layout,size:usize)->*mut u8{
        if FAIL_NEXT.swap(false,Ordering::Relaxed){return std::ptr::null_mut();}
        unsafe{std::alloc::System.realloc(p,layout,size)}
    }
    unsafe fn dealloc(&self,p:*mut u8,layout:std::alloc::Layout){unsafe{std::alloc::System.dealloc(p,layout)}}
}
#[global_allocator]static ALLOCATOR:Allocator=Allocator;
thread_local!{
    static TARGET:RefCell<Arc<task::process::ProcessObject>>=RefCell::new(task::process::new(1));
    static SLOT:RefCell<Arc<task::process::ProcessObject>>=RefCell::new(TARGET.with_borrow(Arc::clone));
    static CURRENT:Cell<bool>=const{Cell::new(true)};
    static LOOKUPS:Cell<usize>=const{Cell::new(0)};
    static NOW:Cell<u64>=const{Cell::new(0)};
    static ARMED:Cell<bool>=const{Cell::new(false)};
    static ARM_OK:Cell<bool>=const{Cell::new(true)};
    static UPCALL:Cell<bool>=const{Cell::new(false)};
    static ACTION:Cell<u8>=const{Cell::new(0)};
    static SLEEPS:Cell<usize>=const{Cell::new(0)};
    static COPY_ERROR:Cell<Option<status::Error>>=const{Cell::new(None)};
    static LOOKUP_ERROR:Cell<Option<status::Error>>=const{Cell::new(None)};
    static EXIT_ON_CLOCK:Cell<bool>=const{Cell::new(false)};
}
struct SpinLock<T>(std::sync::Mutex<T>);
impl<T> SpinLock<T>{const fn new(value:T)->Self{Self(std::sync::Mutex::new(value))}fn lock(&self)->std::sync::MutexGuard<'_,T>{self.0.lock().unwrap()}}
"#,
    );
    program.push_str(&format!(
        "#[path={:?}]mod abi;pub use abi::*;\n",
        root.join("core/crates/abi/src/lib.rs")
    ));
    program.push_str("mod task {pub type ThreadId=u64;#[derive(Clone,Copy,Debug,PartialEq,Eq)]pub struct ProcessId(pub u64);impl ProcessId{pub fn as_u64(self)->u64{self.0}}pub struct ThreadQueue;impl ThreadQueue{pub const MAX_THREADS:usize=4;}\npub mod process {use crate::{mnu_abi,SpinLock};use super::ProcessId;use std::{vec::Vec,sync::{Arc,atomic::{AtomicU8,AtomicU64,Ordering}}};\n");
    program.push_str(probe::between(
        process,
        "#[derive(Debug)]\npub struct ProcessObject",
        "#[derive(Clone, Copy, Debug, PartialEq, Eq)]",
    ));
    program.push_str(probe::between(
        process,
        "const MAX_PROCESS_EXIT_WAITERS:",
        "static DEFERRED_PROCESS_RECLAIMS:",
    ));
    program.push_str(probe::between(
        process,
        "pub fn register_process_exit_waiter(",
        "/// プロセステーブルにプロセスを追加",
    ));
    program.push_str(r#"
pub fn new(id:u64)->Arc<ProcessObject>{Arc::new(ProcessObject::new(ProcessId(id)))}
pub fn exit(object:&ProcessObject){object.mark_exited(u64::MAX);wake_process_exit_waiters(object.id());}
pub fn count()->usize{PROCESS_EXIT_WAITERS.lock().iter().flatten().map(|waiter|waiter.processes.len()).sum()}
pub fn reset(){*PROCESS_EXIT_WAITERS.lock()=[const{None};MAX_PROCESS_EXIT_WAITERS];}
}
pub use process::{register_process_exit_waiter,remove_process_exit_waiter};
pub fn current_thread_id()->Option<ThreadId>{crate::CURRENT.get().then_some(7)}
pub fn wake_registered_waiter(_:ThreadId){}
pub fn sleep_thread_unless_woken(id:ThreadId)->bool{
    assert_eq!(id,7);assert_eq!(process::count(),1);crate::SLEEPS.set(crate::SLEEPS.get()+1);
    match crate::ACTION.replace(0){
        1=>crate::TARGET.with_borrow(|target|process::exit(target)),
        2=>crate::NOW.set(100),
        3=>crate::UPCALL.set(true),
        4=>{crate::SLOT.set(process::new(99));crate::TARGET.with_borrow(|target|process::exit(target));},
        _=>panic!("unexpected unbounded wait"),
    }true
}
pub fn yield_now(){}
}
struct HandleRights;impl HandleRights{const WAIT:Self=Self;}
enum KernelObject{Process(Arc<task::process::ProcessObject>),Other}
fn object_native(raw:u64,_:HandleRights)->Result<KernelObject,status::Error>{
    LOOKUPS.set(LOOKUPS.get()+1);if let Some(error)=LOOKUP_ERROR.get(){return Err(error);}
    Ok(if raw==1{KernelObject::Process(SLOT.with_borrow(Arc::clone))}else{KernelObject::Other})
}
mod syscall{
    pub mod time{
        pub fn disarm_thread_deadline(_:u64){crate::ARMED.set(false)}
        pub fn monotonic_deadline_tick(value:u64)->u64{value}
        pub fn monotonic_nanoseconds()->u64{
            if crate::EXIT_ON_CLOCK.replace(false){crate::TARGET.with_borrow(|target|crate::task::process::exit(target));}
            crate::NOW.get()
        }
        pub fn arm_thread_deadline(_:u64,_:u64)->bool{crate::ARMED.set(true);crate::ARM_OK.get()}
    }
    pub mod upcall{pub fn current_has_deliverable_upcall()->bool{crate::UPCALL.get()}}
    pub fn copy_to_user_native(pointer:u64,bytes:&[u8])->Result<(),crate::status::Error>{
        assert_eq!(crate::task::process::count(),0);assert!(!crate::ARMED.get());
        if let Some(error)=crate::COPY_ERROR.get(){return Err(error);}
        if pointer<4096{return Err(crate::status::Error::InvalidAddress);}
        unsafe{std::ptr::copy_nonoverlapping(bytes.as_ptr(),pointer as *mut u8,bytes.len());}Ok(())
    }
}
mod upcall{pub use crate::syscall::upcall::*;}
mod actual{use crate::{mnu_abi,object_native,KernelObject,HandleRights,SUCCESS};
"#);
    program.push_str(probe::between(
        handle,
        "fn process_status_of(",
        "pub fn process_status(",
    ));
    program.push_str(probe::between(
        handle,
        "pub fn process_wait(",
        "#[derive(Clone)]\nenum WaitTarget",
    ));
    program.push_str(r#"
}
use actual::process_wait;
fn reset(){
    task::process::reset();TARGET.set(task::process::new(1));SLOT.set(TARGET.with_borrow(Arc::clone));
    CURRENT.set(true);LOOKUPS.set(0);NOW.set(0);ARMED.set(false);ARM_OK.set(true);UPCALL.set(false);
    ACTION.set(0);SLEEPS.set(0);COPY_ERROR.set(None);LOOKUP_ERROR.set(None);EXIT_ON_CLOCK.set(false);
}
fn check(raw:u64,deadline:u64,output:u64,expected:u64){
    assert_eq!(process_wait(raw,deadline,output),expected);assert!(!ARMED.get());assert_eq!(task::process::count(),0);
    TARGET.with_borrow(|target|{
        let owners=SLOT.with_borrow(|slot|if Arc::ptr_eq(slot,target){2}else{1});
        assert_eq!(Arc::strong_count(target),owners,"wait leaked its retained target");
    });
}
fn main(){
    use status::Error;
    let mut status=ProcessStatus::default();let output=&mut status as *mut _ as u64;
    for error in [Error::InvalidArgument,Error::AccessDenied,Error::NotReady]{
        reset();LOOKUP_ERROR.set(Some(error));check(1,0,output,error.into_raw());
    }
    reset();check(2,0,output,Error::InvalidArgument.into_raw());
    reset();CURRENT.set(false);check(1,0,output,Error::NotReady.into_raw());
    reset();check(1,0,output,Error::NotReady.into_raw());assert_eq!(SLEEPS.get(),0);
    reset();NOW.set(100);check(1,10,output,Error::NotReady.into_raw());
    reset();UPCALL.set(true);check(1,u64::MAX,output,Error::NotReady.into_raw());
    reset();ARM_OK.set(false);check(1,10,output,Error::ResourceUnavailable.into_raw());
    reset();FAIL_NEXT.store(true,Ordering::Relaxed);check(1,u64::MAX,output,Error::ResourceUnavailable.into_raw());assert!(!FAIL_NEXT.load(Ordering::Relaxed));
    for action in [1,2,3,4]{
        reset();ACTION.set(action);
        check(1,if action==2{10}else{u64::MAX},output,if action==2||action==3{Error::NotReady.into_raw()}else{0});
        assert_eq!(LOOKUPS.get(),1);assert_eq!(SLEEPS.get(),1);
        if action==1||action==4{assert_eq!((status.process_id,status.state,status.exit_code),(1,PROCESS_STATE_EXITED,u64::MAX));}
    }
    reset();EXIT_ON_CLOCK.set(true);check(1,10,output,0);assert_eq!(SLEEPS.get(),0);
    for error in [Error::InvalidAddress,Error::ResourceUnavailable,Error::BackingFailure]{
        reset();TARGET.with_borrow(|target|task::process::exit(target));COPY_ERROR.set(Some(error));check(1,0,output,error.into_raw());
    }
    reset();TARGET.with_borrow(|target|task::process::exit(target));check(1,0,0,Error::InvalidAddress.into_raw());
    // Real registration storage rejects growth without changing an existing
    // subscription; duplicating the same subscription must not allocate.
    reset();assert!(task::register_process_exit_waiter(1,task::ProcessId(1)));
    FAIL_NEXT.store(true,Ordering::Relaxed);assert!(task::register_process_exit_waiter(1,task::ProcessId(1)));
    assert!(FAIL_NEXT.swap(false,Ordering::Relaxed));
    FAIL_NEXT.store(true,Ordering::Relaxed);assert!(!task::register_process_exit_waiter(1,task::ProcessId(2)));
    assert!(!FAIL_NEXT.load(Ordering::Relaxed));assert_eq!(task::process::count(),1);
    for id in 2..=4{assert!(task::register_process_exit_waiter(id,task::ProcessId(id)));}
    assert_eq!(process_wait(1,u64::MAX,output),Error::ResourceUnavailable.into_raw());
    assert_eq!(task::process::count(),4);assert!(!ARMED.get());task::process::reset();
}
"#);
    probe::run(&program);
}
