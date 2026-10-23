//! Execute the actual child TCB reclamation code. Native references and VM
//! disposal are recorded, never replaced with host mmap/free operations.
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn live_sibling_private_memory_is_not_walked_or_unmapped_but_child_references_are_retired() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let implementation = probe::between(
        runtime,
        "enum ThreadReclamation {",
        "fn allocate_thread_reent(",
    );
    let mut fields = std::collections::BTreeSet::new();
    for suffix in implementation.split("control.").skip(1) {
        let name: String = suffix
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if !name.is_empty() {
            fields.insert(name);
        }
    }
    for name in [
        "callback_resources",
        "stdio_scope",
        "specific_values",
        "specific_generations",
    ] {
        fields.remove(name);
    }
    fields.insert("native_handle".to_owned());
    fields.insert("cancel_state".to_owned());
    fields.insert("joinability".to_owned());
    fields.insert("specific_destructors_running".to_owned());
    let declarations = fields
        .iter()
        .map(|name| format!("{name}:AtomicUsize,"))
        .collect::<String>();
    let initializers = fields
        .iter()
        .map(|name| format!("{name}:AtomicUsize::new(0),"))
        .collect::<String>();
    let program = format!(
        r#"
#![allow(dead_code,non_camel_case_types)]
use std::sync::atomic::{{AtomicUsize,AtomicBool,Ordering}};
use std::ffi::c_void;
const THREAD_FREE:usize=0;const THREAD_STARTING:usize=1;const THREAD_RUNNING:usize=2;
const THREAD_EXITED:usize=3;const THREAD_REAPING:usize=4;
const THREAD_JOINABLE:usize=0;const PTHREAD_CANCEL_DISABLE:usize=1;
static EMPTY:AtomicBool=AtomicBool::new(true);
static ALLOW_CACHE:AtomicBool=AtomicBool::new(false);
static UNMAPS:std::sync::Mutex<Vec<(u64,u64)>>=std::sync::Mutex::new(Vec::new());
static CALLBACKS:std::sync::Mutex<Vec<&str>>=std::sync::Mutex::new(Vec::new());
static CLOSED:std::sync::Mutex<Vec<usize>>=std::sync::Mutex::new(Vec::new());
struct Chain;impl Chain{{fn reset_empty(&self)->bool{{EMPTY.load(Ordering::Acquire)}}unsafe fn discard_fork_opaque(&self)->bool{{EMPTY.load(Ordering::Acquire)}}}}
struct Stdio;impl Stdio{{fn reset(&self){{}}}}
struct ThreadControl{{{declarations}callback_resources:Chain,stdio_scope:Stdio,specific_values:[AtomicUsize;2],specific_generations:[AtomicUsize;2]}}
impl ThreadControl{{fn new(state:usize)->Self{{
 let control=Self{{{initializers}callback_resources:Chain,stdio_scope:Stdio,specific_values:[const{{AtomicUsize::new(17)}};2],specific_generations:[const{{AtomicUsize::new(3)}};2]}};
 control.state.store(state,Ordering::Release);
 control.native_handle.store(51,Ordering::Release);control.native_id.store(701,Ordering::Release);
 control.newlib_lock_identity.store(701,Ordering::Release);
 control.signal_upcall_stack.store(0x4000,Ordering::Release);control.signal_upcall_stack_size.store(4096,Ordering::Release);
 control.reent.store(0x6000,Ordering::Release);control.reent_mapping_size.store(4096,Ordering::Release);
 control.stack_base.store(0x8000,Ordering::Release);control.stack_size.store(8192,Ordering::Release);control.owns_stack.store(1,Ordering::Release);
 control
}}}}
fn process_exit(code:i32)->!{{panic!("child startup rejected {{code}}")}}
fn current_thread_control()->Option<((),&'static ThreadControl)>{{None}}
fn native_mutex_wake_all(word:&AtomicUsize){{assert_eq!(word.load(Ordering::Acquire),THREAD_FREE);}}
mod thread_lifecycle{{pub fn mutate(){{}}}}
mod thread_reference{{use super::*;pub fn replace(control:&ThreadControl,new:u32){{
 assert_eq!(new,0);let handle=control.native_handle.swap(0,Ordering::AcqRel);if handle!=0{{CLOSED.lock().unwrap().push(handle);}}
}}}}
mod syscall{{pub enum SyscallNumber{{MemoryUnmap}}pub fn raw_syscall2(_:SyscallNumber,address:u64,length:u64)->u64{{super::UNMAPS.lock().unwrap().push((address,length));0}}}}
unsafe fn __mochios_reent_destroy(pointer:*mut c_void){{assert!(ALLOW_CACHE.load(Ordering::Acquire));assert_eq!(pointer as usize,0x6000);CALLBACKS.lock().unwrap().push("destroy");}}
unsafe fn __mochios_reent_discard(pointer:*mut c_void){{assert!(ALLOW_CACHE.load(Ordering::Acquire));assert_eq!(pointer as usize,0x6000);CALLBACKS.lock().unwrap().push("discard");}}
{implementation}
fn reset(){{UNMAPS.lock().unwrap().clear();CALLBACKS.lock().unwrap().clear();CLOSED.lock().unwrap().clear();EMPTY.store(true,Ordering::Release);}}
fn retired(control:&ThreadControl){{
 assert_eq!(control.state.load(Ordering::Acquire),THREAD_FREE);
 assert_eq!(control.native_handle.load(Ordering::Acquire),0);
 assert_eq!(control.native_id.load(Ordering::Acquire),0);
 assert_eq!(control.reent.load(Ordering::Acquire),0);
 assert_eq!(control.stack_base.load(Ordering::Acquire),0);
 assert_eq!(control.owns_stack.load(Ordering::Acquire),0);
 assert_eq!(*CLOSED.lock().unwrap(),[51]);
 for value in &control.specific_values{{assert_eq!(value.load(Ordering::Acquire),0);}}
}}
fn main(){{
 reset();ALLOW_CACHE.store(false,Ordering::Release);
 let live=ThreadControl::new(THREAD_RUNNING);
 live.reent.store(1,Ordering::Release); // must remain opaque, even if not a valid pointer
 discard_fork_thread_control(&live);retired(&live);
 assert!(UNMAPS.lock().unwrap().is_empty());assert!(CALLBACKS.lock().unwrap().is_empty());
 for state in [THREAD_EXITED,THREAD_REAPING]{{
  reset();ALLOW_CACHE.store(true,Ordering::Release);
  let exited=ThreadControl::new(state);discard_fork_thread_control(&exited);retired(&exited);
  assert_eq!(*CALLBACKS.lock().unwrap(),["discard"]);
  assert_eq!(*UNMAPS.lock().unwrap(),[(0x4000,4096),(0x6000,4096),(0x8000,8192)]);
 }}
 reset();let exited=ThreadControl::new(THREAD_EXITED);release_thread_control(&exited);retired(&exited);
 assert_eq!(*CALLBACKS.lock().unwrap(),["destroy"]);
 reset();EMPTY.store(false,Ordering::Release);let live=ThreadControl::new(THREAD_RUNNING);
 assert!(std::panic::catch_unwind(||discard_fork_thread_control(&live)).is_err());
 assert!(CLOSED.lock().unwrap().is_empty());assert!(UNMAPS.lock().unwrap().is_empty());
 reset();let starting=ThreadControl::new(THREAD_STARTING);
 assert!(std::panic::catch_unwind(||discard_fork_thread_control(&starting)).is_err());
 assert!(CLOSED.lock().unwrap().is_empty());
}}
"#
    );
    probe::run(&program);
}
