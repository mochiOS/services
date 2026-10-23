#[path = "../../../core/src/task/ipc_generation.rs"]
mod generation;
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn actual_generation_reservations_are_unique_across_concurrent_threads() {
    let workers: Vec<_> = (0..8)
        .map(|_| {
            std::thread::spawn(|| {
                (0..1000)
                    .map(|_| generation::reserve().unwrap().into_raw())
                    .collect::<Vec<_>>()
            })
        })
        .collect();
    let mut values: Vec<_> = workers
        .into_iter()
        .flat_map(|worker| worker.join().unwrap())
        .collect();
    values.sort_unstable();
    assert_eq!(values.len(), 8000);
    assert_ne!(values[0], 0);
    assert!(values.windows(2).all(|pair| pair[0] < pair[1]));
}

#[test]
fn actual_u64_exhaustion_is_closed_and_initial_threads_never_reuse_zero() {
    let mut program = String::from("#![allow(dead_code)]\nmod generation {\n");
    program.push_str(include_str!("../../../core/src/task/ipc_generation.rs"));
    program.push_str(r#"
pub fn run(){
 NEXT.store(u64::MAX-1,Ordering::Relaxed);
 assert_eq!(reserve().unwrap().into_raw(),u64::MAX-1);
 assert!(reserve().is_none());assert_eq!(NEXT.load(Ordering::Relaxed),u64::MAX);
 assert_eq!(initial(),0);assert!(reserve().is_none());assert_eq!(NEXT.load(Ordering::Relaxed),u64::MAX);
}
}
fn main(){generation::run()}
"#);
    probe::run(&program);
}

#[test]
fn production_thread_rotation_preserves_native_identity_and_slot_lifetime_but_clears_ipc_state() {
    let thread = include_str!("../../../core/src/task/thread.rs");
    let mut program = String::from(
        r#"
#![allow(dead_code)]
use std::sync::Mutex;
type ThreadId=u64;
#[derive(PartialEq)]enum ThreadState{Ready,Terminated}
const FAST_IPC_MAX_BYTES:usize=256;
"#,
    );
    program.push_str(probe::between(
        thread,
        "pub struct IpcFastState {",
        "/// スレッド終了時に呼ばれるハンドラ",
    ));
    program.push_str(r#"
struct Thread{state:ThreadState,ipc_generation:u64,fast_ipc:IpcFastState,pending_wakeup:bool,native_object:std::sync::Arc<u64>}
impl Thread{fn state(&self)->ThreadState{match self.state{ThreadState::Ready=>ThreadState::Ready,_=>ThreadState::Terminated}}}
struct Queue{threads:[Option<Thread>;1],slot_generation:u64}
impl Queue {
 fn slot_index(&self,id:ThreadId)->Option<usize>{(id==7&&self.threads[0].is_some()).then_some(0)}
 fn get(&self,id:ThreadId)->Option<&Thread>{self.slot_index(id).and_then(|slot|self.threads[slot].as_ref())}
 fn get_mut(&mut self,id:ThreadId)->Option<&mut Thread>{self.slot_index(id).and_then(|slot|self.threads[slot].as_mut())}
"#);
    program.push_str(probe::between(
        thread,
        "    fn ipc_slot_index_and_generation(",
        "    /// スレッドを削除",
    ));
    program.push_str(r#"
}
struct Lock<T>(Mutex<T>);impl<T>Lock<T>{fn lock(&self)->std::sync::MutexGuard<'_,T>{self.0.lock().unwrap()}}
static THREAD_QUEUE:Lock<Queue>=Lock(Mutex::new(Queue{threads:[None],slot_generation:19}));
mod production {use super::*;
"#);
    program.push_str(probe::between(
        thread,
        "pub(crate) fn replace_ipc_generation(",
        "/// 現在実行中のスレッドIDを取得",
    ));
    program.push_str(r#"
}
fn main(){
 let object=std::sync::Arc::new(37);
 let mut fast=IpcFastState::new();fast.set_waiting(true);fast.set_wait_cpu(Some(3));fast.set_awaiting_reply(true);fast.set_reply_ready(true);fast.set_reply_result_len(17);
 THREAD_QUEUE.lock().threads[0]=Some(Thread{state:ThreadState::Ready,ipc_generation:71,fast_ipc:fast,pending_wakeup:true,native_object:object.clone()});
 assert_eq!(production::live_ipc_slot_index_and_generation_by_u64(7),Some((0,71)));
 assert_eq!(production::replace_ipc_generation(7,72),Some((0,71)));
 assert_eq!(production::live_ipc_slot_index_and_generation_by_u64(7),Some((0,72)));
 {
 let mut queue=THREAD_QUEUE.lock();assert_eq!(queue.slot_generation,19);
 let thread=queue.threads[0].as_mut().unwrap();assert!(std::sync::Arc::ptr_eq(&thread.native_object,&object));
 assert!(!thread.pending_wakeup);assert!(!thread.fast_ipc.waiting());assert!(!thread.fast_ipc.awaiting_reply());assert!(!thread.fast_ipc.reply_ready());assert_eq!(thread.fast_ipc.wait_cpu(),None);assert_eq!(thread.fast_ipc.take_reply_result_len(),0);
 thread.state=ThreadState::Terminated;
 }
 assert_eq!(production::live_ipc_slot_index_and_generation_by_u64(7),None);
 assert_eq!(production::replace_ipc_generation(8,73),None);
}
"#);
    // Native ThreadId conversion is not part of the IPC generation algorithm.
    let program = program.replace("ThreadId::from_u64(id_val)", "id_val");
    probe::run(&program);
}

#[test]
fn image_commit_reserves_generation_before_destructive_work_and_retires_before_user_entry() {
    let source = include_str!("../../../core/src/syscall/exec.rs");
    let body = probe::between(
        source,
        "fn replace_current_process_image(",
        "/// Replaces the current process image",
    );
    assert!(
        body.find("ipc_generation::reserve()").unwrap()
            < body.find("release_process_borrowed_mappings(pid)").unwrap()
    );
    let commit = body
        .find(".commit_image_revision(next_image_revision)")
        .unwrap();
    let retirement = body
        .find("replace_thread_image_endpoint(current_tid, next_ipc_generation)")
        .unwrap();
    assert!(commit < retirement);
    assert!(retirement < body.find("destroy_user_page_table(old)").unwrap());
    assert!(retirement < body.find("new_pt_guard.disarm()").unwrap());
}

#[test]
fn production_default_cache_serializes_creation_and_retirement_cannot_remove_a_new_image() {
    let source = include_str!("../../../core/src/syscall/ipc.rs");
    let mut program = String::from(
        r#"
#![allow(dead_code)]
use std::{collections::BTreeMap,sync::{Mutex as StdMutex,atomic::{AtomicU64,Ordering}}};
struct Mutex<T>(StdMutex<T>);
impl<T>Mutex<T>{const fn new(value:T)->Self{Self(StdMutex::new(value))}fn lock(&self)->std::sync::MutexGuard<'_,T>{self.0.lock().unwrap()}}
#[derive(Clone,Copy,Debug)]struct EndpointRights;
#[derive(Clone,Copy)]struct IpcEndpoint{thread_id:u64,slot:u16,generation:u64}
static CURRENT:AtomicU64=AtomicU64::new(71);
fn endpoint_for_thread(thread_id:u64)->Option<IpcEndpoint>{Some(IpcEndpoint{thread_id,slot:0,generation:CURRENT.load(Ordering::Acquire)})}
fn endpoint_is_valid(endpoint:IpcEndpoint)->bool{endpoint.thread_id==7&&endpoint.slot==0&&endpoint.generation==CURRENT.load(Ordering::Acquire)}
fn endpoint_rights_for_thread(_:u64)->EndpointRights{EndpointRights}
"#,
    );
    program.push_str(probe::between(
        source,
        "#[derive(Clone, Copy, Debug)]\nstruct EndpointRecord",
        "pub fn endpoint_for_thread(",
    ));
    program.push_str(probe::between(
        source,
        "fn with_endpoints_mut<R>",
        "pub fn endpoint_alive(",
    ));
    program.push_str(probe::between(
        source,
        "fn endpoint_handle_for_thread(",
        "pub fn resolve_endpoint_handle(",
    ));
    program.push_str(r#"
fn main(){
 let old=endpoint_for_thread(7).unwrap();
 let workers:Vec<_>=(0..24).map(|_|std::thread::spawn(||ensure_endpoint_for_thread(7).unwrap())).collect();
 let handles:Vec<_>=workers.into_iter().map(|worker|worker.join().unwrap()).collect();
 assert!(handles.iter().all(|handle|*handle==handles[0]));
 assert_eq!(with_endpoints_mut(|map|map.len()),1);
 CURRENT.store(72,Ordering::Release);
 assert!(endpoint_record_from_handle(handles[0]).is_none());
 let new=ensure_endpoint_for_thread(7).unwrap();assert_ne!(new,handles[0]);
 // Model cleanup delayed until after publication of the new image's endpoint.
 retire_endpoint_records(old);retire_endpoint_records(old);
 assert_eq!(endpoint_handle_for_thread(7),Some(new));
 assert_eq!(with_endpoints_mut(|map|map.len()),1);
 assert_eq!(with_default_endpoints_mut(|map|map.len()),1);
 assert!(with_default_endpoints_mut(|map|!map.contains_key(&71)));
 assert_eq!(endpoint_record_from_handle(new).unwrap().generation,72);
 // The final opaque handle is issued once; exhaustion cannot wrap or erase
 // another lifetime's default endpoint.
 CURRENT.store(73,Ordering::Release);NEXT_ENDPOINT_HANDLE.store(ENDPOINT_HANDLE_LIMIT,Ordering::Relaxed);
 assert_eq!(ensure_endpoint_for_thread(7),Some(ENDPOINT_HANDLE_LIMIT));
 CURRENT.store(74,Ordering::Release);assert!(ensure_endpoint_for_thread(7).is_none());
 assert_eq!(NEXT_ENDPOINT_HANDLE.load(Ordering::Relaxed),ENDPOINT_HANDLE_LIMIT+1);
 assert!(with_default_endpoints_mut(|map|!map.contains_key(&74)));
 assert_eq!(with_default_endpoints_mut(|map|map.get(&72).copied()),Some(new));
}
"#);
    probe::run(&program);
}
