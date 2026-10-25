#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn production_reclaimer_keeps_the_root_owner_until_the_departing_stack_is_detached() {
    let mut program = String::from(
        r#"
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool,AtomicU64,AtomicUsize,Ordering};
type ProcessId=u64;
struct Lock<T>(Mutex<T>);impl<T> Lock<T>{const fn new(v:T)->Self{Self(Mutex::new(v))}fn lock(&self)->std::sync::MutexGuard<'_,T>{self.0.lock().unwrap()}}
static PRESENT:AtomicBool=AtomicBool::new(true);static BUSY:AtomicBool=AtomicBool::new(true);
static THREAD:AtomicBool=AtomicBool::new(false);static FAIL:AtomicBool=AtomicBool::new(false);
static CURRENT:AtomicU64=AtomicU64::new(0);static DESTROYED:AtomicUsize=AtomicUsize::new(0);
struct Process;impl Process{fn page_table_owned(&self)->bool{true}fn page_table(&self)->Option<u64>{Some(4096)}}
struct ProcessTable;impl ProcessTable{const MAX_PROCESSES:usize=8;
fn take_exited(&mut self,id:u64)->Option<Process>{assert_eq!(id,7);PRESENT.swap(false,Ordering::SeqCst).then_some(Process)}}
static PROCESS_TABLE:Lock<ProcessTable>=Lock::new(ProcessTable);
static DEFERRED_PROCESS_RECLAIMS:Lock<[Option<u64>;8]>=Lock::new([None;8]);
fn defer_process_reclaim(id:u64){let mut queue=DEFERRED_PROCESS_RECLAIMS.lock();if !queue.contains(&Some(id)){*queue.iter_mut().find(|v|v.is_none()).unwrap()=Some(id)}}
fn with_process<T>(id:u64,f:impl FnOnce(&Process)->T)->Option<T>{assert_eq!(id,7);PRESENT.load(Ordering::SeqCst).then(||f(&Process))}
fn release_process_borrowed_mappings(_:u64)->Result<(),u64>{if FAIL.load(Ordering::SeqCst){Err(1)}else{Ok(())}}
fn destroy_exited_process(_:Process){assert!(!BUSY.load(Ordering::SeqCst));DESTROYED.fetch_add(1,Ordering::SeqCst);}
mod syscall{pub mod security{pub fn current_process_id()->Option<u64>{let id=crate::CURRENT.load(crate::Ordering::SeqCst);(id!=0).then_some(id)}}}
mod task{
pub struct Thread;impl Thread{pub fn process_id(&self)->u64{7}}
pub fn for_each_thread(mut f:impl FnMut(&Thread)){if crate::THREAD.load(crate::Ordering::SeqCst){f(&Thread)}}
pub fn kernel_stack_table_in_use(root:u64)->bool{assert_eq!(root,4096);crate::BUSY.load(crate::Ordering::SeqCst)}
}
"#,
    );
    program.push_str(probe::between(
        include_str!("../../../core/src/task/process.rs"),
        "pub fn flush_deferred_process_reclaims(",
        "/// Atomically revoke borrowed PTEs",
    ));
    program.push_str(
        r#"
fn main(){
defer_process_reclaim(7);
for _ in 0..3{
 flush_deferred_process_reclaims();
 assert!(PRESENT.load(Ordering::SeqCst));assert_eq!(DESTROYED.load(Ordering::SeqCst),0);
 assert!(DEFERRED_PROCESS_RECLAIMS.lock().contains(&Some(7)));
}
BUSY.store(false,Ordering::SeqCst);CURRENT.store(7,Ordering::SeqCst);
flush_deferred_process_reclaims();assert!(PRESENT.load(Ordering::SeqCst));
CURRENT.store(0,Ordering::SeqCst);THREAD.store(true,Ordering::SeqCst);
flush_deferred_process_reclaims();assert!(PRESENT.load(Ordering::SeqCst));
THREAD.store(false,Ordering::SeqCst);FAIL.store(true,Ordering::SeqCst);
flush_deferred_process_reclaims();assert!(PRESENT.load(Ordering::SeqCst));
FAIL.store(false,Ordering::SeqCst);flush_deferred_process_reclaims();
assert!(!PRESENT.load(Ordering::SeqCst));assert_eq!(DESTROYED.load(Ordering::SeqCst),1);
assert!(DEFERRED_PROCESS_RECLAIMS.lock().iter().all(Option::is_none));
flush_deferred_process_reclaims();assert_eq!(DESTROYED.load(Ordering::SeqCst),1);
}
"#,
    );
    probe::run(&program);
}
