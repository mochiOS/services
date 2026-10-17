//! Production admission transaction, real executor, controlled table/scheduler.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn rejected_admission_does_not_execute_or_leak_a_handle() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let mut program = format!(
        r#"
#![feature(allocator_api)]
#![allow(dead_code)]
extern crate alloc;
extern crate self as mnu_abi;
#[path={status:?}]pub mod status;
#[path={completion:?}]pub mod completion;
#[path={work:?}]mod owned_work;
#[path={executor:?}]mod executor;
#[path={batch:?}]mod writeback;
use status::Error;
use std::sync::{{Arc,atomic::{{AtomicUsize,Ordering}}}};
use std::cell::{{Cell,RefCell}};
thread_local! {{
    static LOCKED:Cell<bool>=const{{Cell::new(false)}};
    static PRESENT:Cell<bool>=const{{Cell::new(true)}};
    static FAIL_TABLE:Cell<bool>=const{{Cell::new(false)}};
    static FAIL_AFTER:Cell<Option<usize>>=const{{Cell::new(None)}};
    static WAKES:Cell<usize>=const{{Cell::new(0)}};
    static IO:Cell<usize>=const{{Cell::new(0)}};
    static PROCESS:RefCell<task::Process>=const{{RefCell::new(task::Process{{table:task::Table{{entries:Vec::new(),next:1}}}})}};
}}
struct Allocator;
unsafe impl std::alloc::GlobalAlloc for Allocator {{
    unsafe fn alloc(&self,l:std::alloc::Layout)->*mut u8 {{
        if FAIL_AFTER.try_with(|f|match f.get(){{Some(0)=>true,Some(n)=>{{f.set(Some(n-1));false}},None=>false}}).unwrap_or(false){{return std::ptr::null_mut();}}
        unsafe{{std::alloc::System.alloc(l)}}
    }}
    unsafe fn dealloc(&self,p:*mut u8,l:std::alloc::Layout){{unsafe{{std::alloc::System.dealloc(p,l)}}}}
}}
#[global_allocator]static ALLOCATOR:Allocator=Allocator;
struct Backing(Arc<AtomicUsize>);
impl Drop for Backing{{fn drop(&mut self){{assert!(!LOCKED.get());self.0.fetch_add(1,Ordering::SeqCst);}}}}
mod interrupt{{pub mod spinlock{{
    pub struct SpinLock<T>(std::sync::Mutex<T>);
    impl<T> SpinLock<T>{{pub const fn new(value:T)->Self{{Self(std::sync::Mutex::new(value))}}pub fn lock(&self)->std::sync::MutexGuard<'_,T>{{self.0.lock().unwrap()}}}}
}}}}
mod task{{
    pub type ProcessId=u64;
    pub struct ThreadId(u64);impl ThreadId{{pub fn from_u64(id:u64)->Self{{Self(id)}}}}
    pub struct ThreadQueue;impl ThreadQueue{{pub const MAX_THREADS:usize=64;}}
    pub fn wake_registered_waiter(thread:ThreadId){{assert_eq!(thread.0,7);assert!(!crate::LOCKED.get());crate::WAKES.set(crate::WAKES.get()+1);}}
    pub mod handle_table{{
        #[derive(Clone,Copy)]pub struct HandleRights(u64);
        impl HandleRights{{pub const READ:Self=Self(1);pub const WAIT:Self=Self(16);pub const DUPLICATE:Self=Self(1<<62);pub const TRANSFER:Self=Self(1<<63);pub fn union(self,other:Self)->Self{{Self(self.0|other.0)}}}}
        pub enum KernelObject{{Completion(crate::executor::Receipt)}}
        pub struct ObjectHandleEntry(pub KernelObject);
        impl ObjectHandleEntry{{pub fn new(object:KernelObject,rights:HandleRights)->Self{{assert_eq!(rights.0,1|16|(1<<62)|(1<<63));Self(object)}}}}
        #[derive(Clone,Copy)]pub struct ObjectHandle(pub u32);impl ObjectHandle{{pub fn raw(self)->u32{{self.0}}}}
    }}
    use handle_table::*;
    pub struct Table{{pub entries:Vec<(ObjectHandle,ObjectHandleEntry)>,pub next:u32}}
    impl Table{{
        pub fn insert(&mut self,entry:ObjectHandleEntry)->Option<ObjectHandle>{{assert!(crate::LOCKED.get());if crate::FAIL_TABLE.get(){{return None;}}let handle=ObjectHandle(self.next);self.next+=1;self.entries.push((handle,entry));Some(handle)}}
        pub fn take_entry(&mut self,handle:ObjectHandle)->Option<ObjectHandleEntry>{{assert!(crate::LOCKED.get());let index=self.entries.iter().position(|(h,_)|h.0==handle.0)?;Some(self.entries.remove(index).1)}}
    }}
    pub struct Process{{pub table:Table}}impl Process{{pub fn object_handles_mut(&mut self)->&mut Table{{&mut self.table}}}}
    pub fn with_process_mut<R>(pid:u64,f:impl FnOnce(&mut Process)->R)->Option<R>{{assert_eq!(pid,3);if !crate::PRESENT.get(){{return None;}}assert!(!crate::LOCKED.replace(true));let result=crate::PROCESS.with_borrow_mut(f);crate::LOCKED.set(false);Some(result)}}
}}
mod worker{{
use super::*;
use task::handle_table::{{HandleRights,KernelObject,ObjectHandleEntry}};
use executor::Executor;
type Work=writeback::Batch<Arc<Backing>>;
static EXECUTOR:Executor<Work,32>=Executor::new();
"#,
        status = root.join("core/crates/abi/src/status.rs"),
        completion = root.join("core/crates/abi/src/completion.rs"),
        work = root.join("core/src/task/owned_work.rs"),
        executor = root.join("core/src/task/owned_executor.rs"),
        batch = root.join("core/src/mem/writeback.rs"),
    );
    let source = include_str!("../../../core/src/mem/writeback_worker.rs");
    program.push_str(&source[source.find("pub(crate) fn submit(").unwrap()..]);
    program.push_str(r#"
pub fn start(){EXECUTOR.install_worker(7).unwrap();}
pub fn drain(){while EXECUTOR.run_one(|work|work.execute(|_,_,_|{assert!(!LOCKED.get());IO.set(IO.get()+1);Ok(())}),||{}){}}
}
fn work(drops:&Arc<AtomicUsize>)->writeback::Batch<Arc<Backing>>{writeback::Batch::new(vec![((Arc::new(Backing(drops.clone())),4096),8192)])}
fn count()->usize{PROCESS.with_borrow(|p|p.table.entries.len())}
fn main(){
    PROCESS.with_borrow_mut(|p|p.table.entries.reserve(40));
    let drops=Arc::new(AtomicUsize::new(0));
    assert_eq!(worker::submit(3,work(&drops)),Error::NotReady.into_raw());
    assert_eq!((count(),WAKES.get(),IO.get(),drops.load(Ordering::SeqCst)),(0,0,0,1));
    worker::start();
    for allowance in [0,1]{
        let work=work(&drops);FAIL_AFTER.set(Some(allowance));let result=worker::submit(3,work);FAIL_AFTER.set(None);
        assert_eq!(result,Error::ResourceUnavailable.into_raw());assert_eq!((count(),WAKES.get(),IO.get()),(0,0,0));
    }
    PRESENT.set(false);assert_eq!(worker::submit(3,work(&drops)),Error::NotReady.into_raw());PRESENT.set(true);
    FAIL_TABLE.set(true);assert_eq!(worker::submit(3,work(&drops)),Error::ResourceUnavailable.into_raw());FAIL_TABLE.set(false);
    assert_eq!((count(),WAKES.get(),IO.get(),drops.load(Ordering::SeqCst)),(0,0,0,5));
    for _ in 0..32{assert!(worker::submit(3,work(&drops))<4096);}
    assert_eq!(worker::submit(3,work(&drops)),Error::ResourceUnavailable.into_raw());
    assert_eq!((count(),WAKES.get(),IO.get(),drops.load(Ordering::SeqCst)),(32,32,0,6));
    worker::drain();assert_eq!(IO.get(),32);assert_eq!(drops.load(Ordering::SeqCst),38);
    PROCESS.with_borrow(|p|for (_,entry) in &p.table.entries{let task::handle_table::KernelObject::Completion(receipt)=&entry.0;assert_eq!(receipt.result(),Some(Ok(())));});
}
"#);
    probe::run(&program);
}
