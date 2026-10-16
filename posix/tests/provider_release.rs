//! Run the production provider owner, release queue and flush loop with a
//! faulting allocator. Only scheduler/IPC boundaries are substituted.
use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn production_release_owner_queue_and_retry_survive_allocation_denial() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let table = include_str!("../../../core/src/task/handle_table.rs");
    let end = table
        .find("#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]")
        .unwrap();
    let table = &table[..end];
    let handle = include_str!("../../../core/src/syscall/handle.rs");
    let begin = handle
        .find("pub(crate) fn flush_provider_releases()")
        .unwrap();
    let end = handle[begin..].find("\nfn current_process()").unwrap() + begin;
    let mut program = String::from(
        r#"
#![feature(allocator_api)]
#![allow(dead_code,unused_imports)]
extern crate alloc;
use std::sync::atomic::{AtomicBool,AtomicUsize,Ordering};
use std::alloc::{GlobalAlloc,Layout,System};
static DENY:AtomicBool=AtomicBool::new(false);
static ATTEMPTS:AtomicUsize=AtomicUsize::new(0);
struct FaultAllocator;
unsafe impl GlobalAlloc for FaultAllocator {
    unsafe fn alloc(&self,layout:Layout)->*mut u8 {
        if DENY.load(Ordering::Relaxed) { ATTEMPTS.fetch_add(1,Ordering::Relaxed); std::ptr::null_mut() }
        else { unsafe{System.alloc(layout)} }
    }
    unsafe fn realloc(&self,p:*mut u8,l:Layout,n:usize)->*mut u8 {
        if DENY.load(Ordering::Relaxed) { ATTEMPTS.fetch_add(1,Ordering::Relaxed); std::ptr::null_mut() }
        else { unsafe{System.realloc(p,l,n)} }
    }
    unsafe fn dealloc(&self,p:*mut u8,l:Layout) {unsafe{System.dealloc(p,l)}}
}
#[global_allocator] static ALLOCATOR:FaultAllocator=FaultAllocator;
mod interrupt {pub mod spinlock {
    pub struct SpinLock<T>(std::sync::Mutex<T>);
    impl<T> SpinLock<T>{
        pub const fn new(value:T)->Self{Self(std::sync::Mutex::new(value))}
        pub fn lock(&self)->std::sync::MutexGuard<'_,T>{self.0.lock().unwrap()}
        pub fn try_lock(&self)->Option<std::sync::MutexGuard<'_,T>>{self.0.try_lock().ok()}
    }
}}
extern crate self as mnu_abi;
pub const ENOMEM:u64=(-12i64) as u64;
pub const PROCESS_MAX_OBJECT_HANDLES:usize=4096;
pub const HANDLE_SEEK_START:u64=0;
pub const HANDLE_SEEK_CURRENT:u64=1;
pub const HANDLE_SEEK_END:u64=2;
mod task {
    pub mod fd_table {pub struct FileHandle;}
    pub mod process {pub struct ProcessObject;}
    pub mod ids {
        #[derive(Clone,Copy,PartialEq,Eq)] pub struct ThreadId(u64);
        impl ThreadId {
            pub fn as_u64(&self)->u64{self.0}
            pub fn from_u64(id:u64)->Self{Self(id)}
        }
    }
    pub use ids::ThreadId;
    pub fn wake_registered_waiter(_:ThreadId){panic!("release-only fixture has no I/O waiters")}
    pub struct ThreadQueue;
    impl ThreadQueue{pub const MAX_THREADS:usize=64;}
    pub fn thread_id_exists(_:u64)->bool{true}
    pub fn wake_thread(_:ids::ThreadId){}
    pub mod handle_table {
        use crate::mnu_abi;
"#,
    );
    program = program.replace(
        "extern crate self as mnu_abi;",
        &format!(
            "extern crate self as mnu_abi; #[path={:?}] pub mod status;",
            root.join("core/crates/abi/src/status.rs")
        ),
    );
    program = program.replace(
        "mod task {",
        &format!(
            "mod task {{ #[path={:?}] pub mod deferred;",
            root.join("core/src/task/deferred.rs")
        ),
    );
    program.push_str(table);
    program.push_str(
        r#"
    }
}
mod syscall {pub const ENOMEM:u64=(-12i64) as u64;pub mod ipc {
    use crate::{AtomicBool,AtomicUsize,Ordering};
    #[derive(Clone,Copy)] pub struct IpcEndpoint {pub thread_id:u64,pub slot:u16,pub generation:u64}
    pub static BLOCK:AtomicBool=AtomicBool::new(true);
    pub static INVALID:AtomicBool=AtomicBool::new(false);
    pub static SENT:AtomicUsize=AtomicUsize::new(0);
    pub static LAST:AtomicUsize=AtomicUsize::new(0);
    pub fn endpoint_is_valid(endpoint:IpcEndpoint)->bool {
        assert_eq!((endpoint.thread_id,endpoint.slot,endpoint.generation),(31,4,8));
        !INVALID.load(Ordering::Relaxed)
    }
    pub fn send_provider_from_kernel(_:IpcEndpoint,bytes:&[u8])->bool {
        if BLOCK.load(Ordering::Relaxed){return false}
        assert_eq!(u16::from_le_bytes(bytes[6..8].try_into().unwrap()),4);
        let id=u64::from_le_bytes(bytes[8..16].try_into().unwrap()) as usize;
        assert!(id>LAST.load(Ordering::Relaxed));
        LAST.store(id,Ordering::Relaxed);
        SENT.fetch_add(1,Ordering::Relaxed); true
    }
}}
mod flush {
    use crate::mnu_abi;
"#,
    );
    // Use the real wire encoder as well as the real flush loop.
    program.push_str(&format!(
        "mod wire {{ pub const HANDLE_SEEK_START:u64=0; pub const HANDLE_SEEK_CURRENT:u64=1; pub const HANDLE_SEEK_END:u64=2; #[path={:?}] pub mod provider; }}\n",
        root.join("core/crates/abi/src/provider.rs")
    ));
    // The production flush function only uses the provider submodule of ABI.
    program.push_str(&handle[begin..end].replace("mnu_abi::provider", "wire::provider"));
    program.push_str(&format!(
        "#[path={:?}] mod object_io; #[path={:?}] mod object_io_native;\n",
        root.join("core/src/mem/object_io.rs"),
        root.join("core/src/mem/object_io_native.rs"),
    ));
    program.push_str(r#"
pub fn verify_gate_allocations() {
    use crate::{DENY,ATTEMPTS,Ordering};
    use crate::status::Error;
    let mut registry=object_io::Registry::new();
    DENY.store(true,Ordering::Relaxed);
    assert!(matches!(object_io_native::new_lock(),Err(Error::ResourceUnavailable)));
    DENY.store(false,Ordering::Relaxed);
    assert_eq!(ATTEMPTS.swap(0,Ordering::Relaxed),1);
    DENY.store(true,Ordering::Relaxed);
    assert!(matches!(registry.try_get(7,object_io_native::new_lock,Error::ResourceUnavailable),Err(Error::ResourceUnavailable)));
    DENY.store(false,Ordering::Relaxed);
    assert_eq!(ATTEMPTS.swap(0,Ordering::Relaxed),1);
    // Reserve the weak slot, but fail the factory before publishing anything.
    assert_eq!(registry.try_get(7,||Err(Error::AccessDenied),Error::ResourceUnavailable).err(),Some(Error::AccessDenied));
    DENY.store(true,Ordering::Relaxed);
    assert!(matches!(registry.try_get(7,object_io_native::new_lock,Error::ResourceUnavailable),Err(Error::ResourceUnavailable)));
    DENY.store(false,Ordering::Relaxed);
    assert_eq!(ATTEMPTS.swap(0,Ordering::Relaxed),1);
    let first=registry.try_get(7,object_io_native::new_lock,Error::ResourceUnavailable).unwrap();
    DENY.store(true,Ordering::Relaxed);
    let alias=registry.try_get(7,||panic!("live gate must not allocate"),Error::ResourceUnavailable).unwrap();
    let owner=first.lock(||panic!("uncontended gate")).unwrap();
    drop(owner);drop(first);drop(alias);
    assert_eq!(ATTEMPTS.load(Ordering::Relaxed),0);
    DENY.store(false,Ordering::Relaxed);
}
}
fn make(id:u64)->std::sync::Arc<task::handle_table::ProviderObject> {
    let object=std::sync::Arc::try_new(task::handle_table::ProviderObject::new(31,4,8,id).unwrap()).unwrap();
    assert!(task::handle_table::register_provider_object(&object)); object
}
fn main(){
    use task::handle_table as h;
    DENY.store(true,Ordering::Relaxed);
    assert!(matches!(h::ProviderObject::new(31,4,8,99),Err(mnu_abi::ENOMEM)));
    DENY.store(false,Ordering::Relaxed);
    assert_eq!(ATTEMPTS.swap(0,Ordering::Relaxed),1);
    assert!(h::take_provider_releases().pop().is_none());
    let prepared=h::ProviderObject::new(31,4,8,99).unwrap();
    DENY.store(true,Ordering::Relaxed);
    assert!(std::sync::Arc::try_new(prepared).is_err());
    DENY.store(false,Ordering::Relaxed);
    assert_eq!(ATTEMPTS.swap(0,Ordering::Relaxed),1);
    assert!(h::take_provider_releases().pop().is_none());
    let first=make(1); let alias=first.clone();
    DENY.store(true,Ordering::Relaxed);
    drop(first);
    assert!(h::take_provider_releases().pop().is_none());
    drop(alias);
    flush::flush_provider_releases(); // Backpressure: keep the reserved node.
    flush::flush_provider_releases(); // Retry must neither allocate nor lose it.
    assert_eq!(ATTEMPTS.load(Ordering::Relaxed),0);
    syscall::ipc::BLOCK.store(false,Ordering::Relaxed);
    flush::flush_provider_releases();
    flush::flush_provider_releases();
    assert_eq!(syscall::ipc::SENT.load(Ordering::Relaxed),1);
    assert_eq!(ATTEMPTS.load(Ordering::Relaxed),0);
    DENY.store(false,Ordering::Relaxed);
    let unregistered=h::ProviderObject::new(31,4,8,2).unwrap();
    DENY.store(true,Ordering::Relaxed); drop(unregistered);
    assert!(h::take_provider_releases().pop().is_none());
    DENY.store(false,Ordering::Relaxed);
    // Duplicate registration must not release the existing provider's object.
    let owner=make(2);
    let duplicate=std::sync::Arc::new(h::ProviderObject::new(31,4,8,2).unwrap());
    assert!(!h::register_provider_object(&duplicate));
    DENY.store(true,Ordering::Relaxed); drop(duplicate);
    assert!(h::take_provider_releases().pop().is_none());
    drop(owner); flush::flush_provider_releases();
    DENY.store(false,Ordering::Relaxed);
    let old=make(20000); drop(old);
    let mut detached=h::take_provider_releases();
    let arriving=make(20001); drop(arriving);
    let retry=detached.pop().unwrap();
    assert!(detached.pop().is_none());
    h::requeue_provider_release(retry);
    let mut batch=h::take_provider_releases();
    assert_eq!(batch.pop().unwrap().value().object_id,20001);
    assert_eq!(batch.pop().unwrap().value().object_id,20000);
    assert!(batch.pop().is_none());
    // Large batches and final destruction must be iterative and allocation-free.
    let mut objects=Vec::new();
    for id in 3..10003 {objects.push(make(id));}
    DENY.store(true,Ordering::Relaxed);
    for object in objects {drop(object);}
    flush::flush_provider_releases();
    assert_eq!(syscall::ipc::SENT.load(Ordering::Relaxed),10002);
    assert_eq!(ATTEMPTS.load(Ordering::Relaxed),0);
    DENY.store(false,Ordering::Relaxed);
    let dead=make(10003);
    DENY.store(true,Ordering::Relaxed);
    drop(dead); syscall::ipc::INVALID.store(true,Ordering::Relaxed);
    flush::flush_provider_releases();
    assert!(h::take_provider_releases().pop().is_none());
    assert_eq!(ATTEMPTS.load(Ordering::Relaxed),0);
    DENY.store(false,Ordering::Relaxed);
    // Exercise destruction of a nonempty detached chain, not just a drained
    // queue. A recursive Box-chain destructor would exhaust a small stack.
    let objects:Vec<_>=(30000..40000).map(make).collect();
    DENY.store(true,Ordering::Relaxed);
    drop(objects);
    drop(h::take_provider_releases());
    assert!(h::take_provider_releases().pop().is_none());
    assert_eq!(ATTEMPTS.load(Ordering::Relaxed),0);
    DENY.store(false,Ordering::Relaxed);
    flush::verify_gate_allocations();
    deferred_cleanup_probe::verify();
}

"#);
    program.push_str(&format!(
        "#[path={:?}] mod deferred_cleanup_probe;\n",
        root.join("services/posix/tests/support/deferred_cleanup.rs")
    ));
    let directory = std::env::temp_dir().join(format!(
        "mochios-provider-release-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    let binary = directory.join("probe");
    let mut compiler = Command::new("rustup")
        .args([
            "run",
            "nightly-2026-07-16",
            "rustc",
            "--edition=2024",
            "-Cstrip=symbols",
            "-",
        ])
        .arg("-o")
        .arg(&binary)
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    compiler
        .stdin
        .take()
        .unwrap()
        .write_all(program.as_bytes())
        .unwrap();
    let compiled = compiler.wait_with_output().unwrap();
    if !compiled.status.success() {
        std::fs::remove_dir_all(&directory).unwrap();
    }
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let executed = Command::new(&binary).output().unwrap();
    std::fs::remove_dir_all(&directory).unwrap();
    assert!(
        executed.status.success(),
        "{}",
        String::from_utf8_lossy(&executed.stderr)
    );
}

#[test]
fn cleanup_reuses_reserved_nodes_and_does_not_register_sender_endpoints() {
    let owner = include_str!("../../../core/src/task/handle_table.rs");
    let drop = owner
        .split("impl Drop for ProviderObject")
        .nth(1)
        .unwrap()
        .split("impl ProviderObject")
        .next()
        .unwrap();
    assert!(drop.contains("self.release_ticket.take()"));
    assert!(!drop.contains("ProviderRelease {"));
    let ipc = include_str!("../../../core/src/syscall/ipc.rs");
    let send = ipc
        .split("pub(crate) fn send_provider_from_kernel(")
        .nth(1)
        .unwrap()
        .split("pub fn call_from_kernel(")
        .next()
        .unwrap();
    assert!(send.contains("endpoint_handle_for_thread(thread.as_u64())"));
    assert!(!send.contains("ensure_endpoint_for_thread"));
}
