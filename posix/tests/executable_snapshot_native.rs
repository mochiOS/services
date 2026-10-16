//! Run the actual bounded reader with controlled object I/O. This checks local
//! admission, storage and cleanup, not provider IPC or the pager implementation.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn snapshot_preserves_authority_bounds_backend_errors_and_owned_storage() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let mut program = String::from("#![allow(dead_code,unused_attributes)]\nextern crate alloc;\n");
    program.push_str(&format!(
        "extern crate self as mnu_abi;\n#[path={:?}]mod abi;\npub use abi::*;\nmod util {{#[path={:?}]pub mod object_snapshot;}}\n",
        root.join("core/crates/abi/src/lib.rs"),
        root.join("core/src/util/object_snapshot.rs")
    ));
    program.push_str(
        r#"
use std::{cell::Cell,sync::{Arc,atomic::{AtomicUsize,Ordering}}};
use mnu_abi::status::Error;
thread_local! {
    static FAIL_AFTER:Cell<Option<usize>>=const {Cell::new(None)};
    static MODE:Cell<u8>=const {Cell::new(0)};
    static AUTH_ERROR:Cell<Option<Error>>=const {Cell::new(None)};
    static BACKEND_ERROR:Cell<Option<u64>>=const {Cell::new(None)};
    static IDENTITY:Cell<Option<u64>>=const {Cell::new(Some(11))};
    static LENGTH:Cell<u64>=const {Cell::new(5)};
    static SHORT:Cell<bool>=const {Cell::new(false)};
    static QUERIES:Cell<usize>=const {Cell::new(0)};
    static READS:Cell<usize>=const {Cell::new(0)};
    static SEEKS:Cell<usize>=const {Cell::new(0)};
    static LOCKS:Cell<usize>=const {Cell::new(0)};
    static UNLOCKS:Cell<usize>=const {Cell::new(0)};
}
static ALLOCATIONS:AtomicUsize=AtomicUsize::new(0);
struct Allocator;
unsafe impl std::alloc::GlobalAlloc for Allocator {
    unsafe fn alloc(&self,layout:std::alloc::Layout)->*mut u8 {
        if FAIL_AFTER.with(|s|match s.get(){Some(0)=>{s.set(None);true},Some(n)=>{s.set(Some(n-1));false},None=>false}) {return std::ptr::null_mut();}
        let p=unsafe {std::alloc::System.alloc(layout)};
        if !p.is_null(){ALLOCATIONS.fetch_add(1,Ordering::Relaxed);}p
    }
    unsafe fn dealloc(&self,p:*mut u8,layout:std::alloc::Layout) {
        ALLOCATIONS.fetch_sub(1,Ordering::Relaxed);unsafe {std::alloc::System.dealloc(p,layout)}
    }
}
#[global_allocator]static ALLOCATOR:Allocator=Allocator;
mod task {
"#,
    );
    program.push_str(probe::between(
        include_str!("../../../core/src/task/handle_table.rs"),
        "#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]",
        "/// Kernel object identity",
    ));
    program.push_str(
        r#"
}
use task::HandleRights;
struct Memory;
impl Memory {
    fn memory_length(&self)->Option<u64> {if MODE.get()==3 {None}else{Some(LENGTH.get())}}
    fn read_at(&self,offset:u64,output:&mut [u8])->Result<usize,u64> {
        assert_eq!(offset,0);READS.set(READS.get()+1);
        if let Some(error)=BACKEND_ERROR.get(){return Err(error);}
        output.fill(b'x');Ok(if SHORT.get(){output.len().saturating_sub(1)}else{output.len()})
    }
}
struct Provider;
enum KernelObject {VmObject(Memory),Provider(Arc<Provider>),Other}
thread_local! {static PROVIDER:Arc<Provider>=Arc::new(Provider);}
fn object_native(raw:u64,rights:HandleRights)->Result<KernelObject,Error> {
    assert_eq!(raw,7);let query=QUERIES.get();QUERIES.set(query+1);
    assert_eq!(rights,if query==0 {HandleRights::READ}else{HandleRights::READ.union(HandleRights::SEEK)});
    if let Some(error)=AUTH_ERROR.get(){return Err(error);}
    Ok(match MODE.get(){0|3=>KernelObject::VmObject(Memory),1=>KernelObject::Provider(PROVIDER.with(Arc::clone)),_=>KernelObject::Other})
}
mod syscall {pub mod fs {pub enum SeekBasis {Start,End}}}
mod mem {pub mod vm_object {
    pub struct Guard;
    impl Drop for Guard {fn drop(&mut self){crate::UNLOCKS.set(crate::UNLOCKS.get()+1);}}
    pub fn lock_provider_io(_:&crate::Provider,identity:u64)->Result<Guard,crate::Error> {
        assert_eq!(identity,11);crate::LOCKS.set(crate::LOCKS.get()+1);Ok(Guard)
    }
}}
fn provider_cache_identity(_:&Provider)->Result<Option<u64>,u64> {Ok(IDENTITY.get())}
fn provider_seek_result(_:&Provider,offset:i64,basis:syscall::fs::SeekBasis)->Result<u64,u64> {
    assert_eq!(offset,0);let count=SEEKS.get();SEEKS.set(count+1);
    if let Some(error)=BACKEND_ERROR.get(){return Err(error);}
    match basis {syscall::fs::SeekBasis::End=>{assert_eq!(count,0);Ok(LENGTH.get())},syscall::fs::SeekBasis::Start=>{assert_eq!(count,1);Ok(0)}}
}
fn provider_read_chunk<'a>(_:&Provider,identity:Option<u64>,length:usize,storage:&'a mut [u8])->Result<&'a [u8],u64> {
    assert_eq!(identity,IDENTITY.get());assert!(length<=if identity.is_some(){mnu_abi::provider::MAX_POSITIONED_READ_LEN}else{mnu_abi::provider::MAX_DATA_LEN});
    assert_eq!(LOCKS.get()-UNLOCKS.get(),usize::from(identity.is_some()));
    READS.set(READS.get()+1);let count=if SHORT.get(){0}else{length.min(2)};
    storage[..count].fill(b'x');Ok(&storage[..count])
}
"#,
    );
    program.push_str(probe::between(
        include_str!("../../../core/src/syscall/handle.rs"),
        "pub(crate) fn read_all(",
        "pub fn provider_object_create(",
    ));
    program.push_str(
        r#"
fn reset(mode:u8) {
    FAIL_AFTER.set(None);MODE.set(mode);AUTH_ERROR.set(None);BACKEND_ERROR.set(None);
    LENGTH.set(5);SHORT.set(false);IDENTITY.set(Some(11));QUERIES.set(0);READS.set(0);SEEKS.set(0);LOCKS.set(0);UNLOCKS.set(0);
}
fn error(expected:u64) {
    let allocations=ALLOCATIONS.load(Ordering::Relaxed);
    assert_eq!(read_all(7,5).err(),Some(expected));
    assert_eq!(ALLOCATIONS.load(Ordering::Relaxed),allocations,"snapshot error must release all owned storage");
    assert_eq!(LOCKS.get(),UNLOCKS.get());
    PROVIDER.with(|p|assert_eq!(Arc::strong_count(p),1));
}
fn main() {
    // Initialize the retained source before injecting allocation failures.
    PROVIDER.with(|p|assert_eq!(Arc::strong_count(p),1));
    for mode in [0,1] {
        for denied in [Error::InvalidArgument,Error::AccessDenied,Error::NotReady] {
            reset(mode);AUTH_ERROR.set(Some(denied));error(denied.into_raw());assert_eq!(READS.get(),0);assert_eq!(SEEKS.get(),0);
        }
        for length in [6,u64::MAX] {
            reset(mode);LENGTH.set(length);error(Error::LimitExceeded.into_raw());assert_eq!(READS.get(),0);
            assert_eq!(SEEKS.get(),usize::from(mode==1));
        }
        reset(mode);SHORT.set(true);error(Error::BackingFailure.into_raw());
        for downstream in [Error::BackingFailure.into_raw(),Error::ResourceUnavailable.into_raw(),mnu_abi::EACCES,(-42i64) as u64] {
            reset(mode);BACKEND_ERROR.set(Some(downstream));error(downstream);
        }
        for allocation in 0..if mode==0 {1}else{2} {
            reset(mode);FAIL_AFTER.set(Some(allocation));error(Error::ResourceUnavailable.into_raw());
            assert_eq!(FAIL_AFTER.get(),None);assert_eq!(READS.get(),0);
        }
        for identity in [None,Some(11)] {
            reset(mode);IDENTITY.set(identity);assert_eq!(read_all(7,5).unwrap(),b"xxxxx");
            assert_eq!(QUERIES.get(),if mode==0 {1}else{2});assert_eq!(LOCKS.get(),UNLOCKS.get());
        }
        reset(mode);LENGTH.set(0);assert!(read_all(7,0).unwrap().is_empty());assert_eq!(LOCKS.get(),UNLOCKS.get());
    }
    for mode in [2,3] {reset(mode);error(Error::InvalidArgument.into_raw());assert_eq!(READS.get(),0);assert_eq!(SEEKS.get(),0);}
}
"#,
    );
    probe::run(&program);
}
