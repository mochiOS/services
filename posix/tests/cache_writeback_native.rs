#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn writeback_allocation_failures_and_short_writes_preserve_dirty_pages() {
    let source = include_str!("../../../core/src/mem/vm_object.rs");
    let mut program = String::from(
        r#"
#![feature(allocator_api)]
#![allow(dead_code)]
extern crate alloc;
extern crate self as mnu_abi;
use alloc::sync::Arc;
use std::cell::Cell;
use std::ops::{Deref,DerefMut};
mod status {
"#,
    );
    program.push_str(include_str!("../../../core/crates/abi/src/status.rs"));
    program.push_str(r#"
}
use status::Error;
const PAGE_BYTES:usize=4096;
thread_local!{
    static FAIL:Cell<Option<usize>>=const{Cell::new(None)};
    static CACHE_LOCKED:Cell<bool>=const{Cell::new(false)};
    static IO_LOCKED:Cell<bool>=const{Cell::new(false)};
    static GATE_ERROR:Cell<Option<Error>>=const{Cell::new(None)};
    static LOWER_ERROR:Cell<Option<u64>>=const{Cell::new(None)};
    static FAIL_WRITE:Cell<usize>=const{Cell::new(1)};
    static SYNC_ERROR:Cell<Option<u64>>=const{Cell::new(None)};
    static SHORT:Cell<bool>=const{Cell::new(false)};
    static REWRITE:Cell<bool>=const{Cell::new(false)};
    static SHARED_FRAME:Cell<bool>=const{Cell::new(false)};
    static OFFSET_PRESENT:Cell<bool>=const{Cell::new(true)};
    static WRITES:Cell<usize>=const{Cell::new(0)};
    static SYNCS:Cell<usize>=const{Cell::new(0)};
}
struct Allocator;
fn fail()->bool{FAIL.try_with(|slot|match slot.get(){
    Some(0)=>true,Some(n)=>{slot.set(Some(n-1));false},None=>false
}).unwrap_or(false)}
unsafe impl std::alloc::GlobalAlloc for Allocator{
    unsafe fn alloc(&self,l:std::alloc::Layout)->*mut u8{if fail(){core::ptr::null_mut()}else{unsafe{std::alloc::System.alloc(l)}}}
    unsafe fn realloc(&self,p:*mut u8,l:std::alloc::Layout,n:usize)->*mut u8{if fail(){core::ptr::null_mut()}else{unsafe{std::alloc::System.realloc(p,l,n)}}}
    unsafe fn dealloc(&self,p:*mut u8,l:std::alloc::Layout){unsafe{std::alloc::System.dealloc(p,l)}}
}
#[global_allocator]static ALLOCATOR:Allocator=Allocator;
struct Cache(std::sync::Mutex<Vec<CachedPage>>);
struct CacheGuard(std::sync::MutexGuard<'static,Vec<CachedPage>>);
impl Cache{fn lock(&'static self)->CacheGuard{assert!(!CACHE_LOCKED.replace(true));CacheGuard(self.0.lock().unwrap())}}
impl Deref for CacheGuard{type Target=Vec<CachedPage>;fn deref(&self)->&Self::Target{&self.0}}
impl DerefMut for CacheGuard{fn deref_mut(&mut self)->&mut Self::Target{&mut self.0}}
impl Drop for CacheGuard{fn drop(&mut self){assert!(CACHE_LOCKED.replace(false));}}
struct CachedPage{key:PageKey,bytes:Arc<[u8;PAGE_BYTES]>,frame_phys:Option<u64>,dirty_range:Option<(usize,usize)>,version:u64,last_used:u64}
static PAGE_CACHE:Cache=Cache(std::sync::Mutex::new(Vec::new()));
static FRAME:[u8;PAGE_BYTES]=[0x5a;PAGE_BYTES];
static CLOCK:std::sync::atomic::AtomicU64=std::sync::atomic::AtomicU64::new(1);
fn next_cache_access()->u64{CLOCK.fetch_add(1,std::sync::atomic::Ordering::Relaxed)}
struct IoGuard;
impl Drop for IoGuard{fn drop(&mut self){assert!(IO_LOCKED.replace(false));}}
fn lock_provider_key(_:ObjectKey)->Result<IoGuard,Error>{
    assert!(!CACHE_LOCKED.get());if let Some(error)=GATE_ERROR.get(){return Err(error);}
    assert!(!IO_LOCKED.replace(true));Ok(IoGuard)
}
mod mem{pub mod paging{
    pub fn user_frame_has_multiple_owners(_:u64)->bool{crate::SHARED_FRAME.get()}
    pub fn physical_memory_offset()->Option<u64>{crate::OFFSET_PRESENT.get().then_some(0)}
}}
mod syscall{pub mod handle{
    pub fn provider_sync(_:&())->Result<(),u64>{
        assert!(!crate::CACHE_LOCKED.get());assert!(crate::IO_LOCKED.get());
        crate::SYNCS.set(crate::SYNCS.get()+1);crate::SYNC_ERROR.get().map_or(Ok(()),Err)
    }
}}
enum VmObjectSource{Memory(()),Provider{object:()}}
struct VmObject{source:VmObjectSource}
impl VmObject{fn object_key(&self)->ObjectKey{ObjectKey::Memory(1)}
"#);
    program.push_str(probe::between(
        source,
        "    pub fn flush_range(",
        "    /// Cleanup after PTEs",
    ));
    program.push_str("}\n");
    program.push_str(probe::between(
        source,
        "#[derive(Clone, Copy, Debug, PartialEq, Eq)]\npub(crate) enum ObjectKey",
        "struct CachedPage",
    ));
    program.push_str(probe::between(
        source,
        "fn snapshot_page(",
        "fn copy_to_frame(",
    ));
    program.push_str(r#"
fn write_lower(_:&VmObjectSource,offset:u64,input:&[u8])->Result<usize,u64>{
    assert!(!CACHE_LOCKED.get());assert!(IO_LOCKED.get());assert_eq!(offset%4096,7);
    assert_eq!(input.len(),12);assert!(input.iter().all(|b|*b==0x5a));
    WRITES.set(WRITES.get()+1);
    if REWRITE.replace(false){let mut cache=PAGE_CACHE.lock();cache[0].version+=1;}
    if let Some(error)=LOWER_ERROR.get(){if WRITES.get()==FAIL_WRITE.get(){return Err(error);}}
    Ok(if SHORT.get(){input.len()-1}else{input.len()})
}
fn reset(count:usize,resident:bool)->Arc<[u8;PAGE_BYTES]>{
    FAIL.set(None);GATE_ERROR.set(None);LOWER_ERROR.set(None);SYNC_ERROR.set(None);
    SHORT.set(false);REWRITE.set(false);SHARED_FRAME.set(false);OFFSET_PRESENT.set(true);
    WRITES.set(0);SYNCS.set(0);FAIL_WRITE.set(1);
    let bytes=Arc::new([0x5a;PAGE_BYTES]);
    *PAGE_CACHE.lock()=(0..count).map(|index|CachedPage{
        key:PageKey{object:ObjectKey::Memory(1),page_index:index as u64},
        bytes:Arc::clone(&bytes),frame_phys:resident.then_some(FRAME.as_ptr()as u64),
        dirty_range:Some((7,19)),version:1,last_used:0,
    }).collect();
    bytes
}
fn dirty(){assert!(!CACHE_LOCKED.get());assert!(!IO_LOCKED.get());
    assert!(PAGE_CACHE.lock().iter().all(|page|page.dirty_range==Some((7,19))));
}
fn main(){
    let object=VmObject{source:VmObjectSource::Provider{object:()}};
    for allocations in [0,1]{
        let bytes=reset(6,false);FAIL.set(Some(allocations));
        let result=object.flush_range(0,6*4096);FAIL.set(None);
        assert_eq!(result,Err(Error::ResourceUnavailable.into_raw()));
        dirty();assert_eq!(WRITES.get(),0);assert_eq!(SYNCS.get(),0);assert_eq!(Arc::strong_count(&bytes),7);
    }
    // The list reserve succeeds, but copying the resident frame cannot allocate.
    let bytes=reset(1,true);FAIL.set(Some(1));let result=object.flush_range(0,4096);FAIL.set(None);
    assert_eq!(result,Err(Error::ResourceUnavailable.into_raw()));dirty();
    assert_eq!(Arc::strong_count(&bytes),2);assert_eq!(WRITES.get(),0);
    reset(1,true);OFFSET_PRESENT.set(false);
    assert_eq!(object.flush_range(0,4096),Err(Error::BackingFailure.into_raw()));dirty();
    reset(1,false);SHORT.set(true);
    assert_eq!(object.flush_range(0,4096),Err(Error::BackingFailure.into_raw()));dirty();assert_eq!(SYNCS.get(),0);
    SHORT.set(false);assert_eq!(object.flush_range(0,4096),Ok(()));
    assert_eq!(PAGE_CACHE.lock()[0].dirty_range,None);
    for error in [Error::NotReady,Error::ResourceUnavailable,Error::BackingFailure]{
        reset(1,false);GATE_ERROR.set(Some(error));assert_eq!(object.flush_range(0,4096),Err(error.into_raw()));dirty();
        assert_eq!(WRITES.get(),0);
    }
    for error in [Error::AccessDenied.into_raw(),Error::PeerClosed.into_raw(),(-28i64)as u64]{
        reset(1,false);LOWER_ERROR.set(Some(error));assert_eq!(object.flush_range(0,4096),Err(error));dirty();
    }
    reset(2,false);LOWER_ERROR.set(Some(Error::BackingFailure.into_raw()));FAIL_WRITE.set(2);
    assert_eq!(object.flush_range(0,8192),Err(Error::BackingFailure.into_raw()));dirty();
    assert_eq!(WRITES.get(),2);assert_eq!(SYNCS.get(),0);
    reset(1,false);REWRITE.set(true);assert_eq!(object.flush_range(0,4096),Ok(()));dirty();
    reset(1,true);SHARED_FRAME.set(true);assert_eq!(object.flush_range(0,4096),Ok(()));dirty();
    reset(2,true);assert_eq!(object.flush_range(4096,4096),Ok(()));
    {let cache=PAGE_CACHE.lock();assert!(cache[0].dirty_range.is_some());assert_eq!(cache[1].dirty_range,None);}
    reset(1,false);SYNC_ERROR.set(Some(Error::BackingFailure.into_raw()));
    assert_eq!(object.flush_range(0,4096),Err(Error::BackingFailure.into_raw()));dirty();
    SYNC_ERROR.set(None);assert_eq!(object.flush_range(0,4096),Ok(()));
    assert_eq!(WRITES.get(),2);assert_eq!(PAGE_CACHE.lock()[0].dirty_range,None);
    for (offset,length) in [(u64::MAX,1),(4096,u64::MAX)]{
        reset(1,false);assert_eq!(object.flush_range(offset,length),Err(Error::InvalidArgument.into_raw()));dirty();
        assert_eq!(WRITES.get(),0);assert_eq!(SYNCS.get(),0);
    }
    for (index,range) in [(u64::MAX,(7,19)),(0,(19,7)),(0,(0,4097))]{
        reset(1,false);{let mut cache=PAGE_CACHE.lock();cache[0].key.page_index=index;cache[0].dirty_range=Some(range);}
        assert_eq!(object.flush_range(0,u64::MAX),Err(Error::BackingFailure.into_raw()));
        assert_eq!(WRITES.get(),0);assert!(!IO_LOCKED.get());assert!(!CACHE_LOCKED.get());
    }
    let memory=VmObject{source:VmObjectSource::Memory(())};
    assert_eq!(memory.flush_range(0,u64::MAX),Ok(()));
    assert_eq!(memory.flush_range(u64::MAX,1),Err(Error::InvalidArgument.into_raw()));
    assert_eq!(memory.flush_range(u64::MAX,0),Ok(()));
}
"#);
    probe::run_with_toolchain(&program, "nightly-2026-07-16");
}
