#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn actual_clone_dispatcher_keeps_vm_lock_through_cow_sync_and_publication() {
    let source = include_str!("../../../core/src/syscall/process.rs");
    let start = source
        .find("pub fn clone_address_space() -> u64 {")
        .unwrap();
    let end = source[start..].find("/// Suspends every thread").unwrap() + start;
    let mut program = String::from(
        r#"
#![feature(allocator_api)]
#![allow(dead_code)]
extern crate alloc;
use alloc::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
static FAIL_ALLOCATION:AtomicBool=AtomicBool::new(false);
struct Allocator;
unsafe impl std::alloc::GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout:std::alloc::Layout)->*mut u8 {
        if FAIL_ALLOCATION.swap(false,Ordering::Relaxed) {return std::ptr::null_mut();}
        unsafe {std::alloc::System.alloc(layout)}
    }
    unsafe fn dealloc(&self,p:*mut u8,layout:std::alloc::Layout){unsafe {std::alloc::System.dealloc(p,layout)}}
}
#[global_allocator] static ALLOCATOR:Allocator=Allocator;
static LOCKED:AtomicBool=AtomicBool::new(false);
static MODE:AtomicUsize=AtomicUsize::new(0);
static LIVE:AtomicUsize=AtomicUsize::new(1);
static ALLOWED:AtomicBool=AtomicBool::new(true);
static SYNCED:AtomicBool=AtomicBool::new(false);
static IMAGES:AtomicUsize=AtomicUsize::new(0);
static QUIESCENT:AtomicBool=AtomicBool::new(false);
fn caller_has_process_spawn_capability()->bool { ALLOWED.load(Ordering::Acquire) }
mod interrupt { pub mod spinlock {
    pub struct SpinLock<T>(std::sync::Mutex<T>);
    impl<T> SpinLock<T> {
        pub const fn new(value:T)->Self { Self(std::sync::Mutex::new(value)) }
        pub fn lock(&self)->std::sync::MutexGuard<'_,T> { self.0.lock().unwrap() }
    }
} }
mod syscall {
    pub mod security { pub fn current_process_id()->Option<u64> {
        (crate::MODE.load(crate::Ordering::Acquire)!=12).then_some(1)
    } }
}
mod mem {
    pub mod tlb_shootdown { pub fn invalidate_all()->Result<(),()> {
        assert!(crate::LOCKED.load(crate::Ordering::Acquire));
        crate::SYNCED.store(true, crate::Ordering::Release);
        if crate::MODE.load(crate::Ordering::Acquire)==3 {Err(())} else {Ok(())}
    } }
    pub mod address_space {
        pub enum CloneError { BorrowedMapping, Backing(crate::mnu_abi::status::Error), MissingPageTable, Allocation }
        pub struct CloneSource;
        pub struct Image;
        impl Drop for Image {fn drop(&mut self) {
            assert!(crate::LOCKED.load(crate::Ordering::Acquire));
            crate::IMAGES.fetch_sub(1,crate::Ordering::Release);
        }}
        impl CloneSource {
            pub fn capture(_: &crate::task::Process)->Result<Self,CloneError> {
                assert!(crate::LOCKED.load(crate::Ordering::Acquire));
                assert!(crate::QUIESCENT.load(crate::Ordering::Acquire));
                match crate::MODE.load(crate::Ordering::Acquire) {
                    1 => Err(CloneError::BorrowedMapping),
                    5 => Err(CloneError::Backing(crate::mnu_abi::status::Error::NotReady)),
                    8 => Err(CloneError::Backing(crate::mnu_abi::status::Error::BackingFailure)),
                    9 => Err(CloneError::Backing(crate::mnu_abi::status::Error::AccessDenied)),
                    10 => Err(CloneError::Backing(crate::mnu_abi::status::Error::ResourceUnavailable)),
                    6 => Err(CloneError::Allocation),
                    7 => Err(CloneError::MissingPageTable),
                    _ => Ok(Self),
                }
            }
            pub fn clone_image(self)->Result<Image,CloneError> {
                assert!(crate::LOCKED.load(crate::Ordering::Acquire));
                if crate::MODE.load(crate::Ordering::Acquire)==2 {return Err(CloneError::Allocation)}
                crate::IMAGES.fetch_add(1,crate::Ordering::Release);
                if crate::MODE.load(crate::Ordering::Acquire)==11 {
                    crate::FAIL_ALLOCATION.store(true,crate::Ordering::Release);
                }
                Ok(Image)
            }
        }
        pub struct AddressSpaceObject(pub Image);
        impl AddressSpaceObject {pub fn new(image:Image)->Self {Self(image)}}
    }
}
mod task {
    pub type ProcessId = u64;
    pub fn current_thread_id()->Option<u64> {
        (crate::MODE.load(crate::Ordering::Acquire)!=13).then_some(1)
    }
    #[path="@IMAGE_TRANSITION@"] pub mod image_transition;
    pub mod scheduler {
        pub struct Quiescence;
        impl Drop for Quiescence { fn drop(&mut self) {
            assert!(!crate::LOCKED.load(crate::Ordering::Acquire));
            assert!(crate::QUIESCENT.swap(false,crate::Ordering::AcqRel));
        } }
        pub fn quiesce_image_siblings(pid:u64, owner:u64)->Quiescence {
            assert_eq!((pid,owner),(1,1));
            assert!(super::image_transition::begin_thread_creation(pid).is_none());
            assert!(!crate::QUIESCENT.swap(true,crate::Ordering::AcqRel));
            Quiescence
        }
    }
    #[derive(Clone,Copy)] pub struct HandleRights(pub u64);
    impl HandleRights {
        pub const CONTROL:Self=Self(1); pub const DUPLICATE:Self=Self(2); pub const TRANSFER:Self=Self(4);
        pub fn union(self, other:Self)->Self {Self(self.0|other.0)}
    }
    pub enum KernelObject { AddressSpace(crate::Arc<crate::mem::address_space::AddressSpaceObject>) }
    pub struct ObjectHandleEntry(pub KernelObject, pub HandleRights);
    impl ObjectHandleEntry {pub fn new(object:KernelObject, rights:HandleRights)->Self {Self(object,rights)}}
    pub struct Handle; impl Handle {pub fn raw(&self)->u32 {7}}
    pub struct Handles(Vec<ObjectHandleEntry>);
    impl Handles {pub fn insert(&mut self, entry:ObjectHandleEntry)->Result<Handle,()> {
        assert!(crate::LOCKED.load(crate::Ordering::Acquire));
        assert!(crate::SYNCED.load(crate::Ordering::Acquire)); assert_eq!(entry.1.0,7);
        if crate::MODE.load(crate::Ordering::Acquire)==4 {return Err(())}
        self.0.push(entry); Ok(Handle)
    }}
    pub struct Process(Handles);
    impl Process {pub fn object_handles_mut(&mut self)->&mut Handles {&mut self.0}}
    pub fn with_process_mut<T>(pid:u64, f:impl FnOnce(&mut Process)->T)->Option<T> {
        if crate::MODE.load(crate::Ordering::Acquire)==14 {return None;}
        assert_eq!(pid,1); assert!(!crate::LOCKED.swap(true,crate::Ordering::AcqRel));
        let mut process=Process(Handles(Vec::new())); let value=f(&mut process); drop(process);
        crate::LOCKED.store(false,crate::Ordering::Release); Some(value)
    }
}
"#,
    );
    let transition = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../core/src/task/image_transition.rs")
        .canonicalize()
        .unwrap();
    program = program.replace("@IMAGE_TRANSITION@", transition.to_str().unwrap());
    program.push_str(&source[start..end]);
    program.push_str(r#"
fn main() {
    use mnu_abi::status::Error;
    for (mode, expected, sync) in [(0,7,true),(1,Error::AccessDenied.into_raw(),false),
        (2,Error::ResourceUnavailable.into_raw(),true),(3,Error::BackingFailure.into_raw(),true),
        (4,Error::ResourceUnavailable.into_raw(),true),(5,Error::NotReady.into_raw(),false),
        (6,Error::ResourceUnavailable.into_raw(),false),(7,Error::NotReady.into_raw(),false),
        (8,Error::BackingFailure.into_raw(),false),(9,Error::AccessDenied.into_raw(),false),
        (10,Error::ResourceUnavailable.into_raw(),false),(11,Error::ResourceUnavailable.into_raw(),true),
        (12,Error::NotReady.into_raw(),false),(13,Error::NotReady.into_raw(),false),
        (14,Error::NotReady.into_raw(),false)] {
        MODE.store(mode,Ordering::Release); SYNCED.store(false,Ordering::Release);
        assert_eq!(clone_address_space(),expected);
        assert_eq!(SYNCED.load(Ordering::Acquire),sync);
        assert!(!LOCKED.load(Ordering::Acquire)); assert_eq!(IMAGES.load(Ordering::Acquire),0);
        assert!(!QUIESCENT.load(Ordering::Acquire));
        assert!(task::image_transition::begin_thread_creation(1).is_some());
        assert!(!FAIL_ALLOCATION.load(Ordering::Acquire));
    }
    MODE.store(0,Ordering::Release);
    let creating=task::image_transition::begin_thread_creation(1).unwrap();
    SYNCED.store(false,Ordering::Release);
    assert_eq!(clone_address_space(),Error::NotReady.into_raw()); assert!(!SYNCED.load(Ordering::Acquire));
    assert!(!QUIESCENT.load(Ordering::Acquire));
    drop(creating);
    assert_eq!(clone_address_space(),7);
    ALLOWED.store(false,Ordering::Release); assert_eq!(clone_address_space(),Error::AccessDenied.into_raw());
}
"#);
    program.push_str("\nmod mnu_abi {pub mod status {\n");
    program.push_str(include_str!("../../../core/crates/abi/src/status.rs"));
    program.push_str("\n}}\n");
    probe::run_with_toolchain(&program, "nightly-2026-07-16");
}
