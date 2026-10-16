//! Execute object-wait admission and cleanup with controlled scheduler,
//! readiness, usercopy and subscription backends. No CPU switch is simulated.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn storage_faults_and_partial_registration_leave_no_subscriptions_or_deadlines() {
    let handle = include_str!("../../../core/src/syscall/handle.rs");
    let abi = include_str!("../../../core/crates/abi/src/lib.rs");
    let mut program = String::from(
        "#![allow(dead_code)]\nextern crate alloc;\nextern crate self as mnu_abi;\npub mod status {\n",
    );
    program.push_str(include_str!("../../../core/crates/abi/src/status.rs"));
    program.push_str("}\n");
    program.push_str(probe::between(
        abi,
        "#[repr(C)]\n#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]\npub struct HandleWaitItem",
        "/// Native result returned by `WaitOnAddress`.",
    ));
    probe::constants(
        &mut program,
        abi,
        &["HANDLE_WAIT_POLL", "HANDLE_WAIT_INFINITE"],
    );
    program.push_str(r#"
use std::cell::Cell;
use std::sync::{Arc,Weak,OnceLock,atomic::{AtomicIsize,AtomicUsize,Ordering}};
use status::Error;
const EINVAL:u64=(-22i64)as u64;
const EFAULT:u64=(-14i64)as u64;
const EAGAIN:u64=(-11i64)as u64;
static FAIL:AtomicIsize=AtomicIsize::new(-1);
static ALLOCS:AtomicUsize=AtomicUsize::new(0);
struct Allocator;
fn fail()->bool {
    ALLOCS.fetch_add(1,Ordering::Relaxed);
    let next=FAIL.load(Ordering::Relaxed);
    if next<0{return false;}
    FAIL.store(next-1,Ordering::Relaxed);
    next==0
}
unsafe impl std::alloc::GlobalAlloc for Allocator {
    unsafe fn alloc(&self,l:std::alloc::Layout)->*mut u8 {
        if fail(){std::ptr::null_mut()}else{unsafe{std::alloc::System.alloc(l)}}
    }
    unsafe fn realloc(&self,p:*mut u8,l:std::alloc::Layout,n:usize)->*mut u8 {
        if fail(){std::ptr::null_mut()}else{unsafe{std::alloc::System.realloc(p,l,n)}}
    }
    unsafe fn dealloc(&self,p:*mut u8,l:std::alloc::Layout){unsafe{std::alloc::System.dealloc(p,l)}}
}
#[global_allocator]static ALLOCATOR:Allocator=Allocator;
thread_local! {
    static ACTIVE:Cell<u32>=const{Cell::new(0)};
    static LIFETIMES:Cell<usize>=const{Cell::new(0)};
    static ARMED:Cell<bool>=const{Cell::new(false)};
    static READY:Cell<bool>=const{Cell::new(false)};
    static UPCALL:Cell<bool>=const{Cell::new(false)};
    static COPY_FAILURE:Cell<bool>=const{Cell::new(false)};
    static READ_ERROR:Cell<Option<Error>>=const{Cell::new(None)};
    static LOOKUP_ERROR:Cell<Option<Error>>=const{Cell::new(None)};
    static WRITE_ERROR:Cell<Option<Error>>=const{Cell::new(None)};
    static CURRENT:Cell<bool>=const{Cell::new(true)};
    static GUARD_COPIES:Cell<usize>=const{Cell::new(0)};
    static GUARD_EXPECTED:Cell<u64>=const{Cell::new(5)};
    static GUARD_VALUE:Cell<u64>=const{Cell::new(5)};
    static GUARD_READS:Cell<usize>=const{Cell::new(0)};
    static STAGE:Cell<usize>=const{Cell::new(0)};
    static FAIL_STAGE:Cell<usize>=const{Cell::new(0)};
    static SCANS:Cell<usize>=const{Cell::new(0)};
    static FAIL_SCAN:Cell<usize>=const{Cell::new(0)};
    static SLEEPS:Cell<usize>=const{Cell::new(0)};
    static NOW:Cell<u64>=const{Cell::new(0)};
    static SIGNAL_ON_ARM:Cell<bool>=const{Cell::new(false)};
}
fn stage()->bool {let next=STAGE.get()+1;STAGE.set(next);next!=FAIL_STAGE.get()}
fn add(bit:u32){ACTIVE.set(ACTIVE.get()|bit)}
fn remove(bit:u32){ACTIVE.set(ACTIVE.get()&!bit)}
struct ProviderObject;
impl ProviderObject {
    fn register_waiter(&self,_:u64)->bool{if !stage(){return false;}add(8);true}
    fn remove_waiter(&self,_:u64){remove(8)}
}
struct HandleRights;impl HandleRights{const WAIT:Self=Self;}
enum KernelObject{MemoryAdmission(Arc<mem::vm_object::ProviderAdmission>),Other}
static ADMISSION:OnceLock<Arc<mem::vm_object::ProviderAdmission>>=OnceLock::new();
static FILE:OnceLock<Arc<task::FileHandle>>=OnceLock::new();
static PROVIDER:OnceLock<Arc<ProviderObject>>=OnceLock::new();
fn object_native(raw:u64,_:HandleRights)->Result<KernelObject,Error> {
    if let Some(error)=LOOKUP_ERROR.get(){return Err(error);}
    Ok(if raw==5{KernelObject::MemoryAdmission(ADMISSION.get().unwrap().clone())}else{KernelObject::Other})
}
fn provider_endpoint(_: &ProviderObject)->syscall::ipc::IpcEndpoint{syscall::ipc::IpcEndpoint(4)}
mod mem {pub mod vm_object{pub struct ProviderAdmission;}}
mod task {
    pub type ThreadId=u64;
    pub type ProcessId=u64;
    pub struct FileHandle;
    pub fn current_thread_id()->Option<u64>{crate::CURRENT.get().then_some(99)}
    pub fn register_process_exit_waiter(_:u64,_:u64)->bool{if !crate::stage(){return false;}crate::add(1);true}
    pub fn remove_process_exit_waiters(_:u64){crate::remove(1)}
    pub fn sleep_thread_unless_woken(_:u64)->bool{crate::SLEEPS.set(crate::SLEEPS.get()+1);true}
    pub fn yield_now(){crate::READY.set(true)}
}
mod syscall {
    pub fn copy_from_user_native(pointer:u64,bytes:&mut[u8])->Result<(),crate::Error> {
        if pointer==2 { crate::GUARD_COPIES.set(crate::GUARD_COPIES.get()+1); }
        if let Some(error)=crate::READ_ERROR.get(){return Err(error);}
        if pointer==0 || pointer.checked_add(bytes.len()as u64).is_none(){return Err(crate::Error::InvalidAddress);}
        if pointer==2 {
            assert_eq!(bytes.len(),16);
            bytes[..8].copy_from_slice(&8u64.to_ne_bytes());
            bytes[8..].copy_from_slice(&crate::GUARD_EXPECTED.get().to_ne_bytes());
            return Ok(());
        }
        let items:[crate::HandleWaitItem;5]=std::array::from_fn(|index|crate::HandleWaitItem{
            handle:index as u32+1,interests:1,..Default::default()
        });
        let source=unsafe{std::slice::from_raw_parts(items.as_ptr().cast::<u8>(),std::mem::size_of_val(&items))};
        bytes.copy_from_slice(&source[..bytes.len()]);Ok(())
    }
    pub fn copy_to_user_native(_:u64,bytes:&[u8])->Result<(),crate::Error>{
        if bytes.is_empty(){return Ok(());}
        if let Some(error)=crate::WRITE_ERROR.get(){return Err(error);}
        if crate::COPY_FAILURE.get(){Err(crate::Error::InvalidAddress)}else{Ok(())}
    }
    pub mod time {
        pub fn monotonic_deadline_tick(value:u64)->u64{value}
        pub fn monotonic_nanoseconds()->u64{crate::NOW.get()}
        pub fn disarm_thread_deadline(_:u64){crate::ARMED.set(false)}
        pub fn arm_thread_deadline(_:u64,_:u64)->bool{
            crate::ARMED.set(true);
            if crate::SIGNAL_ON_ARM.get(){crate::READY.set(true);}
            crate::stage()
        }
    }
    pub mod fs {
        pub fn register_stream_waiter(_: &crate::task::FileHandle,_:u64)->Result<usize,u64>{
            if !crate::stage(){return Err(crate::EAGAIN);}crate::add(4);Ok(3)
        }
        pub fn remove_stream_waiter(_:usize,_:u64){crate::remove(4)}
    }
    pub mod ipc {
        #[derive(Clone,Copy)]pub struct IpcEndpoint(pub u64);
        pub fn register_endpoint_waiter(_:IpcEndpoint,_:u64)->Result<(),u64>{
            if !crate::stage(){return Err(crate::Error::ResourceUnavailable.into_raw());}crate::add(2);Ok(())
        }
        pub fn remove_endpoint_waiter(_:IpcEndpoint,_:u64){crate::remove(2)}
        pub mod lifetime {
            pub struct Observation(u64);
            impl Drop for Observation{fn drop(&mut self){crate::LIFETIMES.set(crate::LIFETIMES.get()-1)}}
            pub fn observe(endpoint:super::IpcEndpoint,_:u64)->Result<Observation,u64>{
                if !crate::stage(){return Err(crate::Error::ResourceUnavailable.into_raw());}
                crate::LIFETIMES.set(crate::LIFETIMES.get()+1);Ok(Observation(endpoint.0))
            }
        }
    }
}
mod address_wait {
    pub fn read_guard_value(address:u64)->Result<u64,u64>{
        assert_eq!(address,8);crate::GUARD_READS.set(crate::GUARD_READS.get()+1);
        // A user may edit its descriptor after it was copied. Later predicate
        // checks must use the captured expected value, not reread that field.
        crate::GUARD_EXPECTED.set(999);Ok(crate::GUARD_VALUE.get())
    }
    pub fn register_guard(_:u64,_:u64,_:u64)->Result<usize,u64>{Ok(0)}
}
mod upcall{pub fn current_has_deliverable_upcall()->bool{crate::UPCALL.get()}}
mod memory_update {
    pub fn admission_endpoint(_: &crate::mem::vm_object::ProviderAdmission)->crate::syscall::ipc::IpcEndpoint{crate::syscall::ipc::IpcEndpoint(5)}
    pub struct AdmissionWaiter(u64);
    impl AdmissionWaiter {
        pub fn register(_:std::sync::Arc<crate::mem::vm_object::ProviderAdmission>,thread:u64)->Result<Self,u64>{
            if !crate::stage(){return Err(crate::EAGAIN);}crate::add(16);Ok(Self(thread))
        }
    }
    impl Drop for AdmissionWaiter{fn drop(&mut self){crate::remove(16)}}
}
mod handle {
use crate::*;
"#);
    program.push_str(probe::between(
        handle,
        "#[derive(Clone)]\nenum WaitTarget",
        "fn wait_item_signal(",
    ));
    program.push_str(r#"
fn wait_item_signal(item:&mut HandleWaitItem,_:Option<&Weak<mem::vm_object::ProviderAdmission>>)->Result<(WaitTarget,bool),u64>{
    let scan=SCANS.get()+1;SCANS.set(scan);
    if scan==FAIL_SCAN.get(){return Err(EINVAL);}
    let target=match item.handle {
        1=>WaitTarget::Process(1),2=>WaitTarget::IpcEndpoint(syscall::ipc::IpcEndpoint(2)),
        3=>WaitTarget::Stream(FILE.get().unwrap().clone()),4=>WaitTarget::Provider(PROVIDER.get().unwrap().clone()),
        5=>WaitTarget::MemoryAdmission(ADMISSION.get().unwrap().clone()),_=>unreachable!(),
    };
    item.observed=u64::from(READY.get());Ok((target,READY.get()))
}
"#);
    program.push_str(probe::between(
        handle,
        "fn remove_endpoint_waiters(",
        "pub fn process_resume(",
    ));
    program.push_str(r#"
}
fn clean(){
    assert_eq!(ACTIVE.get(),0);assert_eq!(LIFETIMES.get(),0);assert!(!ARMED.get());
    assert_eq!(Arc::strong_count(ADMISSION.get().unwrap()),1);
    assert_eq!(Arc::strong_count(FILE.get().unwrap()),1);
    assert_eq!(Arc::strong_count(PROVIDER.get().unwrap()),1);
}
fn reset(){
    clean();READY.set(false);UPCALL.set(false);COPY_FAILURE.set(false);
    READ_ERROR.set(None);LOOKUP_ERROR.set(None);WRITE_ERROR.set(None);CURRENT.set(true);
    GUARD_COPIES.set(0);GUARD_READS.set(0);GUARD_EXPECTED.set(5);GUARD_VALUE.set(5);
    STAGE.set(0);FAIL_STAGE.set(0);SCANS.set(0);FAIL_SCAN.set(0);SLEEPS.set(0);
    NOW.set(0);SIGNAL_ON_ARM.set(false);
}
fn main(){
    ADMISSION.set(Arc::new(mem::vm_object::ProviderAdmission)).ok().unwrap();
    FILE.set(Arc::new(task::FileHandle)).ok().unwrap();PROVIDER.set(Arc::new(ProviderObject)).ok().unwrap();
    // Eight actual allocation sites: items, three explicit registries,
    // endpoint observations, admission guards, identity sources and targets.
    for index in 0..8 {
        reset();FAIL.store(index,Ordering::Relaxed);
        let result=handle::wait_many(1,5,100,0);
        FAIL.store(-1,Ordering::Relaxed);
        assert_eq!(result,Error::ResourceUnavailable.into_raw());assert_eq!(STAGE.get(),0);clean();
    }
    // Fail every subscription backend and deadline admission. The deadline
    // backend deliberately arms before failing, to exercise unconditional Drop.
    for index in 1..=8 {
        reset();FAIL_STAGE.set(index);
        let expected=if [1,2,4,5,6,8].contains(&index){Error::ResourceUnavailable.into_raw()}else{EAGAIN};
        assert_eq!(handle::wait_many(1,5,100,0),expected);clean();assert_eq!(SLEEPS.get(),0);
    }
    // Failure during the post-registration readiness scan must clean all kinds.
    reset();FAIL_SCAN.set(6);assert_eq!(handle::wait_many(1,5,100,0),EINVAL);clean();
    reset();let before=ALLOCS.load(Ordering::Relaxed);
    assert_eq!(handle::wait_many(1,5,100,0),0);
    assert_eq!(ALLOCS.load(Ordering::Relaxed)-before,8,"retry must reuse reserved storage");
    assert_eq!(SLEEPS.get(),1);clean();
    reset();COPY_FAILURE.set(true);assert_eq!(handle::wait_many(1,5,100,0),Error::InvalidAddress.into_raw());clean();
    reset();UPCALL.set(true);assert_eq!(handle::wait_many(1,5,100,0),Error::NotReady.into_raw());clean();
    reset();assert_eq!(handle::wait_many(1,5,0,0),Error::NotReady.into_raw());clean();
    reset();assert_eq!(handle::wait_many(0,0,0,0),Error::NotReady.into_raw());clean();
    reset();NOW.set(100);assert_eq!(handle::wait_many(1,5,100,0),Error::NotReady.into_raw());
    assert_eq!(STAGE.get(),0);assert_eq!(SLEEPS.get(),0);clean();
    reset();NOW.set(101);assert_eq!(handle::wait_many(0,0,100,0),Error::NotReady.into_raw());clean();
    reset();UPCALL.set(true);READY.set(true);assert_eq!(handle::wait_many(1,5,0,0),0);clean();
    reset();SIGNAL_ON_ARM.set(true);assert_eq!(handle::wait_many(1,5,100,0),0);
    assert_eq!(SLEEPS.get(),0);clean();
    // Preserve each native resident/fault-in error at all three copy phases.
    for error in [Error::InvalidAddress,Error::ResourceUnavailable,Error::BackingFailure] {
        reset();READ_ERROR.set(Some(error));
        assert_eq!(handle::wait_many(1,5,100,0),error.into_raw());
        assert_eq!(STAGE.get(),0);clean();
        reset();READ_ERROR.set(Some(error));let before=ALLOCS.load(Ordering::Relaxed);
        assert_eq!(handle::wait_many(1,5,100,2),error.into_raw());
        assert_eq!(ALLOCS.load(Ordering::Relaxed),before);assert_eq!(GUARD_COPIES.get(),1);
        assert_eq!(GUARD_READS.get(),0);clean();
        reset();WRITE_ERROR.set(Some(error));
        assert_eq!(handle::wait_many(1,5,100,0),error.into_raw());
        assert_eq!(SLEEPS.get(),1);clean();
    }
    reset();assert_eq!(handle::wait_many(1,65,0,0),Error::InvalidArgument.into_raw());clean();
    reset();assert_eq!(handle::wait_many(0,5,0,0),Error::InvalidAddress.into_raw());clean();
    reset();assert_eq!(handle::wait_many(1,5,0,u64::MAX),Error::InvalidAddress.into_raw());clean();
    reset();CURRENT.set(false);assert_eq!(handle::wait_many(1,5,100,0),Error::NotReady.into_raw());clean();
    for error in [Error::InvalidArgument,Error::AccessDenied,Error::NotReady] {
        reset();LOOKUP_ERROR.set(Some(error));
        assert_eq!(handle::wait_many(1,5,100,0),error.into_raw());
        assert_eq!(STAGE.get(),0);clean();
    }
    reset();assert_eq!(handle::wait_many(1,5,100,2),0);
    assert_eq!(GUARD_COPIES.get(),1);assert!(GUARD_READS.get()>1);clean();
    reset();GUARD_VALUE.set(6);
    assert_eq!(handle::wait_many(1,5,100,2),Error::NotReady.into_raw());
    assert_eq!(GUARD_COPIES.get(),1);assert_eq!(SLEEPS.get(),0);clean();
}
"#);
    probe::run(&program);
}
