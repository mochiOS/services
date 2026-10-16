//! Execute the provider's production subscription and signal-state methods.
//! Only the thread-liveness and wake callbacks are controlled boundaries.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn provider_waiters_fail_without_mutation_and_wake_outside_the_state_lock() {
    let table = include_str!("../../../core/src/task/handle_table.rs");
    let mut program = String::from(
        r#"
#![allow(dead_code)]
extern crate alloc;
use std::{cell::{Cell,RefCell},sync::atomic::{AtomicBool,AtomicUsize,Ordering}};
static FAIL_NEXT:AtomicBool=AtomicBool::new(false);
static ALLOCS:AtomicUsize=AtomicUsize::new(0);
struct Allocator;
unsafe impl std::alloc::GlobalAlloc for Allocator {
    unsafe fn alloc(&self,l:std::alloc::Layout)->*mut u8 {
        ALLOCS.fetch_add(1,Ordering::Relaxed);
        if FAIL_NEXT.swap(false,Ordering::Relaxed){std::ptr::null_mut()}else{unsafe{std::alloc::System.alloc(l)}}
    }
    unsafe fn realloc(&self,p:*mut u8,l:std::alloc::Layout,n:usize)->*mut u8 {
        ALLOCS.fetch_add(1,Ordering::Relaxed);
        if FAIL_NEXT.swap(false,Ordering::Relaxed){std::ptr::null_mut()}else{unsafe{std::alloc::System.realloc(p,l,n)}}
    }
    unsafe fn dealloc(&self,p:*mut u8,l:std::alloc::Layout){unsafe{std::alloc::System.dealloc(p,l)}}
}
#[global_allocator]static ALLOCATOR:Allocator=Allocator;
thread_local! {
    static STALE:Cell<u64>=const{Cell::new(0)};
    static LOCKED:Cell<bool>=const{Cell::new(false)};
    static WOKEN:RefCell<[u64;64]>=const{RefCell::new([0;64])};
    static WAKE_COUNT:Cell<usize>=const{Cell::new(0)};
}
struct SpinLock<T>(std::sync::Mutex<T>);
impl<T> SpinLock<T> {
    fn new(value:T)->Self{Self(std::sync::Mutex::new(value))}
    fn lock(&self)->Guard<'_,T>{
        assert!(!LOCKED.replace(true));Guard(self.0.lock().unwrap())
    }
}
struct Guard<'a,T>(std::sync::MutexGuard<'a,T>);
impl<T>std::ops::Deref for Guard<'_,T>{type Target=T;fn deref(&self)->&T{&self.0}}
impl<T>std::ops::DerefMut for Guard<'_,T>{fn deref_mut(&mut self)->&mut T{&mut self.0}}
impl<T>Drop for Guard<'_,T>{fn drop(&mut self){assert!(LOCKED.replace(false));}}
mod task {
    pub fn thread_id_exists(id:u64)->bool{id!=crate::STALE.get()}
    pub fn wake_thread(id:ids::ThreadId){
        assert!(!crate::LOCKED.get(),"wake must not retain the provider lock");
        let count=crate::WAKE_COUNT.get();
        crate::WOKEN.with_borrow_mut(|woken|woken[count]=id.as_u64());
        crate::WAKE_COUNT.set(count+1);
    }
    pub mod ids {
        #[derive(Clone,Copy,Debug,PartialEq,Eq)]pub struct ThreadId(pub u64);
        impl ThreadId{pub fn as_u64(self)->u64{self.0}}
    }
    pub struct ThreadQueue;
    impl ThreadQueue {
"#,
    );
    probe::constants(
        &mut program,
        include_str!("../../../core/src/task/thread.rs"),
        &["MAX_THREADS"],
    );
    program.push_str("}\npub mod handle_table {\nuse alloc::vec::Vec;\nuse crate::*;\n");
    program.push_str(probe::between(
        table,
        "#[derive(Default)]\nstruct ProviderSignalState",
        "type ProviderKey",
    ));
    program.push_str("struct ProviderObject {signal_state:SpinLock<ProviderSignalState>}\nimpl ProviderObject {\n");
    program.push_str(probe::between(
        table,
        "    pub(crate) fn register_waiter(",
        "\npub(crate) fn register_provider_object(",
    ));
    program.push_str(r#"
pub fn run(){
    use super::ids::ThreadId;
    let provider=ProviderObject{signal_state:SpinLock::new(ProviderSignalState::default())};
    FAIL_NEXT.store(true,Ordering::Relaxed);
    assert!(!provider.register_waiter(ThreadId(1)));
    assert!(!FAIL_NEXT.load(Ordering::Relaxed));
    assert!(provider.signal_state.lock().waiters.is_empty());
    assert!(provider.register_waiter(ThreadId(1)));
    FAIL_NEXT.store(true,Ordering::Relaxed);
    assert!(provider.register_waiter(ThreadId(1)));
    provider.remove_waiter(ThreadId(99)); // Removing an absent subscription is harmless.
    assert!(FAIL_NEXT.swap(false,Ordering::Relaxed),"idempotence/removal must not allocate");
    let capacity=provider.signal_state.lock().waiters.capacity();
    for id in 2..=capacity as u64 {assert!(provider.register_waiter(ThreadId(id)));}
    FAIL_NEXT.store(true,Ordering::Relaxed);
    assert!(!provider.register_waiter(ThreadId(capacity as u64+1)));
    assert!(!FAIL_NEXT.load(Ordering::Relaxed));
    {
        let state=provider.signal_state.lock();assert_eq!(state.waiters.len(),capacity);
        for (index,id) in state.waiters.iter().enumerate(){assert_eq!(id.0,index as u64+1);}
    }
    // Drop stale generation identities before growing; their existing capacity
    // can be reused even when all subsequent allocations are denied.
    STALE.set(1);FAIL_NEXT.store(true,Ordering::Relaxed);
    assert!(provider.register_waiter(ThreadId(1001)));
    assert!(FAIL_NEXT.swap(false,Ordering::Relaxed));
    assert!(!provider.signal_state.lock().waiters.contains(&ThreadId(1)));
    STALE.set(0);provider.remove_waiter(ThreadId(1001));
    provider.remove_waiter(ThreadId(1001));
    for id in 1..=super::ThreadQueue::MAX_THREADS as u64 {assert!(provider.register_waiter(ThreadId(id)));}
    FAIL_NEXT.store(true,Ordering::Relaxed);
    assert!(provider.register_waiter(ThreadId(64)));
    assert!(!provider.register_waiter(ThreadId(65)));
    assert!(FAIL_NEXT.swap(false,Ordering::Relaxed),"capacity check must precede allocation");
    // An unchanged readiness word does not consume subscriptions or wake them.
    let before=ALLOCS.load(Ordering::Relaxed);
    provider.update_signals(0,0);assert_eq!(WAKE_COUNT.get(),0);
    assert_eq!(provider.signal_state.lock().waiters.len(),64);
    provider.update_signals(2,0);
    assert_eq!(WAKE_COUNT.get(),64);assert_eq!(provider.signal_state.lock().signals,2);
    assert!(provider.signal_state.lock().waiters.is_empty());
    for id in 1..=64 {assert!(WOKEN.with_borrow(|woken|woken.contains(&id)));}
    assert_eq!(ALLOCS.load(Ordering::Relaxed),before,"signal publication must not allocate");
    provider.update_signals(2,0);assert_eq!(WAKE_COUNT.get(),64);
    FAIL_NEXT.store(true,Ordering::Relaxed);
    assert!(!provider.register_waiter(ThreadId(1)),"notification transferred and released waiter storage");
    assert!(!FAIL_NEXT.load(Ordering::Relaxed));
    assert!(provider.signal_state.lock().waiters.is_empty());
    assert!(provider.register_waiter(ThreadId(1)));
    provider.remove_waiter(ThreadId(1));assert!(provider.signal_state.lock().waiters.is_empty());
}
}}
fn main(){task::handle_table::run();}
"#);
    probe::run(&program);
}
