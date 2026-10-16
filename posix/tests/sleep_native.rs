//! Execute the production deadline queue and Sleep wrapper with a controlled
//! scheduler. This verifies admission/error propagation, not real switching.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn sleep_preserves_native_admission_failures_and_deadline_semantics() {
    let source = include_str!("../../../core/src/syscall/time.rs");
    let mut program = probe::program();
    program.push_str(r#"
use mnu_abi::status::Error;
use std::cell::{Cell,RefCell};
const SUCCESS:u64=0;
thread_local! {
    static NOW:Cell<u64>=const{Cell::new(10)};
    static CURRENT:Cell<Option<u64>>=const{Cell::new(Some(7))};
    static CRITICAL:Cell<bool>=const{Cell::new(false)};
    static SLEPT:RefCell<Vec<u64>>=const{RefCell::new(Vec::new())};
    static WOKEN:RefCell<Vec<u64>>=const{RefCell::new(Vec::new())};
    static YIELDS:Cell<usize>=const{Cell::new(0)};
}
mod instructions {pub mod interrupts {
    pub fn without_interrupts<T>(operation:impl FnOnce()->T)->T {
        assert!(!crate::CRITICAL.replace(true));
        let result=operation();
        assert!(crate::CRITICAL.replace(false));result
    }
}}
mod interrupt {
    pub mod spinlock {
        pub struct SpinLock<T>(std::sync::Mutex<T>);
        impl<T> SpinLock<T>{
            pub const fn new(value:T)->Self{Self(std::sync::Mutex::new(value))}
            pub fn lock(&self)->std::sync::MutexGuard<'_,T>{self.0.lock().unwrap()}
        }
    }
    pub mod timer {
        pub fn ms_to_ticks_ceil(milliseconds:u64)->u64{milliseconds.div_ceil(5)}
    }
}
mod task {
    pub type ThreadId=u64;
    pub struct ThreadQueue;
    impl ThreadQueue{pub const MAX_THREADS:usize=2;}
    pub fn current_thread_id()->Option<ThreadId>{crate::CURRENT.get()}
    pub fn sleep_thread(tid:ThreadId){
        assert!(crate::CRITICAL.get());crate::SLEPT.with_borrow_mut(|items|items.push(tid));
    }
    pub fn yield_now(){
        assert!(!crate::CRITICAL.get());crate::YIELDS.set(crate::YIELDS.get()+1);
        crate::NOW.set(crate::NOW.get().saturating_add(1));
    }
    pub fn wake_registered_waiter(tid:ThreadId){crate::WOKEN.with_borrow_mut(|items|items.push(tid));}
}
mod syscall {pub mod time {
    use crate::{Error,interrupt::spinlock::SpinLock,task::ThreadId};
    use crate as x86_64;
    use core::sync::atomic::{AtomicU64,Ordering};
"#);
    program.push_str(probe::between(
        source,
        "const NO_DEADLINE:",
        "#[derive(Clone, Copy, Debug",
    ));
    program.push_str(probe::between(
        source,
        "#[derive(Clone, Copy)]\nstruct SleepEntry",
        "/// GetTicks",
    ));
    program.push_str("pub fn get_ticks()->u64{crate::NOW.get()}\n");
    program.push_str(&source[source.find("pub fn sleep_until(").unwrap()..]);
    program.push_str("}}\n");
    program.push_str(probe::between(
        include_str!("../../../core/src/syscall/process.rs"),
        "pub fn sleep(milliseconds:",
        "/// Resolve a write-authorized",
    ));
    program.push_str(
        r#"
fn reset(){
    for tid in [1,2,3,7]{syscall::time::disarm_thread_deadline(tid);}
    NOW.set(10);CURRENT.set(Some(7));YIELDS.set(0);
    SLEPT.with_borrow_mut(Vec::clear);WOKEN.with_borrow_mut(Vec::clear);
}
fn main(){
    reset();CURRENT.set(None);
    assert_eq!(syscall::time::sleep_until(10),Ok(()));
    assert_eq!(syscall::time::sleep_until(9),Ok(()));
    assert_eq!(syscall::time::sleep_until(11),Err(Error::NotReady));
    assert_eq!(sleep(1),Error::NotReady.into_raw());
    assert_eq!(YIELDS.get(),0);SLEPT.with_borrow(|items|assert!(items.is_empty()));
    // Zero-duration Sleep remains a yield, even without a selected thread.
    assert_eq!(sleep(0),0);assert_eq!(YIELDS.get(),1);

    reset();
    assert!(syscall::time::arm_thread_deadline(1,20));
    assert!(syscall::time::arm_thread_deadline(2,30));
    assert_eq!(syscall::time::sleep_until(12),Err(Error::ResourceUnavailable));
    assert_eq!(sleep(6),Error::ResourceUnavailable.into_raw());
    assert_eq!(NOW.get(),10);assert_eq!(YIELDS.get(),0);
    SLEPT.with_borrow(|items|assert!(items.is_empty()));
    // Failure must not overwrite an existing waiter's deadline.
    syscall::time::wake_due_sleepers(19);
    WOKEN.with_borrow(|items|assert!(items.is_empty()));
    syscall::time::wake_due_sleepers(20);
    WOKEN.with_borrow(|items|assert_eq!(items,&[1]));
    syscall::time::wake_due_sleepers(30);
    WOKEN.with_borrow(|items|assert_eq!(items,&[1,2]));

    reset();
    assert_eq!(sleep(6),0);assert_eq!(NOW.get(),12);assert_eq!(YIELDS.get(),2);
    SLEPT.with_borrow(|items|assert_eq!(items,&[7]));
    syscall::time::wake_due_sleepers(11);
    WOKEN.with_borrow(|items|assert!(items.is_empty()));
    syscall::time::wake_due_sleepers(12);
    WOKEN.with_borrow(|items|assert_eq!(items,&[7]));

    reset();
    assert!(syscall::time::arm_thread_deadline(7,50));
    assert!(syscall::time::arm_thread_deadline(2,60));
    assert_eq!(syscall::time::sleep_until(12),Ok(()));
    syscall::time::wake_due_sleepers(12);
    WOKEN.with_borrow(|items|assert_eq!(items,&[7]));
    syscall::time::wake_due_sleepers(59);
    WOKEN.with_borrow(|items|assert_eq!(items,&[7]));
    syscall::time::wake_due_sleepers(60);
    WOKEN.with_borrow(|items|assert_eq!(items,&[7,2]));

    reset();NOW.set(u64::MAX-1);
    assert_eq!(sleep(u64::MAX),0);assert_eq!(NOW.get(),u64::MAX);
    assert_eq!(YIELDS.get(),1);
    syscall::time::wake_due_sleepers(u64::MAX);
    WOKEN.with_borrow(|items|assert_eq!(items,&[7]));
}
"#,
    );
    probe::run(&program);
}
