//! Real owned-work state machine and writeback batch. This does not claim a
//! running kernel executor or enabled asynchronous MemorySync ABI.
#![feature(allocator_api)]
#![allow(dead_code)]
extern crate alloc;
extern crate self as mnu_abi;

#[path = "../../../core/crates/abi/src/status.rs"]
pub mod status;
#[path = "../../../core/src/task/owned_work.rs"]
mod work;
#[path = "../../../core/src/mem/writeback.rs"]
mod writeback;

use status::Error;
use std::{
    cell::Cell,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use work::{Completion, Prepared, Queue};

thread_local! {
    static DENY:Cell<bool>=const{Cell::new(false)};
    static LOCKED:Cell<bool>=const{Cell::new(false)};
}
struct Allocator;
unsafe impl std::alloc::GlobalAlloc for Allocator {
    unsafe fn alloc(&self, l: std::alloc::Layout) -> *mut u8 {
        if DENY.try_with(Cell::get).unwrap_or(false) {
            return std::ptr::null_mut();
        }
        unsafe { std::alloc::System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: std::alloc::Layout) {
        unsafe { std::alloc::System.dealloc(p, l) }
    }
}
#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

fn editing<R>(f: impl FnOnce() -> R) -> R {
    assert!(!LOCKED.replace(true));
    DENY.set(true);
    let result = f();
    DENY.set(false);
    LOCKED.set(false);
    result
}
fn prepare<T>(value: T) -> Prepared<T> {
    match Prepared::new(value) {
        Ok(value) => value,
        Err(_) => panic!("unexpected allocation failure"),
    }
}
fn submit<T, const N: usize>(queue: &mut Queue<T, N>, value: T) {
    let prepared = prepare(value);
    assert!(editing(|| queue.submit(prepared)).is_ok());
}
fn retired<T>(completion: Result<Completion<T>, work::Claim<T>>) -> work::Retired<T> {
    match completion {
        Ok(Completion::Retired(retired)) => retired,
        _ => panic!("not retired"),
    }
}
struct Backing {
    id: u64,
    drops: Arc<AtomicUsize>,
}
impl Drop for Backing {
    fn drop(&mut self) {
        assert!(!LOCKED.get(), "payload destruction under queue lock");
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn owned_backing_survives_mapping_replacement_until_retirement_outside_lock() {
    let drops = Arc::new(AtomicUsize::new(0));
    let backing = Arc::new(Backing {
        id: 17,
        drops: Arc::clone(&drops),
    });
    let weak = Arc::downgrade(&backing);
    let batch = writeback::Batch::new(vec![((Arc::clone(&backing), 8192), 4096)]);
    let mut queue = Queue::<_, 1>::new();
    submit(&mut queue, batch);
    drop(backing);
    assert!(weak.upgrade().is_some());
    let claim = editing(|| queue.claim()).unwrap();
    let mut observed = Vec::new();
    assert_eq!(
        claim.value().execute(|target, offset, len| {
            assert!(!LOCKED.get());
            observed.push((target.id, offset, len));
            Ok(())
        }),
        Ok(())
    );
    assert_eq!(observed, [(17, 8192, 4096)]);
    let retired = retired(editing(|| queue.complete(claim, Ok(()))));
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    assert!(weak.upgrade().is_some());
    drop(retired);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert!(weak.upgrade().is_none());
}

#[test]
fn running_and_failed_jobs_count_toward_capacity_and_retry_is_explicit_fifo() {
    let mut queue = Queue::<u64, 2>::new();
    submit(&mut queue, 1);
    submit(&mut queue, 2);
    let first = editing(|| queue.claim()).unwrap();
    assert_eq!(*first.value(), 1);
    let third = prepare(3);
    let rejected = match editing(|| queue.submit(third)) {
        Err((error, owner)) => {
            assert_eq!(error, Error::ResourceUnavailable);
            owner
        }
        _ => panic!("running work escaped capacity"),
    };
    let first = match editing(|| queue.complete(first, Err(Error::BackingFailure.into_raw()))) {
        Ok(Completion::Failed { error, claim }) => {
            assert_eq!(error, Error::BackingFailure.into_raw());
            claim
        }
        _ => panic!("failure lost"),
    };
    let rejected = match editing(|| queue.submit(rejected)) {
        Err((_, owner)) => owner,
        _ => panic!("failed work escaped capacity"),
    };
    assert!(editing(|| queue.retry(first)).is_ok());
    let second = editing(|| queue.claim()).unwrap();
    assert_eq!(*second.value(), 2);
    let first = editing(|| queue.claim()).unwrap();
    assert_eq!(*first.value(), 1);
    assert!(editing(|| queue.claim()).is_none());
    drop(retired(editing(|| queue.complete(second, Ok(())))));
    assert!(editing(|| queue.submit(rejected)).is_ok());
    let third = editing(|| queue.claim()).unwrap();
    assert_eq!(*third.value(), 3);
    drop(retired(editing(|| queue.complete(first, Ok(())))));
    drop(retired(editing(|| queue.complete(third, Ok(())))));
}

#[test]
fn allocation_and_admission_failure_return_the_original_owner() {
    let drops = Arc::new(AtomicUsize::new(0));
    let value = Backing {
        id: 7,
        drops: Arc::clone(&drops),
    };
    DENY.set(true);
    let result = Prepared::new(value);
    DENY.set(false);
    let value = match result {
        Err((error, value)) => {
            assert_eq!(error, Error::ResourceUnavailable);
            value
        }
        _ => panic!("allocation was not fallible"),
    };
    assert_eq!(value.id, 7);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    let mut queue = Queue::<Backing, 0>::new();
    let prepared = prepare(value);
    let rejected = match editing(|| queue.submit(prepared)) {
        Err((error, owner)) => {
            assert_eq!(error, Error::ResourceUnavailable);
            owner
        }
        _ => panic!("zero capacity accepted work"),
    };
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    drop(rejected);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[test]
fn foreign_claim_cannot_complete_or_retry_another_queues_work() {
    let mut a = Queue::<u64, 1>::new();
    let mut b = Queue::<u64, 1>::new();
    submit(&mut a, 1);
    submit(&mut b, 2);
    let first = editing(|| a.claim()).unwrap();
    let second = editing(|| b.claim()).unwrap();
    let first = match editing(|| b.complete(first, Ok(()))) {
        Err(claim) => claim,
        _ => panic!("foreign completion accepted"),
    };
    let first = match editing(|| b.retry(first)) {
        Err(claim) => claim,
        _ => panic!("foreign retry accepted"),
    };
    let first = match editing(|| a.retry(first)) {
        Err(claim) => claim,
        _ => panic!("running retry accepted"),
    };
    assert_eq!(*first.value(), 1);
    assert_eq!(*second.value(), 2);
    drop(retired(editing(|| a.complete(first, Ok(())))));
    drop(retired(editing(|| b.complete(second, Ok(())))));
}

#[test]
fn losing_a_claim_does_not_report_completion_or_release_the_backing() {
    let drops = Arc::new(AtomicUsize::new(0));
    let mut queue = Queue::<Backing, 1>::new();
    submit(
        &mut queue,
        Backing {
            id: 9,
            drops: Arc::clone(&drops),
        },
    );
    drop(editing(|| queue.claim()).unwrap());
    assert!(editing(|| queue.claim()).is_none());
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    let another = prepare(Backing {
        id: 10,
        drops: Arc::clone(&drops),
    });
    let rejected = editing(|| queue.submit(another));
    assert!(rejected.is_err());
    drop(rejected);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    drop(queue);
    assert_eq!(drops.load(Ordering::SeqCst), 2);
}

#[test]
fn failed_batch_retains_all_targets_and_never_executes_a_later_span() {
    let batch = writeback::Batch::new(vec![
        ((17, 8192), 4096),
        ((23, 65536), 8192),
        ((29, 0), 4096),
    ]);
    let mut queue = Queue::<_, 1>::new();
    submit(&mut queue, batch);
    let claim = editing(|| queue.claim()).unwrap();
    let mut seen = Vec::new();
    let result = claim.value().execute(|id, offset, len| {
        seen.push((*id, offset, len));
        if *id == 23 {
            Err(Error::NotReady.into_raw())
        } else {
            Ok(())
        }
    });
    assert_eq!(seen, [(17, 8192, 4096), (23, 65536, 8192)]);
    let claim = match editing(|| queue.complete(claim, result)) {
        Ok(Completion::Failed { claim, .. }) => claim,
        _ => panic!("batch failure lost"),
    };
    assert!(editing(|| queue.claim()).is_none());
    assert!(editing(|| queue.retry(claim)).is_ok());
    let claim = editing(|| queue.claim()).unwrap();
    seen.clear();
    assert_eq!(
        claim.value().execute(|id, offset, len| {
            seen.push((*id, offset, len));
            Ok(())
        }),
        Ok(())
    );
    assert_eq!(seen, [(17, 8192, 4096), (23, 65536, 8192), (29, 0, 4096)]);
    drop(retired(editing(|| queue.complete(claim, Ok(())))));
}

#[test]
fn acknowledged_failure_releases_capacity_but_cleanup_waits_until_after_unlock() {
    let drops = Arc::new(AtomicUsize::new(0));
    let mut queue = Queue::<Backing, 1>::new();
    submit(
        &mut queue,
        Backing {
            id: 31,
            drops: Arc::clone(&drops),
        },
    );
    let claim = editing(|| queue.claim()).unwrap();
    let raw = Error::BackingFailure.into_raw();
    let claim = match editing(|| queue.complete(claim, Err(raw))) {
        Ok(Completion::Failed { error, claim }) => {
            assert_eq!(error, raw);
            claim
        }
        _ => panic!("failure lost"),
    };
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    let (error, retired) = match editing(|| queue.acknowledge_failure(claim)) {
        Ok(result) => result,
        Err(_) => panic!("acknowledgement rejected"),
    };
    assert_eq!(error, raw);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    submit(
        &mut queue,
        Backing {
            id: 32,
            drops: Arc::clone(&drops),
        },
    );
    drop(retired);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(editing(|| queue.claim()).unwrap().value().id, 32);
    drop(queue);
    assert_eq!(drops.load(Ordering::SeqCst), 2);
}

#[test]
fn failure_acknowledgement_cannot_cancel_running_or_foreign_work() {
    let mut a = Queue::<u64, 1>::new();
    let mut b = Queue::<u64, 1>::new();
    submit(&mut a, 17);
    submit(&mut b, 23);
    let a_claim = editing(|| a.claim()).unwrap();
    let b_claim = editing(|| b.claim()).unwrap();
    let a_claim = match editing(|| a.acknowledge_failure(a_claim)) {
        Err(claim) => claim,
        Ok(_) => panic!("running operation was retired"),
    };
    let a_claim = match editing(|| a.complete(a_claim, Err(12345))) {
        Ok(Completion::Failed { claim, .. }) => claim,
        _ => panic!("failure lost"),
    };
    let a_claim = match editing(|| b.acknowledge_failure(a_claim)) {
        Err(claim) => claim,
        Ok(_) => panic!("foreign failed operation was retired"),
    };
    // A foreign error acknowledgement must not disturb the actual running job.
    assert_eq!(*b_claim.value(), 23);
    drop(retired(editing(|| b.complete(b_claim, Ok(())))));
    let (error, retired) = match editing(|| a.acknowledge_failure(a_claim)) {
        Ok(result) => result,
        Err(_) => panic!("matching failure rejected"),
    };
    assert_eq!(error, 12345);
    drop(retired);
}
