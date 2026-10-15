//! Real reserved queue and suspension journal, with a modeled VM lock.
//! This verifies handoff/finalization, not a native PTE backend spanning IPC.
use crate::task::deferred::{Pending, Ticket};
use crate::{ATTEMPTS, DENY, Ordering};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, AtomicUsize};
use crate::interrupt::spinlock::SpinLock;

#[path = "../../../../core/src/mem/mapping_revocation.rs"]
mod mapping_revocation;
use mapping_revocation::{Backend, Suspension};

struct State {
    vm: Mutex<()>,
    cleanup_allowed: AtomicBool,
    restored: AtomicUsize,
    released: AtomicUsize,
    lease_dropped: AtomicBool,
}

struct Vm(Arc<State>);

impl Vm {
    fn finish(&self, released: bool) {
        assert!(self.0.cleanup_allowed.load(Ordering::Acquire));
        assert!(self.0.vm.try_lock().is_err(), "cleanup must hold VM lock");
        assert!(!self.0.lease_dropped.load(Ordering::Acquire));
        if released {
            &self.0.released
        } else {
            &self.0.restored
        }
        .fetch_add(1, Ordering::AcqRel);
    }
}

impl Backend for Vm {
    type Page = u64;
    type Error = u64;
    fn next_page(&mut self, _: u64, start: u64, end: u64) -> Result<Option<u64>, u64> {
        Ok((start < end).then_some(start))
    }
    fn suspend(&mut self, _: u64, address: u64) -> Result<Option<u64>, u64> {
        assert!(self.0.vm.try_lock().is_err());
        Ok(Some(address))
    }
    fn synchronize(&mut self) -> Result<(), u64> {
        Ok(())
    }
    fn restore(&mut self, _: u64) {
        self.finish(false);
    }
    fn release(&mut self, _: u64) {
        self.finish(true);
    }
}

impl Drop for Vm {
    fn drop(&mut self) {
        assert_eq!(
            self.0.restored.load(Ordering::Acquire) + self.0.released.load(Ordering::Acquire),
            2,
            "lease dropped before every PTE was resolved"
        );
        assert!(!self.0.lease_dropped.swap(true, Ordering::AcqRel));
    }
}

fn verify_journal_handoff() {
    for mode in 0..3 {
        let state = Arc::new(State {
            vm: Mutex::new(()),
            cleanup_allowed: AtomicBool::new(false),
            restored: AtomicUsize::new(0),
            released: AtomicUsize::new(0),
            lease_dropped: AtomicBool::new(false),
        });
        let queue = SpinLock::new(Pending::new());
        // Reserve the node while it is still empty, BEFORE any PTE edits.
        let ticket = Ticket::new(None::<Suspension<Vm>>).ok().unwrap();
        let mut owner = ticket.defer_on_drop(&queue);
        {
            let _vm = state.vm.lock().unwrap();
            *owner.value_mut() =
                Some(Suspension::new([(4096, 4096, 12288)], Vm(state.clone())).unwrap());
            DENY.store(true, Ordering::Relaxed);
            if mode == 0 {
                // Models Handle insertion failure/final-reference destruction
                // under the process table lock. No VM callback may run here.
                drop(owner);
                assert_eq!(state.restored.load(Ordering::Acquire), 0);
                assert!(!state.lease_dropped.load(Ordering::Acquire));
            } else {
                // Explicit finish disarms enqueue while keeping the node's
                // resource owner alive through journal commit or rollback.
                state.cleanup_allowed.store(true, Ordering::Release);
                let journal = owner.into_ticket().into_value().unwrap();
                assert_eq!(
                    journal.commit_with(|_| if mode == 1 { Ok(37) } else { Err(19) }),
                    if mode == 1 {
                        Ok(37)
                    } else {
                        Err(mapping_revocation::Error::Backend(19))
                    }
                );
            }
        }
        let mut batch = {
            let mut shared = queue.lock();
            std::mem::take(&mut *shared)
        }
        .reversed();
        // Never retain queue exclusion while acquiring VM exclusion or running
        // a destructor that may enqueue another ticket.
        assert!(queue.lock().pop().is_none());
        if mode == 0 {
            let _vm = state.vm.lock().unwrap();
            state.cleanup_allowed.store(true, Ordering::Release);
            let journal = batch.pop().unwrap().into_value().unwrap();
            drop(journal);
        }
        assert!(batch.pop().is_none());
        assert!(state.lease_dropped.load(Ordering::Acquire));
        assert_eq!(
            state.released.load(Ordering::Acquire),
            if mode == 1 { 2 } else { 0 }
        );
        assert_eq!(
            state.restored.load(Ordering::Acquire),
            if mode == 1 { 0 } else { 2 }
        );
        assert_eq!(ATTEMPTS.load(Ordering::Relaxed), 0);
        DENY.store(false, Ordering::Relaxed);
    }
}

fn verify_allocation_failure_retains_payload() {
    struct Counted(Arc<AtomicUsize>);
    impl Drop for Counted {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    let drops = Arc::new(AtomicUsize::new(0));
    let value = Counted(drops.clone());
    DENY.store(true, Ordering::Relaxed);
    let returned = Ticket::new(value).err().unwrap();
    DENY.store(false, Ordering::Relaxed);
    assert_eq!(ATTEMPTS.swap(0, Ordering::Relaxed), 1);
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    drop(returned);
    assert_eq!(drops.load(Ordering::Relaxed), 1);
}

struct Reentrant {
    next: Option<Ticket<Reentrant>>,
}
static REENTRANT: SpinLock<Pending<Reentrant>> = SpinLock::new(Pending::new());
static REENTRANT_DROPS: AtomicUsize = AtomicUsize::new(0);

impl Drop for Reentrant {
    fn drop(&mut self) {
        assert!(
            REENTRANT.try_lock().is_some(),
            "cleanup ran under queue lock"
        );
        if let Some(next) = self.next.take() {
            REENTRANT.lock().push(next);
        }
        REENTRANT_DROPS.fetch_add(1, Ordering::Relaxed);
    }
}

fn verify_cleanup_may_reenter_queue() {
    let next = Ticket::new(Reentrant { next: None }).ok().unwrap();
    let owner = Ticket::new(Reentrant { next: Some(next) })
        .ok()
        .unwrap()
        .defer_on_drop(&REENTRANT);
    DENY.store(true, Ordering::Relaxed);
    drop(owner);
    let mut batch = {
        let mut shared = REENTRANT.lock();
        std::mem::take(&mut *shared)
    };
    // Cleanup may enqueue another action on the SAME queue. New arrivals must
    // remain for the next pass rather than extending this detached batch.
    drop(batch.pop().unwrap());
    assert!(batch.pop().is_none());
    assert_eq!(REENTRANT_DROPS.load(Ordering::Relaxed), 1);
    let last = { REENTRANT.lock().pop().unwrap() };
    drop(last);
    assert!(REENTRANT.lock().pop().is_none());
    assert_eq!(REENTRANT_DROPS.load(Ordering::Relaxed), 2);
    assert_eq!(ATTEMPTS.load(Ordering::Relaxed), 0);
    DENY.store(false, Ordering::Relaxed);
}

fn verify_concurrent_handoff() {
    let queue = Arc::new(SpinLock::new(Pending::new()));
    let mut workers = Vec::new();
    for worker in 0..16 {
        let queue = queue.clone();
        workers.push(std::thread::spawn(move || {
            for index in 0..8 {
                drop(
                    Ticket::new(worker * 8 + index)
                        .unwrap()
                        .defer_on_drop(&queue),
                );
            }
        }));
    }
    for worker in workers {
        worker.join().unwrap();
    }
    let mut batch = {
        let mut shared = queue.lock();
        std::mem::take(&mut *shared)
    }
    .reversed();
    let mut seen = [false; 128];
    DENY.store(true, Ordering::Relaxed);
    while let Some(ticket) = batch.pop() {
        let index = ticket.into_value();
        assert!(!seen[index], "cleanup ownership duplicated");
        seen[index] = true;
    }
    assert!(seen.into_iter().all(|value| value));
    assert_eq!(ATTEMPTS.load(Ordering::Relaxed), 0);
    DENY.store(false, Ordering::Relaxed);
}

pub fn verify() {
    verify_allocation_failure_retains_payload();
    verify_journal_handoff();
    verify_cleanup_may_reenter_queue();
    verify_concurrent_handoff();
}
