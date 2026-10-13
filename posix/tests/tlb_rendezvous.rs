#[path = "../../../core/src/mem/tlb_rendezvous.rs"]
mod tlb_rendezvous;

use tlb_rendezvous::{Error, Rendezvous, ServiceError};

#[test]
fn publication_requires_every_target_to_finish_and_rejects_invalid_cpu_masks() {
    let ledger = Rendezvous::<4>::new();
    assert!(matches!(ledger.publish(16), Err(Error::InvalidCpu)));
    assert_eq!(
        ledger.service(4, || Ok::<_, ()>(())),
        Err(ServiceError::InvalidCpu)
    );
    assert!(ledger.publish(0).unwrap().complete());
    let request = ledger.publish(0b0101).unwrap();
    assert!(!request.complete());
    assert_eq!(
        ledger.service(1, || -> Result<(), ()> { panic!("not targeted") }),
        Ok(false)
    );
    assert_eq!(ledger.service(0, || Ok::<_, ()>(())), Ok(true));
    assert!(!request.complete());
    assert_eq!(ledger.service(2, || Ok::<_, ()>(())), Ok(true));
    assert!(request.complete());
    assert_eq!(
        ledger.service(2, || -> Result<(), ()> { panic!("already complete") }),
        Ok(false)
    );
    // Slot 63 and all-bits masks must not trigger a shift-by-64 overflow.
    let full = Rendezvous::<64>::new();
    let highest = full.publish(1u64 << 63).unwrap();
    full.service(63, || Ok::<_, ()>(())).unwrap();
    assert!(highest.complete());
    assert!(!full.publish(u64::MAX).unwrap().complete());
}

#[test]
fn failed_flush_does_not_authorize_reclaim_and_retry_can_finish() {
    let ledger = Rendezvous::<2>::new();
    let request = ledger.publish(1).unwrap();
    assert_eq!(ledger.service(0, || Err(5u8)), Err(ServiceError::Flush(5)));
    assert!(!request.complete());
    assert_eq!(ledger.service(0, || Ok::<_, u8>(())), Ok(true));
    assert!(request.complete());
}

#[test]
fn generation_arriving_during_flush_requires_another_flush() {
    let ledger = Rendezvous::<1>::new();
    let first = ledger.publish(1).unwrap();
    let mut newer = None;
    ledger
        .service(0, || {
            newer = Some(ledger.publish(1).unwrap());
            Ok::<_, ()>(())
        })
        .unwrap();
    assert!(first.complete());
    assert!(!newer.as_ref().unwrap().complete());
    ledger.service(0, || Ok::<_, ()>(())).unwrap();
    assert!(newer.unwrap().complete());
}

#[test]
fn concurrent_publishers_coalesce_and_completion_is_not_dispatch() {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Barrier,
    };
    let ledger = Rendezvous::<2>::new();
    let callbacks = AtomicUsize::new(0);
    let entered = Barrier::new(2);
    let finish = Barrier::new(2);
    std::thread::scope(|scope| {
        let publishers: Vec<_> = (0..32)
            .map(|_| scope.spawn(|| ledger.publish(3).unwrap()))
            .collect();
        let requests: Vec<_> = publishers
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect();
        assert!(requests.iter().all(|request| !request.complete()));
        scope.spawn(|| {
            ledger
                .service(0, || {
                    entered.wait();
                    finish.wait();
                    callbacks.fetch_add(1, Ordering::Relaxed);
                    Ok::<_, ()>(())
                })
                .unwrap();
        });
        entered.wait();
        ledger
            .service(1, || {
                callbacks.fetch_add(1, Ordering::Relaxed);
                Ok::<_, ()>(())
            })
            .unwrap();
        assert!(requests.iter().all(|request| !request.complete()));
        finish.wait();
        while !requests.iter().all(|request| request.complete()) {
            std::thread::yield_now();
        }
    });
    assert_eq!(callbacks.load(Ordering::Acquire), 2);
}

#[test]
fn late_completion_cannot_regress_a_newer_completed_flush() {
    let ledger = Rendezvous::<1>::new();
    let first = ledger.publish(1).unwrap();
    let mut second = None;
    ledger
        .service(0, || {
            let next = ledger.publish(1).unwrap();
            ledger.service(0, || Ok::<_, ()>(())).unwrap();
            assert!(next.complete());
            second = Some(next);
            Ok::<_, ()>(())
        })
        .unwrap();
    assert!(first.complete() && second.unwrap().complete());
    assert_eq!(
        ledger.service(0, || -> Result<(), ()> { panic!("no regression") }),
        Ok(false)
    );
}
