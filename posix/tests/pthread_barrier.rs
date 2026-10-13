use mochios_posix_client::pthread_barrier::{Arrival, Barrier, Error};
use std::sync::atomic::{AtomicU32, Ordering};

fn ticket<const LIMIT: u64>(barrier: &Barrier<LIMIT>) -> (u64, bool) {
    loop {
        match barrier.arrive().unwrap() {
            Arrival::Admitted { ticket, serial, .. } => return (ticket, serial),
            Arrival::ResetPending { .. } => std::thread::yield_now(),
        }
    }
}
fn wait<const LIMIT: u64>(barrier: &Barrier<LIMIT>) -> bool {
    let (ticket, serial) = ticket(barrier);
    while !barrier.passed(ticket).unwrap() {
        std::thread::yield_now();
    }
    barrier.leave(ticket).unwrap();
    serial
}

#[test]
fn count_and_lifecycle_validation_keep_unfinished_barriers_busy() {
    assert!(matches!(Barrier::<10>::new(0), Err(Error::Invalid)));
    assert!(matches!(Barrier::<10>::new(11), Err(Error::Invalid)));
    let barrier = Barrier::<10>::new(2).unwrap();
    let (first, serial) = ticket(&barrier);
    assert!(!serial);
    assert_eq!(barrier.passed(first), Ok(false));
    assert_eq!(barrier.leave(first), Err(Error::Invalid));
    assert_eq!(barrier.destroy(), Err(Error::Busy));
    let (second, serial) = ticket(&barrier);
    assert!(serial);
    assert_eq!(barrier.passed(first), Ok(true));
    barrier.leave(second).unwrap();
    assert_eq!(barrier.destroy(), Err(Error::Busy));
    barrier.leave(first).unwrap();
    assert_eq!(barrier.destroy(), Ok(()));
    assert_eq!(barrier.arrive(), Err(Error::Invalid));
    assert_eq!(barrier.destroy(), Err(Error::Invalid));
    assert_eq!(std::mem::size_of::<Barrier>(), 32);
    assert_eq!(std::mem::align_of::<Barrier>(), 8);
}

#[test]
fn singleton_barrier_reuses_and_resets_without_overflow() {
    let barrier = Barrier::<3>::new(1).unwrap();
    for _ in 0..1000 {
        assert!(wait(&barrier));
    }
    barrier.destroy().unwrap();
}

#[test]
fn delayed_departure_prevents_reset_and_new_admission_until_old_round_is_quiescent() {
    let barrier = Barrier::<3>::new(2).unwrap(); // Rounded reset boundary is 2.
    let (old, _) = ticket(&barrier);
    let (last, serial) = ticket(&barrier);
    assert!(serial);
    assert_eq!(barrier.leave(last), Ok(false));
    assert_eq!(barrier.arrive(), Ok(Arrival::ResetPending { expected: 2 }));
    assert_eq!(barrier.passed(old), Ok(true));
    assert_eq!(barrier.leave(old), Ok(true));
    assert_eq!(barrier.completion_word().load(Ordering::Acquire), 0);
    assert_eq!(barrier.entry_word().load(Ordering::Acquire), 0);
    let (new, _) = ticket(&barrier);
    assert_eq!(new, 1);
    assert_eq!(barrier.passed(new), Ok(false));
}

#[test]
fn many_rounds_publish_every_participant_write_and_choose_one_serial_return() {
    let barrier = Barrier::<24>::new(8).unwrap();
    let serial = AtomicU32::new(0);
    let values = std::array::from_fn::<_, 8, _>(|_| AtomicU32::new(0));
    std::thread::scope(|scope| {
        for index in 0..8 {
            let values = &values;
            let barrier = &barrier;
            let serial = &serial;
            scope.spawn(move || {
                for round in 1..=300 {
                    values[index].store(round, Ordering::Relaxed);
                    if wait(barrier) {
                        serial.fetch_add(1, Ordering::Relaxed);
                    }
                    for value in values {
                        assert_eq!(value.load(Ordering::Relaxed), round);
                    }
                    // Readers must finish before any participant writes the next round.
                    if wait(barrier) {
                        serial.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });
        }
    });
    assert_eq!(serial.load(Ordering::Acquire), 600);
    barrier.destroy().unwrap();
}

#[test]
fn later_round_can_complete_while_earlier_ticket_has_not_departed() {
    let barrier = Barrier::<6>::new(2).unwrap();
    let (old, _) = ticket(&barrier);
    let (last, _) = ticket(&barrier);
    barrier.leave(last).unwrap();
    let (next, _) = ticket(&barrier);
    let (next_last, _) = ticket(&barrier);
    assert_eq!(barrier.passed(old), Ok(true));
    assert_eq!(barrier.passed(next), Ok(true));
    barrier.leave(next_last).unwrap();
    barrier.leave(next).unwrap();
    barrier.leave(old).unwrap();
    barrier.destroy().unwrap();
}
