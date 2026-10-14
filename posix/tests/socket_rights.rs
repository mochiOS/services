use mochios_posix_protocol::{INHERITED_FD_KIND_FILE, InheritedFdMetadata, socket::Address};
use posix_service::{
    socket_record::{MAX_RECORD_SIZE, RecordQueue, SourceAddress},
    socket_rights::{Budget, Bundle, Lease, Pending},
};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::{Cell, RefCell},
};

thread_local! {
    static CLOSED: RefCell<Vec<u32>> = const { RefCell::new(Vec::new()) };
    static FAIL_AFTER: Cell<isize> = const { Cell::new(-1) };
}
struct Allocator;
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let fail = FAIL_AFTER
            .try_with(|remaining| {
                let count = remaining.get();
                if count < 0 {
                    false
                } else {
                    remaining.set(count - 1);
                    count == 0
                }
            })
            .unwrap_or(false);
        if fail {
            std::ptr::null_mut()
        } else {
            unsafe { System.alloc(layout) }
        }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
    }
}
#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

fn close(handle: u32) {
    CLOSED.with(|closed| closed.borrow_mut().push(handle));
}
fn reset() {
    CLOSED.with(|closed| closed.borrow_mut().clear());
}
fn closed() -> Vec<u32> {
    CLOSED.with(|closed| closed.borrow().clone())
}
fn metadata() -> InheritedFdMetadata {
    InheritedFdMetadata {
        kind: INHERITED_FD_KIND_FILE,
        open_flags: 2,
        descriptor_flags: 0,
    }
}
fn lease(handle: u32) -> Lease {
    Lease::adopt(
        handle,
        mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_TRANSFER,
        metadata(),
        close,
    )
    .ok()
    .unwrap()
}
fn bundle(budget: &Budget, handles: &[u32]) -> Bundle {
    let mut pending = Pending::new(handles.len(), budget).ok().unwrap();
    for chunk in handles.chunks(3) {
        pending
            .append(
                pending.received(),
                chunk.iter().map(|id| lease(*id)).collect(),
            )
            .unwrap();
    }
    pending.finish().ok().unwrap()
}
fn source() -> SourceAddress {
    SourceAddress::new(Address::UnixUnnamed).unwrap()
}

#[test]
fn adoption_checks_onward_transfer_and_metadata_without_leaking_invalid_references() {
    reset();
    for (id, rights, info, expected) in [
        (1, mnu_abi::HANDLE_RIGHT_READ, metadata(), -13),
        (2, mnu_abi::HANDLE_RIGHT_ALL | (1 << 32), metadata(), -13),
        (
            3,
            mnu_abi::HANDLE_RIGHT_ALL,
            InheritedFdMetadata {
                descriptor_flags: 1,
                ..metadata()
            },
            -22,
        ),
        (
            4,
            mnu_abi::HANDLE_RIGHT_ALL,
            InheritedFdMetadata {
                kind: 0,
                ..metadata()
            },
            -22,
        ),
        (
            5,
            mnu_abi::HANDLE_RIGHT_ALL,
            InheritedFdMetadata {
                open_flags: 3,
                ..metadata()
            },
            -22,
        ),
        (
            6,
            mnu_abi::HANDLE_RIGHT_ALL,
            InheritedFdMetadata {
                kind: 1,
                ..metadata()
            },
            -22,
        ),
    ] {
        assert_eq!(Lease::adopt(id, rights, info, close).err(), Some(expected));
    }
    assert_eq!(closed(), [1, 2, 3, 4, 5, 6]);
    assert_eq!(
        Lease::adopt(0, mnu_abi::HANDLE_RIGHT_ALL, metadata(), close).err(),
        Some(-13)
    );
    let owned = lease(7);
    assert_eq!(owned.handle(), 7);
    assert_eq!(
        owned.rights(),
        mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_TRANSFER
    );
    assert_eq!(owned.metadata(), metadata());
    drop(owned);
    assert_eq!(closed(), [1, 2, 3, 4, 5, 6, 7]);
}

#[test]
fn full_253_reference_transaction_commits_only_after_every_batch() {
    reset();
    let budget = Budget::new(253);
    let mut pending = Pending::new(253, &budget).ok().unwrap();
    assert_eq!(budget.used(), 253);
    for start in (0..252).step_by(3) {
        pending
            .append(
                start,
                (start..start + 3).map(|id| lease(id as u32 + 1)).collect(),
            )
            .unwrap();
    }
    let mut pending = pending.finish().err().unwrap();
    assert_eq!(pending.received(), 252);
    assert!(closed().is_empty());
    pending.append(252, vec![lease(253)]).unwrap();
    let ready = pending.finish().ok().unwrap();
    assert_eq!(ready.len(), 253);
    assert!(!ready.is_empty());
    assert_eq!(ready.leases().last().unwrap().handle(), 253);
    drop(ready);
    assert_eq!(budget.used(), 0);
    assert_eq!(closed(), (1..=253).collect::<Vec<_>>());
}

#[test]
fn invalid_batches_close_only_new_references_and_do_not_change_old_stage() {
    reset();
    let budget = Budget::new(5);
    let mut pending = Pending::new(5, &budget).ok().unwrap();
    pending.append(0, vec![lease(1), lease(2)]).unwrap();
    assert_eq!(pending.append(0, vec![lease(3)]), Err(-22));
    assert_eq!(pending.append(3, vec![lease(4)]), Err(-22));
    assert_eq!(pending.append(2, vec![]), Err(-22));
    assert_eq!(
        pending.append(2, vec![lease(5), lease(6), lease(7), lease(8)]),
        Err(-22)
    );
    assert_eq!(pending.received(), 2);
    assert_eq!(closed(), [3, 4, 5, 6, 7, 8]);
    pending
        .append(2, vec![lease(9), lease(10), lease(11)])
        .unwrap();
    assert_eq!(pending.append(5, vec![lease(12)]), Err(-22));
    drop(pending);
    assert_eq!(budget.used(), 0);
    assert_eq!(closed(), [3, 4, 5, 6, 7, 8, 12, 1, 2, 9, 10, 11]);
}

#[test]
fn queue_pressure_returns_the_intact_bundle_for_retry_without_publication() {
    reset();
    let budget = Budget::new(3);
    let mut queue = RecordQueue::new();
    queue
        .push(source(), &vec![0; MAX_RECORD_SIZE], MAX_RECORD_SIZE)
        .unwrap();
    let rights = bundle(&budget, &[1, 2, 3]);
    let (error, rights) = queue
        .push_with_rights(source(), b"x", MAX_RECORD_SIZE, Some(7), rights)
        .err()
        .unwrap();
    assert_eq!(error, -11);
    assert_eq!(rights.len(), 3);
    assert_eq!(queue.len(), 1);
    assert!(queue.front_rights().is_none());
    assert!(closed().is_empty());
    queue.receive(&mut [], false).unwrap();
    queue
        .push_with_rights(source(), b"x", MAX_RECORD_SIZE, Some(7), rights)
        .ok()
        .unwrap();
    assert_eq!(queue.front_rights().unwrap().len(), 3);
    queue.receive(&mut [0], true).unwrap();
    assert_eq!(budget.used(), 3);
    assert!(closed().is_empty());
    queue.receive(&mut [], false).unwrap(); // ordinary recv discards control
    assert_eq!(budget.used(), 0);
    assert_eq!(closed(), [1, 2, 3]);
}

#[test]
fn every_queue_discard_path_closes_ancillary_references_once() {
    reset();
    let budget = Budget::new(9);
    let mut queue = RecordQueue::new();
    queue
        .push_with_rights(
            source(),
            b"a",
            MAX_RECORD_SIZE,
            Some(1),
            bundle(&budget, &[1, 2]),
        )
        .ok()
        .unwrap();
    queue
        .push_with_rights(
            source(),
            b"b",
            MAX_RECORD_SIZE,
            Some(2),
            bundle(&budget, &[3]),
        )
        .ok()
        .unwrap();
    queue.retain_sender(2); // connect/reconnect removes another sender's data
    assert_eq!(budget.used(), 1);
    assert_eq!(closed(), [1, 2]);
    queue.clear(); // read shutdown / disconnect discards every queued reference
    queue.clear();
    assert_eq!(budget.used(), 0);
    assert_eq!(closed(), [1, 2, 3]);
    queue
        .push_with_rights(source(), b"", MAX_RECORD_SIZE, None, bundle(&budget, &[4]))
        .ok()
        .unwrap();
    drop(queue); // final endpoint release
    assert_eq!(budget.used(), 0);
    assert_eq!(closed(), [1, 2, 3, 4]);
}

#[test]
fn budget_covers_unfinished_and_queued_references_and_is_reclaimed_on_abort() {
    reset();
    let budget = Budget::new(3);
    assert_eq!(Pending::new(254, &budget).err(), Some(-22));
    assert_eq!(budget.used(), 0);
    let mut queue = RecordQueue::new();
    queue
        .push_with_rights(
            source(),
            b"",
            MAX_RECORD_SIZE,
            None,
            bundle(&budget, &[1, 2]),
        )
        .ok()
        .unwrap();
    assert_eq!(Pending::new(2, &budget).err(), Some(-105));
    let mut pending = Pending::new(1, &budget).ok().unwrap();
    pending.append(0, vec![lease(3)]).unwrap();
    assert_eq!(budget.used(), 3);
    drop(pending);
    assert_eq!(budget.used(), 2);
    queue.clear();
    assert_eq!(budget.used(), 0);
    for _ in 0..1100 {
        drop(bundle(&budget, &[4, 5, 6]));
    }
    assert_eq!(budget.used(), 0);
}

#[test]
fn concurrent_reservations_cannot_overbook_the_shared_allowance() {
    use std::sync::{Arc, Barrier};
    let budget = Budget::new(253);
    let gate = Arc::new(Barrier::new(2));
    let threads: Vec<_> = (0..2)
        .map(|_| {
            let budget = budget.clone();
            let gate = gate.clone();
            std::thread::spawn(move || {
                let pending = Pending::new(253, &budget);
                gate.wait(); // keep the winning reservation alive until both tried
                let success = pending.is_ok();
                if let Err(error) = pending {
                    assert_eq!(error, -105);
                }
                success
            })
        })
        .collect();
    let successes = threads
        .into_iter()
        .map(|thread| usize::from(thread.join().unwrap()))
        .sum::<usize>();
    assert_eq!(successes, 1);
    assert_eq!(budget.used(), 0);
}

#[test]
fn allocation_failures_preserve_queue_and_return_all_bundle_ownership() {
    reset();
    let budget = Budget::new(3);
    FAIL_AFTER.with(|fail| fail.set(0));
    let result = Pending::new(3, &budget);
    FAIL_AFTER.with(|fail| fail.set(-1));
    assert_eq!(result.err(), Some(-12));
    assert_eq!(budget.used(), 0);
    // Payload allocation and VecDeque growth are separate possible failures.
    for allocation in 0..2 {
        let mut queue = RecordQueue::new();
        let rights = bundle(&budget, &[1, 2, 3]);
        FAIL_AFTER.with(|fail| fail.set(allocation));
        let result = queue.push_with_rights(source(), b"payload", MAX_RECORD_SIZE, None, rights);
        FAIL_AFTER.with(|fail| fail.set(-1));
        let (error, rights) = result.err().unwrap();
        assert_eq!(error, -12);
        assert_eq!(rights.len(), 3);
        assert_eq!(queue.len(), 0);
        assert_eq!(queue.charged(), 0);
        assert_eq!(budget.used(), 3);
        drop(rights);
        assert_eq!(budget.used(), 0);
    }
    assert_eq!(closed(), [1, 2, 3, 1, 2, 3]);
}

#[test]
fn snapshots_pin_only_the_requested_prefix_without_duplicate_authority() {
    reset();
    let budget = Budget::new(5);
    let mut original = bundle(&budget, &[1, 2, 3]);
    let mut snapshot = original.snapshot(2).unwrap();
    assert_eq!(budget.used(), 5);
    assert_eq!(snapshot.len(), 2);
    assert!(snapshot.leases().iter().all(|lease| !lease.is_exclusive()));
    assert!(
        snapshot
            .leases()
            .iter()
            .all(|lease| lease.rights()
                == mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_TRANSFER)
    );
    original.truncate(0);
    assert_eq!(closed(), [3]);
    assert_eq!(budget.used(), 2);
    assert!(snapshot.leases().iter().all(Lease::is_exclusive));
    snapshot.discard_delivered_prefix(1).unwrap();
    assert_eq!(closed(), [3, 1]);
    assert_eq!(budget.used(), 1);
    drop(original);
    drop(snapshot);
    assert_eq!(closed(), [3, 1, 2]);
    assert_eq!(budget.used(), 0);
}

#[test]
fn dropping_a_snapshot_does_not_close_the_queued_native_reference() {
    reset();
    let budget = Budget::new(4);
    let original = bundle(&budget, &[1, 2]);
    for _ in 0..8 {
        let snapshot = original.snapshot(2).unwrap();
        assert_eq!(budget.used(), 4);
        drop(snapshot);
        assert_eq!(budget.used(), 2);
        assert!(closed().is_empty());
        assert!(original.leases().iter().all(Lease::is_exclusive));
    }
    drop(original);
    assert_eq!(closed(), [1, 2]);
}

#[test]
fn snapshot_pressure_and_allocation_failure_never_change_the_source_or_quota() {
    reset();
    let budget = Budget::new(5);
    let original = bundle(&budget, &[1, 2, 3]);
    assert_eq!(original.snapshot(3).err(), Some(-105));
    assert_eq!(budget.used(), 3);
    FAIL_AFTER.with(|fail| fail.set(0));
    let result = original.snapshot(2);
    FAIL_AFTER.with(|fail| fail.set(-1));
    assert_eq!(result.err(), Some(-12));
    assert_eq!(budget.used(), 3);
    assert!(closed().is_empty());
    assert!(original.leases().iter().all(Lease::is_exclusive));
    let empty = original.snapshot(0).unwrap();
    assert!(empty.is_empty());
    drop(empty);
    drop(original);
    assert_eq!(closed(), [1, 2, 3]);
}

#[test]
fn failed_local_reference_allocation_closes_the_adopted_native_handle_once() {
    reset();
    FAIL_AFTER.with(|fail| fail.set(0));
    let result = Lease::adopt(
        42,
        mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_TRANSFER,
        metadata(),
        close,
    );
    FAIL_AFTER.with(|fail| fail.set(-1));
    assert_eq!(result.err(), Some(-12));
    assert_eq!(closed(), [42]);
}
