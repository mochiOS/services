#[path = "support/fifo_manager.rs"]
#[allow(dead_code)]
mod helpers;
use helpers::{admit, call, frame, open, release};
use mnu_abi::provider;
use posix_service::{
    fifo::{Access, BUFFER_CAPACITY, WaitCondition},
    fifo_manager::{FilesystemScope, MAX_DATA_OBJECT_ID, Manager},
    fifo_wait::{MAX_WAITS, Waits, is_notification},
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

struct Lease(Arc<AtomicUsize>);
impl Drop for Lease {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}
fn register(
    waits: &mut Waits<Lease>,
    manager: &Manager,
    object: u64,
    condition: WaitCondition,
    closed: &Arc<AtomicUsize>,
) -> posix_service::fifo_wait::Registered {
    waits
        .register(manager, object, condition, Lease(closed.clone()), |id| {
            assert!(is_notification(id));
            assert!(id > MAX_DATA_OBJECT_ID && id <= i64::MAX as u64);
            Ok((id & MAX_DATA_OBJECT_ID) as u32 + 100)
        })
        .unwrap()
}

#[test]
fn open_wait_latches_rendezvous_and_never_treats_empty_readability_as_pending_open() {
    let scope = FilesystemScope::new().unwrap();
    let closed = Arc::new(AtomicUsize::new(0));
    let leases = Arc::new(AtomicUsize::new(0));
    let mut manager = Manager::default();
    let mut waits = Waits::default();
    let reader = manager
        .open(
            admit(scope, 1, Access::Read, &closed),
            false,
            |_, _, _| Ok(1),
            |_| panic!("no native close"),
        )
        .unwrap();
    let job = register(
        &mut waits,
        &manager,
        reader.object_id,
        WaitCondition::Open,
        &leases,
    );
    assert!(!job.ready);
    assert!(!manager.readiness(reader.object_id).unwrap().open_ready);
    waits
        .pump(&manager, reader.channel, |_| panic!("unmatched open"))
        .unwrap();
    let writer = open(&mut manager, admit(scope, 1, Access::Write, &closed));
    // Registering after the transition must also inspect it before publication.
    let late = register(
        &mut waits,
        &manager,
        reader.object_id,
        WaitCondition::Open,
        &leases,
    );
    assert!(late.ready);
    let mut woke = Vec::new();
    waits
        .pump(&manager, writer.channel, |id| {
            woke.push(id);
            Ok(())
        })
        .unwrap();
    assert_eq!(woke, [job.object_id, late.object_id]);
    let state = manager.readiness(reader.object_id).unwrap();
    assert!(state.open_ready && !state.readable && !state.end_of_stream);
    // Closing the peer before the client wakes cannot revoke completed open.
    release(&mut manager, writer.object_id);
    assert!(waits.ready(job.object_id).unwrap());
    assert!(
        register(
            &mut waits,
            &manager,
            reader.object_id,
            WaitCondition::Read,
            &leases
        )
        .ready
    );
    drop(waits);
    assert_eq!(leases.load(Ordering::Relaxed), 3);
    assert!(manager.readiness(reader.object_id).is_ok());
    release(&mut manager, reader.object_id);
    assert_eq!(closed.load(Ordering::Relaxed), 2);
}

#[test]
fn atomic_write_wait_needs_full_capacity_and_no_readers_is_a_completion() {
    let scope = FilesystemScope::new().unwrap();
    let closed = Arc::new(AtomicUsize::new(0));
    let leases = Arc::new(AtomicUsize::new(0));
    let mut manager = Manager::default();
    let reader = open(&mut manager, admit(scope, 2, Access::Read, &closed));
    let writer = open(&mut manager, admit(scope, 2, Access::Write, &closed));
    let chunk = [b'x'; provider::MAX_DATA_LEN];
    for _ in 0..BUFFER_CAPACITY / provider::MAX_DATA_LEN {
        assert_eq!(
            call(
                &mut manager,
                provider::OP_WRITE,
                writer.object_id,
                &chunk,
                chunk.len()
            )
            .0,
            0
        );
    }
    let mut waits = Waits::default();
    let atomic = register(
        &mut waits,
        &manager,
        writer.object_id,
        WaitCondition::Write(512),
        &leases,
    );
    let large = register(
        &mut waits,
        &manager,
        writer.object_id,
        WaitCondition::Write(513),
        &leases,
    );
    assert!(!atomic.ready && !large.ready);
    assert_eq!(
        call(&mut manager, provider::OP_READ, reader.object_id, &[], 1)
            .1
            .len(),
        1
    );
    assert!(manager.readiness(writer.object_id).unwrap().writable);
    let mut woke = Vec::new();
    waits
        .pump(&manager, reader.channel, |id| {
            woke.push(id);
            Ok(())
        })
        .unwrap();
    assert_eq!(woke, [large.object_id]);
    assert!(!waits.ready(atomic.object_id).unwrap());
    assert_eq!(
        call(
            &mut manager,
            provider::OP_WRITE,
            writer.object_id,
            &[0; 512],
            512
        )
        .0,
        -11
    );
    assert_eq!(
        call(&mut manager, provider::OP_READ, reader.object_id, &[], 511)
            .1
            .len(),
        511
    );
    waits.pump(&manager, reader.channel, |_| Ok(())).unwrap();
    assert!(waits.ready(atomic.object_id).unwrap());
    // A competing writer consumes the room; a latched wake still means retry.
    assert_eq!(
        call(
            &mut manager,
            provider::OP_WRITE,
            writer.object_id,
            &[0; 512],
            512
        )
        .0,
        0
    );
    assert!(waits.ready(atomic.object_id).unwrap());
    let broken = register(
        &mut waits,
        &manager,
        writer.object_id,
        WaitCondition::Write(512),
        &leases,
    );
    assert!(!broken.ready);
    release(&mut manager, reader.object_id);
    waits.pump(&manager, writer.channel, |_| Ok(())).unwrap();
    assert!(waits.ready(broken.object_id).unwrap());
    assert_eq!(
        call(&mut manager, provider::OP_WRITE, writer.object_id, &[1], 1).0,
        -32
    );
    drop(waits);
    release(&mut manager, writer.object_id);
}

#[test]
fn read_notifications_latch_and_signal_failures_do_not_hide_other_wakes() {
    let scope = FilesystemScope::new().unwrap();
    let closed = Arc::new(AtomicUsize::new(0));
    let leases = Arc::new(AtomicUsize::new(0));
    let mut manager = Manager::default();
    let a = open(&mut manager, admit(scope, 3, Access::Read, &closed));
    let writer = open(&mut manager, admit(scope, 3, Access::Write, &closed));
    let b = open(&mut manager, admit(scope, 4, Access::Read, &closed));
    let other_writer = open(&mut manager, admit(scope, 4, Access::Write, &closed));
    let mut waits = Waits::default();
    let first = register(
        &mut waits,
        &manager,
        a.object_id,
        WaitCondition::Read,
        &leases,
    );
    let second = register(
        &mut waits,
        &manager,
        a.object_id,
        WaitCondition::Read,
        &leases,
    );
    let other = register(
        &mut waits,
        &manager,
        b.object_id,
        WaitCondition::Read,
        &leases,
    );
    assert!(!first.ready && !other.ready);
    assert_eq!(
        call(&mut manager, provider::OP_WRITE, writer.object_id, b"a", 1).0,
        0
    );
    // Data arrived after the client's failed read but before registration.
    let late = register(
        &mut waits,
        &manager,
        a.object_id,
        WaitCondition::Read,
        &leases,
    );
    assert!(late.ready);
    let mut signaled = Vec::new();
    assert_eq!(
        waits.pump(&manager, a.channel, |id| {
            signaled.push(id);
            if id == first.object_id {
                Err(-5)
            } else {
                Ok(())
            }
        }),
        Err(-5)
    );
    assert_eq!(
        signaled,
        [first.object_id, second.object_id, late.object_id]
    );
    assert!(waits.ready(first.object_id).unwrap() && waits.ready(second.object_id).unwrap());
    assert!(!waits.ready(other.object_id).unwrap());
    assert_eq!(
        call(&mut manager, provider::OP_READ, a.object_id, &[], 1).1,
        b"a"
    );
    let mut retried = Vec::new();
    waits
        .pump(&manager, a.channel, |id| {
            retried.push(id);
            Ok(())
        })
        .unwrap();
    assert_eq!(retried, signaled);
    // An already-retired source while holding its lease is an owner invariant
    // violation, not permission to silently publish an arbitrary ready job.
    release(&mut manager, b.object_id);
    assert_eq!(
        waits.pump(&manager, b.channel, |_| panic!("missing source")),
        Err(-9)
    );
    drop(waits);
    for id in [a.object_id, writer.object_id, other_writer.object_id] {
        release(&mut manager, id);
    }
    assert_eq!(leases.load(Ordering::Relaxed), 4);
}

#[test]
fn native_release_cancels_only_its_job_and_forged_release_does_not_close_lease() {
    assert!(!is_notification(0));
    assert!(!is_notification(1 << 62));
    assert!(!is_notification(MAX_DATA_OBJECT_ID));
    assert!(!is_notification(u64::MAX));
    assert!(is_notification(i64::MAX as u64));
    let scope = FilesystemScope::new().unwrap();
    let closed = Arc::new(AtomicUsize::new(0));
    let leases = Arc::new(AtomicUsize::new(0));
    let mut manager = Manager::default();
    let reader = open(&mut manager, admit(scope, 5, Access::Read, &closed));
    let mut waits = Waits::default();
    let job = register(
        &mut waits,
        &manager,
        reader.object_id,
        WaitCondition::Read,
        &leases,
    );
    let request = frame(provider::OP_RELEASE, job.object_id, &[], 0);
    assert_eq!(
        waits.handle_provider_request(&request, mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE, 0),
        Err(-13)
    );
    assert_eq!(
        waits.handle_provider_request(&request, mnu_abi::IPC_DELIVERY_NATIVE_OBJECT, 1),
        Err(-22)
    );
    assert_eq!(leases.load(Ordering::Relaxed), 0);
    let wrong = frame(provider::OP_RELEASE, reader.object_id, &[], 0);
    assert_eq!(
        waits.handle_provider_request(&wrong, mnu_abi::IPC_DELIVERY_NATIVE_OBJECT, 0),
        Err(-22)
    );
    let read = frame(provider::OP_READ, job.object_id, &[], 1);
    assert_eq!(
        waits.handle_provider_request(&read, mnu_abi::IPC_DELIVERY_NATIVE_OBJECT, 0),
        Err(-95)
    );
    let mut malformed = request.clone();
    malformed.push(0);
    assert_eq!(
        waits.handle_provider_request(&malformed, mnu_abi::IPC_DELIVERY_NATIVE_OBJECT, 0),
        Err(-22)
    );
    waits
        .handle_provider_request(&request, mnu_abi::IPC_DELIVERY_NATIVE_OBJECT, 0)
        .unwrap();
    assert_eq!(leases.load(Ordering::Relaxed), 1);
    assert_eq!(
        waits.handle_provider_request(&request, mnu_abi::IPC_DELIVERY_NATIVE_OBJECT, 0),
        Err(-9)
    );
    assert!(manager.readiness(reader.object_id).is_ok());
    release(&mut manager, reader.object_id);
}

#[test]
fn rejected_registration_closes_lease_and_failed_publication_cannot_reuse_id() {
    let scope = FilesystemScope::new().unwrap();
    let closed = Arc::new(AtomicUsize::new(0));
    let leases = Arc::new(AtomicUsize::new(0));
    let mut manager = Manager::default();
    let reader = open(&mut manager, admit(scope, 6, Access::Read, &closed));
    let writer = open(&mut manager, admit(scope, 6, Access::Write, &closed));
    let mut waits = Waits::default();
    for (object, condition, errno) in [
        (reader.object_id, WaitCondition::Write(1), -9),
        (writer.object_id, WaitCondition::Read, -9),
        (writer.object_id, WaitCondition::Write(0), -22),
        (0, WaitCondition::Open, -9),
    ] {
        assert_eq!(
            waits
                .register(
                    &manager,
                    object,
                    condition,
                    Lease(leases.clone()),
                    |_| panic!("invalid admission")
                )
                .err(),
            Some(errno)
        );
    }
    assert_eq!(leases.load(Ordering::Relaxed), 4);
    let mut failed = 0;
    assert_eq!(
        waits
            .register(
                &manager,
                reader.object_id,
                WaitCondition::Read,
                Lease(leases.clone()),
                |id| {
                    failed = id;
                    Err(-12)
                }
            )
            .err(),
        Some(-12)
    );
    assert_eq!(waits.ready(failed), Err(-9));
    assert_eq!(leases.load(Ordering::Relaxed), 5);
    assert_eq!(
        waits
            .register(
                &manager,
                reader.object_id,
                WaitCondition::Read,
                Lease(leases.clone()),
                |_| Ok(0)
            )
            .err(),
        Some(-5)
    );
    let good = register(
        &mut waits,
        &manager,
        reader.object_id,
        WaitCondition::Read,
        &leases,
    );
    assert!(good.object_id > failed + 1);
    // Publication failure closes the notification; its eventual native release
    // cancels the job without deleting its source or touching queued bytes.
    waits.release(good.object_id).unwrap();
    assert_eq!(leases.load(Ordering::Relaxed), 7);
    assert_eq!(
        call(
            &mut manager,
            provider::OP_WRITE,
            writer.object_id,
            b"kept",
            4
        )
        .0,
        0
    );
    assert_eq!(
        call(&mut manager, provider::OP_READ, reader.object_id, &[], 4).1,
        b"kept"
    );
    release(&mut manager, writer.object_id);
    release(&mut manager, reader.object_id);
}

#[test]
fn wait_quota_is_global_and_reclaimed_without_changing_data_state() {
    let scope = FilesystemScope::new().unwrap();
    let closed = Arc::new(AtomicUsize::new(0));
    let leases = Arc::new(AtomicUsize::new(0));
    let mut manager = Manager::default();
    let reader = open(&mut manager, admit(scope, 7, Access::Read, &closed));
    let mut waits = Waits::default();
    let mut ids = Vec::new();
    for _ in 0..MAX_WAITS {
        ids.push(
            register(
                &mut waits,
                &manager,
                reader.object_id,
                WaitCondition::Open,
                &leases,
            )
            .object_id,
        );
    }
    assert_eq!(
        waits
            .register(
                &manager,
                reader.object_id,
                WaitCondition::Read,
                Lease(leases.clone()),
                |_| panic!("quota before native creation")
            )
            .err(),
        Some(-23)
    );
    assert_eq!(leases.load(Ordering::Relaxed), 1);
    waits.release(ids[0]).unwrap();
    let new = register(
        &mut waits,
        &manager,
        reader.object_id,
        WaitCondition::Open,
        &leases,
    );
    assert!(new.object_id > *ids.last().unwrap());
    drop(waits);
    assert_eq!(leases.load(Ordering::Relaxed), MAX_WAITS + 2);
    assert!(manager.readiness(reader.object_id).unwrap().open_ready);
    release(&mut manager, reader.object_id);
}
