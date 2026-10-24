#[path = "support/fifo_manager.rs"]
#[allow(dead_code)]
mod helpers;
use mnu_abi::{
    HANDLE_RIGHT_CONTROL as C, HANDLE_RIGHT_READ as R, HANDLE_RIGHT_TRANSFER as T,
    HANDLE_RIGHT_WRITE as W, IpcObjectHandle, IpcObjectHandles,
};
use posix_service::{
    fifo::{Access, WaitCondition},
    fifo_manager::{FilesystemScope, Manager},
    fifo_wait::Waits,
    fifo_wait_ipc::{self as wire, JOB_RIGHTS},
};
use std::{
    cell::Cell,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
struct Lease(Arc<AtomicUsize>);
impl Drop for Lease {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}
fn attachment(rights: u64) -> IpcObjectHandles {
    let mut objects = IpcObjectHandles::default();
    objects.count = 1;
    objects.delivery_flags = mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE;
    objects.handles[0] = IpcObjectHandle {
        handle: 7,
        reserved: 0,
        rights,
    };
    objects
}

#[test]
fn registration_identifies_only_received_direction_and_consumes_lease_after_validation() {
    let scope = FilesystemScope::new().unwrap();
    let pins = Arc::new(AtomicUsize::new(0));
    let closed = Arc::new(AtomicUsize::new(0));
    let mut manager = Manager::default();
    let reader = helpers::open(&mut manager, helpers::admit(scope, 1, Access::Read, &pins));
    let writer = helpers::open(&mut manager, helpers::admit(scope, 1, Access::Write, &pins));
    let mut waits = Waits::default();
    for (condition, rights, id, ready) in [
        (WaitCondition::Read, R, reader.object_id, false),
        (WaitCondition::Open, R, reader.object_id, true),
        (WaitCondition::Open, W, writer.object_id, true),
        (WaitCondition::Write(512), W, writer.object_id, true),
    ] {
        let mut objects = attachment(rights);
        let job = wire::register_with(
            &manager,
            &mut waits,
            &wire::encode(condition).unwrap(),
            &mut objects,
            |handle| {
                assert_eq!(handle, 7);
                Ok(id)
            },
            |object| {
                assert_eq!(object.rights, rights);
                Ok(Lease(closed.clone()))
            },
            |_| Ok(99),
        )
        .unwrap();
        assert_eq!(job.ready, ready);
        assert_eq!(objects.count, 0);
        assert_eq!(objects.handles[0].handle, 0);
        waits.release(job.object_id).unwrap();
    }
    assert_eq!(closed.load(Ordering::Relaxed), 4);
    helpers::release(&mut manager, reader.object_id);
    helpers::release(&mut manager, writer.object_id);
}

#[test]
fn malformed_and_underprivileged_requests_never_identify_or_adopt_a_handle() {
    let manager = Manager::default();
    let mut waits: Waits<Lease> = Waits::default();
    let good = wire::encode(WaitCondition::Read).unwrap();
    let mut cases = Vec::new();
    for delivery in [0, mnu_abi::IPC_DELIVERY_NATIVE_OBJECT, u32::MAX] {
        let mut a = attachment(R);
        a.delivery_flags = delivery;
        cases.push((good.to_vec(), a));
    }
    for count in [0, 2, u32::MAX] {
        let mut a = attachment(R);
        a.count = count;
        cases.push((good.to_vec(), a));
    }
    for rights in [0, W, R | W, R | T, R | C, JOB_RIGHTS] {
        cases.push((good.to_vec(), attachment(rights)));
    }
    let mut a = attachment(R);
    a.handles[0].handle = 0;
    cases.push((good.to_vec(), a));
    let mut a = attachment(R);
    a.handles[0].reserved = 1;
    cases.push((good.to_vec(), a));
    for index in [0, 4, 5, 6, 7, 8, 15] {
        let mut bytes = good;
        bytes[index] ^= 128;
        cases.push((bytes.to_vec(), attachment(R)));
    }
    cases.push((good[..15].to_vec(), attachment(R)));
    let mut bytes = good.to_vec();
    bytes.push(0);
    cases.push((bytes, attachment(R)));
    let mut bytes = wire::encode(WaitCondition::Write(1)).unwrap();
    bytes[8..].fill(0);
    cases.push((bytes.to_vec(), attachment(W)));
    for (bytes, mut objects) in cases {
        let before = objects;
        assert!(
            wire::register_with(
                &manager,
                &mut waits,
                &bytes,
                &mut objects,
                |_| panic!("invalid transport or direction"),
                |_| panic!("not owned"),
                |_| panic!("no publication")
            )
            .is_err()
        );
        assert_eq!(objects.count, before.count);
        assert_eq!(objects.handles[0].handle, before.handles[0].handle);
    }
    assert_eq!(wire::encode(WaitCondition::Write(0)), Err(-22));
}

#[test]
fn foreign_identity_stale_id_and_failed_adoption_have_exact_ownership() {
    let scope = FilesystemScope::new().unwrap();
    let pins = Arc::new(AtomicUsize::new(0));
    let closed = Arc::new(AtomicUsize::new(0));
    let mut manager = Manager::default();
    let reader = helpers::open(&mut manager, helpers::admit(scope, 3, Access::Read, &pins));
    let mut waits = Waits::default();
    let request = wire::encode(WaitCondition::Read).unwrap();
    for identity in [Err(-13), Ok(0), Ok(reader.object_id + 100)] {
        let mut objects = attachment(R);
        assert!(
            wire::register_with(
                &manager,
                &mut waits,
                &request,
                &mut objects,
                |_| identity,
                |_| panic!("foreign source not owned"),
                |_| panic!("not created")
            )
            .is_err()
        );
        assert_eq!(objects.count, 1);
    }
    let mut objects = attachment(R);
    assert_eq!(
        wire::register_with(
            &manager,
            &mut waits,
            &request,
            &mut objects,
            |_| Ok(reader.object_id),
            |_| {
                drop(Lease(closed.clone()));
                Err(-12)
            },
            |_| panic!("adoption failed")
        )
        .err(),
        Some(-12)
    );
    assert_eq!(objects.count, 0);
    assert_eq!(closed.load(Ordering::Relaxed), 1);
    let mut objects = attachment(R);
    assert_eq!(
        wire::register_with(
            &manager,
            &mut waits,
            &request,
            &mut objects,
            |_| Ok(reader.object_id),
            |_| Ok(Lease(closed.clone())),
            |_| Err(-23)
        )
        .err(),
        Some(-23)
    );
    assert_eq!(objects.count, 0);
    assert_eq!(closed.load(Ordering::Relaxed), 2);
    helpers::release(&mut manager, reader.object_id);
}

#[test]
fn query_attenuates_direction_and_preserves_borrowed_source_on_native_failure() {
    for condition in [
        WaitCondition::Open,
        WaitCondition::Read,
        WaitCondition::Write(512),
    ] {
        let direction = if matches!(condition, WaitCondition::Write(_)) {
            W
        } else {
            R
        };
        let source = IpcObjectHandle {
            handle: 44,
            reserved: 0,
            rights: direction | T | C,
        };
        let result = wire::query_with(
            4,
            source,
            condition,
            |endpoint, bytes, reply, objects| {
                assert_eq!(endpoint, 4);
                assert_eq!(bytes, wire::encode(condition).unwrap());
                assert_eq!(objects.count, 1);
                assert_eq!(objects.handles[0].handle, 44);
                assert_eq!(objects.handles[0].rights, direction);
                *objects = IpcObjectHandles::default();
                objects.count = 1;
                objects.handles[0] = IpcObjectHandle {
                    handle: 99,
                    reserved: 0,
                    rights: JOB_RIGHTS,
                };
                reply.copy_from_slice(&0i32.to_le_bytes());
                Ok(4)
            },
            |_| panic!("valid reply owns Handle"),
        )
        .unwrap();
        assert_eq!((result.handle, result.rights), (99, JOB_RIGHTS));
        assert_eq!(
            wire::query_with(
                4,
                source,
                condition,
                |_, _, _, objects| {
                    assert_eq!(objects.handles[0].handle, 44);
                    Err(-5)
                },
                |_| panic!("borrowed source must survive")
            )
            .err(),
            Some(-5)
        );
    }
    let source = IpcObjectHandle {
        handle: 44,
        reserved: 0,
        rights: R,
    };
    assert_eq!(
        wire::query_with(
            4,
            source,
            WaitCondition::Read,
            |_, _, _, _| panic!("TRANSFER missing"),
            |_| panic!("source borrowed")
        )
        .err(),
        Some(-13)
    );
    let source = IpcObjectHandle {
        rights: R | W | T,
        ..source
    };
    assert_eq!(
        wire::query_with(
            4,
            source,
            WaitCondition::Open,
            |_, _, _, _| panic!("ambiguous direction"),
            |_| panic!("source borrowed")
        )
        .err(),
        Some(-13)
    );
}

#[test]
fn invalid_success_and_error_replies_close_only_newly_installed_references_once() {
    let source = IpcObjectHandle {
        handle: 44,
        reserved: 0,
        rights: R | T,
    };
    for case in 0..10 {
        let closed = Cell::new(0);
        let result = wire::query_with(
            4,
            source,
            WaitCondition::Read,
            |_, _, reply, objects| {
                *objects = IpcObjectHandles::default();
                objects.count = 1;
                objects.handles[0] = IpcObjectHandle {
                    handle: 99,
                    reserved: 0,
                    rights: JOB_RIGHTS,
                };
                reply.copy_from_slice(&0i32.to_le_bytes());
                match case {
                    0 => return Ok(3),
                    1 => objects.delivery_flags = mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE,
                    2 => objects.handles[0].rights |= R,
                    3 => objects.handles[0].reserved = 1,
                    4 => {
                        objects.count = 2;
                        objects.handles[1] = objects.handles[0];
                    }
                    5 => reply.copy_from_slice(&(-13i32).to_le_bytes()),
                    6 => reply.copy_from_slice(&13i32.to_le_bytes()),
                    7 => {
                        objects.count = 0;
                    }
                    8 => objects.handles[0].handle = 0,
                    9 => {
                        objects.count = 0;
                        reply.copy_from_slice(&(-13i32).to_le_bytes());
                    }
                    _ => unreachable!(),
                }
                Ok(4)
            },
            |handle| {
                assert_eq!(handle, 99);
                closed.set(closed.get() + 1);
            },
        );
        assert_eq!(result.err(), Some(if case == 9 { -13 } else { -5 }));
        assert_eq!(closed.get(), usize::from(case < 7));
    }
}
