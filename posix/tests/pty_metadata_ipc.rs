use mnu_abi::{
    HANDLE_RIGHT_CONTROL as C, HANDLE_RIGHT_DUPLICATE as D, HANDLE_RIGHT_READ as R,
    HANDLE_RIGHT_TRANSFER as T, IpcObjectHandle, IpcObjectHandles,
};
use mochios_filesystem_protocol::device_metadata::Request;
use posix_service::{
    pty::{EBADF, PtyManager},
    pty_metadata::{Backend, Reference},
    pty_metadata_ipc::{lookup, query_with},
};
use std::{
    cell::Cell,
    sync::{Arc, Mutex},
};
#[derive(Debug)]
struct Metadata(Arc<Mutex<Vec<u64>>>);
impl Backend for Metadata {
    fn duplicate(&self, rights: u64) -> Result<u32, i32> {
        self.0.lock().unwrap().push(rights);
        Ok(92)
    }
}
fn attached(rights: u64) -> IpcObjectHandles {
    let mut objects = IpcObjectHandles::default();
    objects.delivery_flags = mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE;
    objects.count = 1;
    objects.handles[0] = IpcObjectHandle {
        handle: 73,
        reserved: 0,
        rights,
    };
    objects
}
fn manager() -> (PtyManager, u64, Arc<Mutex<Vec<u64>>>) {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut ptys = PtyManager::new();
    let pair = ptys.open().unwrap();
    let factory = ptys.create_slave_factory(pair.master_object_id).unwrap();
    let metadata = Reference::new(Box::new(Metadata(calls.clone())), C | D | T).unwrap();
    let slave = ptys.open_slave_with_metadata(factory, metadata).unwrap();
    (ptys, slave, calls)
}

#[test]
fn transfer_only_lookup_uses_only_the_received_data_handle_and_cannot_manufacture_control() {
    let (ptys, slave, calls) = manager();
    let metadata = lookup(
        &ptys,
        &Request { rights: T }.encode(),
        &attached(T),
        |raw| {
            assert_eq!(raw, 73);
            Ok(slave)
        },
    )
    .unwrap();
    assert_eq!((metadata.handle, metadata.rights), (92, T));
    assert_eq!(
        lookup(
            &ptys,
            &Request { rights: T | C }.encode(),
            &attached(T),
            |_| panic!("insufficient attachment authority")
        ),
        Err(13)
    );
    let controlled = lookup(
        &ptys,
        &Request { rights: T | C }.encode(),
        &attached(T | C),
        |_| Ok(slave),
    )
    .unwrap();
    assert_eq!(controlled.rights, T | C);
    assert_eq!(*calls.lock().unwrap(), vec![T, T | C]);
}

#[test]
fn invalid_framing_delivery_or_attachment_is_rejected_before_native_identification() {
    let (ptys, _, calls) = manager();
    let valid = Request { rights: T }.encode();
    let mut cases = Vec::new();
    for flags in [0, 1, 3, u32::MAX] {
        let mut a = attached(T);
        a.delivery_flags = flags;
        cases.push((valid.to_vec(), a));
    }
    for count in [0, 2, u32::MAX] {
        let mut a = attached(T);
        a.count = count;
        cases.push((valid.to_vec(), a));
    }
    let mut a = attached(T);
    a.handles[0].handle = 0;
    cases.push((valid.to_vec(), a));
    let mut a = attached(T);
    a.handles[0].reserved = 1;
    cases.push((valid.to_vec(), a));
    cases.push((valid.to_vec(), attached(0)));
    for rights in [0, C, R | T, D | T, u64::MAX] {
        cases.push((Request { rights }.encode().to_vec(), attached(u64::MAX)));
    }
    for at in [0, 4, 6] {
        let mut bad = valid;
        bad[at] ^= 0x80;
        cases.push((bad.to_vec(), attached(T)));
    }
    cases.push((valid[..15].to_vec(), attached(T)));
    let mut extra = valid.to_vec();
    extra.extend_from_slice(&1u64.to_le_bytes());
    cases.push((extra, attached(T)));
    for (bytes, a) in cases {
        assert!(lookup(&ptys, &bytes, &a, |_| panic!("invalid admission")).is_err());
    }
    assert!(calls.lock().unwrap().is_empty());
}

#[test]
fn only_an_identified_live_slave_with_retained_metadata_can_supply_a_reference() {
    let (mut ptys, slave, calls) = manager();
    let other = ptys.open().unwrap();
    for id in [other.master_object_id, u64::MAX] {
        assert_eq!(
            lookup(
                &ptys,
                &Request { rights: T }.encode(),
                &attached(T),
                |_| Ok(id)
            ),
            Err(EBADF)
        );
    }
    assert_eq!(
        lookup(
            &ptys,
            &Request { rights: T }.encode(),
            &attached(T),
            |_| Ok(other.slave_object_id)
        ),
        Err(95)
    );
    assert_eq!(
        lookup(&ptys, &Request { rights: T }.encode(), &attached(T), |_| {
            Err(EBADF)
        }),
        Err(EBADF)
    );
    ptys.release(slave).unwrap();
    assert_eq!(
        lookup(
            &ptys,
            &Request { rights: T }.encode(),
            &attached(T),
            |_| Ok(slave)
        ),
        Err(EBADF)
    );
    assert!(calls.lock().unwrap().is_empty());
}

#[test]
fn client_attenuates_the_attachment_and_validates_exact_reply_authority() {
    let (ptys, slave, calls) = manager();
    let result = query_with(
        11,
        IpcObjectHandle {
            handle: 40,
            reserved: 0,
            rights: R | C | D | T,
        },
        T,
        |endpoint, bytes, reply, objects| {
            assert_eq!(endpoint, 11);
            assert_eq!(objects.count, 1);
            assert_eq!(objects.delivery_flags, 0);
            assert_eq!(objects.handles[0].rights, T);
            objects.delivery_flags = mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE;
            objects.handles[0].handle = 73;
            let opened = lookup(&ptys, bytes, objects, |raw| {
                assert_eq!(raw, 73);
                Ok(slave)
            })
            .map_err(|errno| -errno)?;
            *objects = IpcObjectHandles::default();
            objects.count = 1;
            objects.handles[0] = IpcObjectHandle {
                handle: 100,
                reserved: 0,
                rights: opened.rights,
            };
            reply.copy_from_slice(&0i64.to_le_bytes());
            Ok(8)
        },
        |_| panic!("successful result and borrowed data reference must remain open"),
    )
    .unwrap();
    assert_eq!((result.handle, result.rights), (100, T));
    assert_eq!(*calls.lock().unwrap(), vec![T]);
}

#[test]
fn client_cleans_malformed_installed_replies_but_never_closes_borrowed_data_on_transport_error() {
    let source = IpcObjectHandle {
        handle: 40,
        reserved: 0,
        rights: T,
    };
    for (status, count, length, flags, rights, reserved, expected) in [
        (0i64, 1, 8u64, 0, T | C, 0, -5),
        (0, 1, 7, 0, T, 0, -5),
        (0, 1, 9, 0, T, 0, -5),
        (0, 2, 8, 0, T, 0, -5),
        (0, 1, 8, 1, T, 0, -5),
        (0, 1, 8, 0, T, 1, -5),
        (-13, 1, 8, 0, T, 0, -5),
        (-13, 0, 8, 0, T, 0, -13),
        (13, 0, 8, 0, T, 0, -5),
        (i64::MIN, 0, 8, 0, T, 0, -5),
        (0, u32::MAX, 8, 0, T, 0, -5),
    ] {
        let mut closed = Vec::new();
        assert_eq!(
            query_with(
                11,
                source,
                T,
                |_, _, reply, objects| {
                    *objects = IpcObjectHandles::default();
                    objects.count = count;
                    objects.delivery_flags = flags;
                    objects.handles[0] = IpcObjectHandle {
                        handle: 90,
                        reserved,
                        rights,
                    };
                    objects.handles[1] = IpcObjectHandle {
                        handle: 90,
                        reserved: 0,
                        rights: T,
                    };
                    reply.copy_from_slice(&status.to_le_bytes());
                    Ok(length)
                },
                |handle| closed.push(handle)
            ),
            Err(expected)
        );
        assert_eq!(closed, if count == 0 { vec![] } else { vec![90] });
    }
    assert_eq!(
        query_with(
            11,
            source,
            T,
            |_, _, _, _| Err(-32),
            |_| panic!("native rollback leaves only borrowed references")
        ),
        Err(-32)
    );
    let called = Cell::new(false);
    assert_eq!(
        query_with(
            11,
            source,
            T | C,
            |_, _, _, _| {
                called.set(true);
                Ok(8)
            },
            |_| panic!("no native call")
        ),
        Err(-13)
    );
    assert!(!called.get());
}
