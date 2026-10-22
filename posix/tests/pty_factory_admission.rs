use core::cell::Cell;
use mnu_abi::{IPC_DELIVERY_ENDPOINT_HANDLE, IpcObjectHandle, IpcObjectHandles};
use mochios_posix_protocol::pty_factory as wire;
use posix_service::{
    pty::{EBADF, PtyManager},
    pty_factory::{FACTORY_RIGHTS, MASTER_RIGHTS, create},
};

fn attachment() -> IpcObjectHandles {
    let mut attached = IpcObjectHandles::default();
    attached.delivery_flags = IPC_DELIVERY_ENDPOINT_HANDLE;
    attached.count = 1;
    attached.handles[0] = IpcObjectHandle {
        handle: 73,
        reserved: 0,
        rights: MASTER_RIGHTS,
    };
    attached
}

#[test]
fn only_the_received_local_master_is_identified_and_factory_is_data_rights_free() {
    let mut manager = PtyManager::new();
    let pair = manager.open().unwrap();
    let published = Cell::new(0);
    let result = create(
        &mut manager,
        &wire::CREATE_REQUEST,
        &attachment(),
        |handle| {
            assert_eq!(handle, 73); // Receiver-local Handle, not inline object ID.
            Ok(pair.master_object_id)
        },
        |id, rights| {
            assert_eq!(rights, FACTORY_RIGHTS);
            assert_eq!(
                rights,
                mnu_abi::HANDLE_RIGHT_DUPLICATE | mnu_abi::HANDLE_RIGHT_TRANSFER
            );
            published.set(id);
            Ok(91)
        },
    )
    .unwrap();
    assert_eq!(result.handle, 91);
    assert_eq!(result.rights, FACTORY_RIGHTS);
    let slave = manager.open_slave_from_factory(published.get()).unwrap();
    assert_eq!(
        manager.slave_terminal_id(slave),
        manager.slave_terminal_id(pair.slave_object_id)
    );
}

#[test]
fn malformed_or_incomplete_authority_is_rejected_before_identification_or_mutation() {
    let mut cases = Vec::new();
    for flags in [0, mnu_abi::IPC_DELIVERY_NATIVE_OBJECT, 3, u32::MAX] {
        let mut attached = attachment();
        attached.delivery_flags = flags;
        cases.push(attached);
    }
    for count in [0, 2, u32::MAX] {
        let mut attached = attachment();
        attached.count = count;
        cases.push(attached);
    }
    let mut attached = attachment();
    attached.handles[0].handle = 0;
    cases.push(attached);
    attached = attachment();
    attached.handles[0].reserved = 1;
    cases.push(attached);
    for bit in 0..64 {
        if MASTER_RIGHTS & (1 << bit) != 0 {
            let mut attached = attachment();
            attached.handles[0].rights &= !(1 << bit);
            cases.push(attached);
        }
    }
    for attached in cases {
        let mut manager = PtyManager::new();
        let pair = manager.open().unwrap();
        assert!(
            create(
                &mut manager,
                &wire::CREATE_REQUEST,
                &attached,
                |_| panic!("must not identify before admission"),
                |_, _| panic!("must not publish before admission")
            )
            .is_err()
        );
        assert!(manager.attributes(pair.master_object_id).is_ok());
        assert_eq!(manager.take_terminal_signal(), None);
    }
}

#[test]
fn version_opcode_and_exact_length_are_checked_before_using_the_attachment() {
    let mut bad_version = wire::CREATE_REQUEST.to_vec();
    bad_version[4] = 2;
    let mut unknown = wire::CREATE_REQUEST.to_vec();
    unknown[6] = 2;
    let mut trailing = wire::CREATE_REQUEST.to_vec();
    trailing.extend_from_slice(&2u64.to_le_bytes()); // Inline IDs never accepted.
    for (request, errno) in [
        (Vec::new(), 22),
        (wire::CREATE_REQUEST[..7].to_vec(), 22),
        (bad_version, 22),
        (unknown, 38),
        (trailing, 22),
    ] {
        let mut manager = PtyManager::new();
        assert_eq!(
            create(
                &mut manager,
                &request,
                &attachment(),
                |_| panic!("invalid wire request"),
                |_, _| panic!("invalid wire request")
            ),
            Err(errno)
        );
    }
}

#[test]
fn foreign_slave_factory_and_retired_master_cannot_mint_authority() {
    let mut manager = PtyManager::new();
    let pair = manager.open().unwrap();
    let factory = manager.create_slave_factory(pair.master_object_id).unwrap();
    manager.release(pair.master_object_id).unwrap();
    for object in [
        pair.master_object_id,
        pair.slave_object_id,
        factory,
        u64::MAX,
    ] {
        assert_eq!(
            create(
                &mut manager,
                &wire::CREATE_REQUEST,
                &attachment(),
                |_| Ok(object),
                |_, _| panic!("not a live master")
            ),
            Err(EBADF)
        );
    }
    assert_eq!(
        create(
            &mut manager,
            &wire::CREATE_REQUEST,
            &attachment(),
            |_| Err(EBADF),
            |_, _| panic!("foreign native provider")
        ),
        Err(EBADF)
    );
}

#[test]
fn native_publication_failure_reclaims_factory_without_closing_the_master() {
    for failed_handle in [Err(12), Ok(0)] {
        let mut manager = PtyManager::new();
        let pair = manager.open().unwrap();
        let object = Cell::new(0);
        let result = create(
            &mut manager,
            &wire::CREATE_REQUEST,
            &attachment(),
            |_| Ok(pair.master_object_id),
            |id, _| {
                object.set(id);
                failed_handle
            },
        );
        assert_eq!(result, Err(if failed_handle.is_err() { 12 } else { 5 }));
        assert_eq!(manager.open_slave_from_factory(object.get()), Err(EBADF));
        assert_eq!(manager.release(object.get()), Err(EBADF));
        assert!(manager.attributes(pair.master_object_id).is_ok());
        assert_eq!(manager.take_terminal_signal(), None);
    }
}
