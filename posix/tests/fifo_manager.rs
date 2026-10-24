#[path = "support/fifo_manager.rs"]
mod helpers;
use helpers::*;
use mnu_abi::provider;
use posix_service::{
    fifo::Access,
    fifo_manager::{FilesystemScope, MAX_CHANNELS, MAX_DESCRIPTIONS, Manager},
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[test]
fn independent_opens_share_queue_only_within_the_same_inode_and_authority() {
    let scope = FilesystemScope::new().unwrap();
    let other = FilesystemScope::new().unwrap();
    let closed = Arc::new(AtomicUsize::new(0));
    let mut manager = Manager::default();
    let a = open(&mut manager, admit(scope, 17, Access::Read, &closed));
    let b = open(&mut manager, admit(scope, 17, Access::Read, &closed));
    let w = open(&mut manager, admit(scope, 17, Access::Write, &closed));
    let c = open(&mut manager, admit(scope, 18, Access::Read, &closed));
    let d = open(&mut manager, admit(other, 17, Access::Read, &closed));
    assert_eq!(a.channel, b.channel);
    assert_ne!(a.channel, c.channel);
    assert_ne!(a.channel, d.channel);
    assert_eq!(
        call(&mut manager, provider::OP_WRITE, w.object_id, b"shared", 6).0,
        0
    );
    assert_eq!(
        call(&mut manager, provider::OP_READ, a.object_id, &[], 2).1,
        b"sh"
    );
    assert_eq!(
        call(&mut manager, provider::OP_READ, b.object_id, &[], 4).1,
        b"ared"
    );
    assert_eq!(
        call(&mut manager, provider::OP_READ, c.object_id, &[], 1),
        (0, vec![])
    );
    assert_eq!(
        call(&mut manager, provider::OP_READ, d.object_id, &[], 1),
        (0, vec![])
    );
    let calls = std::cell::Cell::new(0);
    assert_eq!(
        manager
            .open(
                admit(other, 19, Access::Write, &closed),
                true,
                |_, _, _| {
                    calls.set(1);
                    Ok(1)
                },
                |_| {}
            )
            .err(),
        Some(-6)
    );
    assert_eq!(calls.get(), 0);
    for id in [
        a.object_id,
        b.object_id,
        w.object_id,
        c.object_id,
        d.object_id,
    ] {
        release(&mut manager, id);
    }
    assert_eq!(closed.load(Ordering::Relaxed), 6);
}

#[test]
fn native_creation_failure_does_not_match_pending_peers_or_reuse_object_ids() {
    let scope = FilesystemScope::new().unwrap();
    let closed = Arc::new(AtomicUsize::new(0));
    let mut manager = Manager::default();
    let reader = manager
        .open(
            admit(scope, 17, Access::Read, &closed),
            false,
            |_, rights, options| {
                assert_ne!(rights & mnu_abi::HANDLE_RIGHT_READ, 0);
                assert_eq!(rights & mnu_abi::HANDLE_RIGHT_WRITE, 0);
                assert_eq!(options, 0);
                Ok(1)
            },
            |_| panic!("no close"),
        )
        .unwrap();
    assert!(!manager.readiness(reader.object_id).unwrap().open_ready);
    let failed = std::cell::Cell::new(0);
    assert_eq!(
        manager
            .open(
                admit(scope, 17, Access::Write, &closed),
                true,
                |id, rights, options| {
                    failed.set(id);
                    assert_ne!(rights & mnu_abi::HANDLE_RIGHT_WRITE, 0);
                    assert_eq!(rights & mnu_abi::HANDLE_RIGHT_READ, 0);
                    assert_eq!(options, mnu_abi::HANDLE_OPTION_NONBLOCKING);
                    Err(-12)
                },
                |_| panic!("creation failed before a native reference existed")
            )
            .err(),
        Some(-12)
    );
    assert!(!manager.readiness(reader.object_id).unwrap().open_ready);
    assert_eq!(closed.load(Ordering::Relaxed), 1);
    let writer = open(&mut manager, admit(scope, 17, Access::Write, &closed));
    assert!(writer.object_id > failed.get());
    assert!(manager.readiness(reader.object_id).unwrap().open_ready);
    release(&mut manager, writer.object_id);
    release(&mut manager, reader.object_id);
    assert_eq!(closed.load(Ordering::Relaxed), 3);
}

#[test]
fn last_release_drops_pins_discards_data_and_stale_ids_cannot_touch_recycled_inodes() {
    let scope = FilesystemScope::new().unwrap();
    let closed = Arc::new(AtomicUsize::new(0));
    let mut manager = Manager::default();
    let reader = open(&mut manager, admit(scope, 17, Access::Read, &closed));
    let writer = open(&mut manager, admit(scope, 17, Access::Write, &closed));
    call(
        &mut manager,
        provider::OP_WRITE,
        writer.object_id,
        b"discard",
        7,
    );
    release(&mut manager, writer.object_id);
    assert_eq!(closed.load(Ordering::Relaxed), 1);
    assert!(manager.readiness(reader.object_id).unwrap().hangup);
    release(&mut manager, reader.object_id);
    assert_eq!(closed.load(Ordering::Relaxed), 2);
    let replacement = open(&mut manager, admit(scope, 17, Access::Read, &closed));
    assert!(replacement.object_id > writer.object_id);
    assert_eq!(
        call(
            &mut manager,
            provider::OP_READ,
            replacement.object_id,
            &[],
            10
        ),
        (0, vec![])
    );
    assert_eq!(
        manager
            .handle_provider_request(
                &frame(provider::OP_RELEASE, reader.object_id, &[], 0),
                mnu_abi::IPC_DELIVERY_NATIVE_OBJECT,
                0,
                &mut []
            )
            .err(),
        Some(-9)
    );
    assert!(manager.readiness(replacement.object_id).is_ok());
    release(&mut manager, replacement.object_id);
}

#[test]
fn metadata_duplication_is_attenuated_by_the_attached_data_rights_and_keeps_inode_identity() {
    let scope = FilesystemScope::new().unwrap();
    let closed = Arc::new(AtomicUsize::new(0));
    let mut manager = Manager::default();
    let opened = open(&mut manager, admit(scope, 17, Access::Read, &closed));
    let t = mnu_abi::HANDLE_RIGHT_TRANSFER;
    let c = mnu_abi::HANDLE_RIGHT_CONTROL;
    assert_eq!(manager.duplicate_metadata(opened.object_id, t, t), Ok(1087));
    assert_eq!(
        manager.duplicate_metadata(opened.object_id, t, t | c),
        Err(-13)
    );
    assert_eq!(
        manager.duplicate_metadata(opened.object_id, t | c, t | c),
        Ok(1087)
    );
    assert_eq!(
        manager.duplicate_metadata(
            opened.object_id,
            opened.rights,
            t | mnu_abi::HANDLE_RIGHT_READ
        ),
        Err(-13)
    );
    release(&mut manager, opened.object_id);
    assert_eq!(manager.duplicate_metadata(opened.object_id, t, t), Err(-9));
}

#[test]
fn forged_release_cannot_remove_pins_and_signal_visits_only_cover_affected_peers() {
    let scope = FilesystemScope::new().unwrap();
    let closed = Arc::new(AtomicUsize::new(0));
    let mut manager = Manager::default();
    let reader = open(&mut manager, admit(scope, 17, Access::Read, &closed));
    let other = open(&mut manager, admit(scope, 18, Access::Read, &closed));
    let request = frame(provider::OP_RELEASE, reader.object_id, &[], 0);
    let mut response = [0; provider::RESPONSE_HEADER_LEN];
    let result = manager
        .handle_provider_request(&request, 0, 0, &mut response)
        .unwrap();
    assert_eq!(
        provider::ResponseHeader::decode(&response[..result.reply_length.unwrap()])
            .unwrap()
            .0
            .status,
        -13
    );
    assert_eq!(closed.load(Ordering::Relaxed), 0);
    let mut ids = Vec::new();
    manager
        .visit_signals(reader.channel, |id, _| {
            ids.push(id);
            Ok(())
        })
        .unwrap();
    assert_eq!(ids, [reader.object_id]);
    assert_eq!(
        manager.visit_signals(reader.channel, |_, _| Err(-5)),
        Err(-5)
    );
    release(&mut manager, reader.object_id);
    release(&mut manager, other.object_id);
}

#[test]
fn owner_quotas_bound_channels_and_descriptions_without_creating_native_references() {
    let scope = FilesystemScope::new().unwrap();
    let closed = Arc::new(AtomicUsize::new(0));
    let mut manager = Manager::default();
    let mut ids = Vec::new();
    for inode in 1..=MAX_CHANNELS as u32 {
        ids.push(open(&mut manager, admit(scope, inode, Access::Read, &closed)).object_id);
    }
    assert_eq!(
        manager
            .open(
                admit(scope, 999, Access::Read, &closed),
                true,
                |_, _, _| panic!("quota checked before native creation"),
                |_| {}
            )
            .err(),
        Some(-23)
    );
    for id in ids {
        release(&mut manager, id);
    }
    let mut ids = Vec::new();
    for _ in 0..MAX_DESCRIPTIONS {
        ids.push(open(&mut manager, admit(scope, 17, Access::Read, &closed)).object_id);
    }
    assert_eq!(
        manager
            .open(
                admit(scope, 17, Access::Read, &closed),
                true,
                |_, _, _| panic!("quota checked before native creation"),
                |_| {}
            )
            .err(),
        Some(-23)
    );
    for id in ids {
        release(&mut manager, id);
    }
    assert_eq!(
        closed.load(Ordering::Relaxed),
        MAX_CHANNELS + MAX_DESCRIPTIONS + 2
    );
}

#[test]
fn failed_validation_keeps_caller_ownership_but_failed_adoption_consumes_exactly_one_reference() {
    use mochios_filesystem_protocol as wire;
    use posix_service::fifo_inode::METADATA_RIGHTS;
    let scope = FilesystemScope::new().unwrap();
    let mut payload = vec![0; wire::NODE_STATUS_LEN];
    wire::encode_node_status(
        wire::NodeStatus {
            device: 1,
            node_id: (1 << 32) | 17,
            kind: wire::NODE_TYPE_FIFO,
            ..Default::default()
        },
        &mut payload,
    )
    .unwrap();
    let header = wire::Header {
        opcode: wire::OP_STATUS,
        request_id: 1,
        node_id: (1 << 32) | 17,
        open_id: 3,
        flags: wire::OPEN_REPLY_FIFO,
        length: payload.len() as u32,
        ..Default::default()
    };
    let mut objects = mnu_abi::IpcObjectHandles::default();
    objects.count = 1;
    objects.handles[0] = mnu_abi::IpcObjectHandle {
        handle: 17,
        rights: METADATA_RIGHTS | mnu_abi::HANDLE_RIGHT_READ,
        reserved: 0,
    };
    assert_eq!(
        scope
            .admit(header, 1, &payload, &mut objects, Access::Read, |_| panic!(
                "validation before adoption"
            ))
            .err(),
        Some(-5)
    );
    assert_eq!(objects.count, 1);
    assert_eq!(objects.handles[0].handle, 17);
    objects.handles[0].rights = METADATA_RIGHTS;
    let calls = std::cell::Cell::new(0);
    assert_eq!(
        scope
            .admit(header, 1, &payload, &mut objects, Access::Read, |owned| {
                assert_eq!(owned.handle, 17);
                calls.set(calls.get() + 1);
                Err(13)
            })
            .err(),
        Some(-13)
    );
    assert_eq!(calls.get(), 1);
    assert_eq!(objects.count, 0);
    assert_eq!(objects.handles[0].handle, 0);
}
