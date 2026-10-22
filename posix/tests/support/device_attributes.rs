use super::{FilesystemService, Fixture, PathAnchors, configure_received_device, device_open};
use ext4plus::inode::InodeTimestamp;
use mochios_filesystem_protocol as wire;
use std::cell::Cell;

thread_local! {
    static CLOCK_ERROR: Cell<i32> = const { Cell::new(0) };
    static CLOCK_CALLS: Cell<u32> = const { Cell::new(0) };
}
fn clock() -> Result<InodeTimestamp, i32> {
    CLOCK_CALLS.set(CLOCK_CALLS.get() + 1);
    match CLOCK_ERROR.get() {
        0 => Ok(InodeTimestamp {
            seconds: -7,
            nanoseconds: 321,
        }),
        -1 => Ok(InodeTimestamp {
            seconds: 1,
            nanoseconds: 1_000_000_000,
        }),
        error => Err(error),
    }
}
fn credentials(uid: u32, gid: u32, groups: &[u32]) -> wire::Credentials {
    let mut bytes = [0; 256];
    let len = wire::encode_credentials_payload(uid, gid, groups, &[], &mut bytes).unwrap();
    wire::decode_credentials_payload(&bytes[..len]).unwrap().0
}
fn fixture(f: &Fixture) -> (FilesystemService, u64, u64) {
    CLOCK_ERROR.set(0);
    CLOCK_CALLS.set(0);
    let mut service = FilesystemService::new_with_clock(f.volume("device-attributes"), clock);
    service
        .mount_devices(
            b"/dev",
            filesystem_service::devfs::DeviceFilesystem::default(),
        )
        .unwrap();
    let parent = device_open(
        &mut service,
        b"/dev",
        wire::OPEN_AT_READ | wire::OPEN_AT_DIRECTORY,
        PathAnchors::default(),
    )
    .unwrap();
    configure(
        &mut service,
        parent,
        wire::OP_DEVICE_NODE_SET_ATTRIBUTES,
        0o660,
        501,
        20,
    );
    let file = device_open(
        &mut service,
        b"/dev/null",
        wire::OPEN_AT_WRITE,
        PathAnchors::default(),
    )
    .unwrap();
    (service, parent, file)
}
fn configure(
    service: &mut FilesystemService,
    parent: u64,
    opcode: u16,
    mode: u16,
    uid: u32,
    gid: u32,
) {
    configure_received_device(
        service,
        parent,
        opcode,
        wire::device_namespace::Request {
            kind: if opcode == wire::OP_DEVICE_NODE_CREATE {
                wire::device_namespace::KIND_NULL
            } else {
                0
            },
            mode,
            uid,
            gid,
            name: b"null",
        },
    )
    .unwrap();
}
fn status(service: &FilesystemService, file: u64) -> wire::NodeStatus {
    wire::decode_node_status(
        &service
            .stat_handle(wire::Header::default(), file)
            .unwrap()
            .payload,
    )
    .unwrap()
}
fn chmod(
    service: &mut FilesystemService,
    file: u64,
    mode: u32,
    caller: wire::Credentials,
) -> Result<(), i32> {
    service
        .chmod_handle(
            wire::Header {
                mode,
                ..Default::default()
            },
            file,
            caller,
        )
        .map(|_| ())
}
fn chown(
    service: &mut FilesystemService,
    file: u64,
    uid: u32,
    gid: u32,
    caller: wire::Credentials,
) -> Result<(), i32> {
    service
        .chown_handle(
            wire::Header {
                node_id: u64::from(uid) | (u64::from(gid) << 32),
                ..Default::default()
            },
            file,
            caller,
        )
        .map(|_| ())
}

#[test]
fn chmod_checks_fresh_owner_and_group_then_updates_shared_inode_and_ctime() {
    let f = Fixture::new();
    let (mut service, parent, file) = fixture(&f);
    let alias = device_open(
        &mut service,
        b"/dev/null",
        wire::OPEN_AT_READ,
        PathAnchors::default(),
    )
    .unwrap();
    for (caller, expected) in [
        (credentials(501, 20, &[]), 0o6750),
        (credentials(501, 30, &[20]), 0o6750),
        (credentials(501, 30, &[]), 0o4750),
        (credentials(0, 30, &[]), 0o6750),
    ] {
        chmod(&mut service, file, 0o6750, caller).unwrap();
        let node = status(&service, alias);
        assert_eq!(node.mode, 0o020000 | expected);
        assert_eq!((node.uid, node.gid), (501, 20));
        assert_eq!(
            (node.change_time_seconds, node.change_time_nanoseconds),
            (-7, 321)
        );
    }
    configure(
        &mut service,
        parent,
        wire::OP_DEVICE_NODE_SET_ATTRIBUTES,
        0o660,
        999,
        20,
    );
    let before = status(&service, file);
    assert_eq!(
        chmod(&mut service, file, 0o600, credentials(501, 20, &[])),
        Err(1)
    );
    assert_eq!(status(&service, file), before);
    chmod(&mut service, file, 0, credentials(999, 20, &[])).unwrap();
    assert_eq!(service.provider_write(file, b"retained"), Ok(8));
    assert!(matches!(
        service.open_at(
            wire::Header {
                flags: wire::OPEN_AT_WRITE,
                ..Default::default()
            },
            b"/dev/null",
            PathAnchors::default(),
            credentials(999, 20, &[])
        ),
        Err(13)
    ));
}

#[test]
fn chown_restricts_owner_and_group_changes_and_clears_set_id_only_when_requested() {
    let f = Fixture::new();
    let (mut service, parent, file) = fixture(&f);
    for (caller, uid, gid, expected) in [
        (credentials(502, 20, &[]), u32::MAX, u32::MAX, Err(1)),
        (credentials(501, 20, &[]), 999, 20, Err(1)),
        (credentials(501, 20, &[]), u32::MAX, 30, Err(1)),
        (credentials(501, 20, &[30]), 501, 30, Ok(())),
        (credentials(501, 30, &[]), u32::MAX, 30, Ok(())),
        (credentials(0, 0, &[]), 999, 44, Ok(())),
        (credentials(501, 20, &[]), u32::MAX, u32::MAX, Ok(())),
    ] {
        configure(
            &mut service,
            parent,
            wire::OP_DEVICE_NODE_SET_ATTRIBUTES,
            0o6660,
            501,
            20,
        );
        let before = status(&service, file);
        assert_eq!(chown(&mut service, file, uid, gid, caller), expected);
        let after = status(&service, file);
        if expected.is_err() {
            assert_eq!(after, before);
        } else {
            assert_eq!(after.uid, if uid == u32::MAX { 501 } else { uid });
            assert_eq!(after.gid, if gid == u32::MAX { 20 } else { gid });
            assert_eq!(
                after.mode & 0o7777,
                if uid == u32::MAX && gid == u32::MAX {
                    0o6660
                } else {
                    0o660
                }
            );
        }
    }
}

#[test]
fn clock_failures_never_partially_change_metadata_and_denials_do_not_read_clock() {
    let f = Fixture::new();
    let (mut service, _, file) = fixture(&f);
    for error in [5, -1] {
        CLOCK_ERROR.set(error);
        let before = status(&service, file);
        let expected = if error == -1 { 22 } else { error };
        assert_eq!(
            chmod(&mut service, file, 0o600, credentials(501, 20, &[])),
            Err(expected)
        );
        assert_eq!(status(&service, file), before);
        assert_eq!(
            chown(&mut service, file, 999, 99, credentials(0, 0, &[])),
            Err(expected)
        );
        assert_eq!(status(&service, file), before);
    }
    CLOCK_CALLS.set(0);
    assert_eq!(
        chmod(&mut service, file, 0o600, credentials(502, 20, &[])),
        Err(1)
    );
    assert_eq!(
        chown(&mut service, file, 999, 99, credentials(501, 20, &[])),
        Err(1)
    );
    assert_eq!(CLOCK_CALLS.get(), 0);
}

#[test]
fn removed_open_inode_can_change_without_touching_replacement_and_close_retires_authority() {
    let f = Fixture::new();
    let (mut service, parent, file) = fixture(&f);
    configure(&mut service, parent, wire::OP_DEVICE_NODE_REMOVE, 0, 0, 0);
    configure(
        &mut service,
        parent,
        wire::OP_DEVICE_NODE_CREATE,
        0o666,
        900,
        44,
    );
    let replacement = device_open(
        &mut service,
        b"/dev/null",
        wire::OPEN_AT_READ,
        PathAnchors::default(),
    )
    .unwrap();
    let before = status(&service, replacement);
    chmod(&mut service, file, 0o600, credentials(501, 20, &[])).unwrap();
    chown(&mut service, file, 700, 30, credentials(0, 0, &[])).unwrap();
    assert_eq!(status(&service, replacement), before);
    let old = status(&service, file);
    assert_ne!(old.node_id, before.node_id);
    assert_eq!(
        (old.link_count, old.uid, old.gid, old.mode & 0o7777),
        (0, 700, 30, 0o600)
    );
    service.provider_close(file).unwrap();
    assert_eq!(
        chmod(&mut service, file, 0o600, credentials(0, 0, &[])),
        Err(9)
    );
    assert_eq!(
        chown(&mut service, file, 0, 0, credentials(0, 0, &[])),
        Err(9)
    );
    for opcode in [wire::OP_CHMOD_HANDLE, wire::OP_CHOWN_HANDLE] {
        assert_eq!(
            filesystem_service::handle_access::authorize(opcode, mnu_abi::HANDLE_RIGHT_TRANSFER),
            Err(13)
        );
    }
}

#[test]
fn pathname_updates_share_fd_ownership_group_rules_and_atomic_clock_failure() {
    let f = Fixture::new();
    let (mut service, parent, file) = fixture(&f);
    for relative in [false, true] {
        configure(
            &mut service,
            parent,
            wire::OP_DEVICE_NODE_SET_ATTRIBUTES,
            0o660,
            501,
            20,
        );
        let (path, anchors, chmod_flags, chown_flags) = if relative {
            (
                b"null".as_slice(),
                PathAnchors {
                    root_open_id: Some(parent),
                    base_open_id: Some(parent),
                },
                wire::CHMOD_AT_ROOT_ATTACHED | wire::CHMOD_AT_BASE_ATTACHED,
                wire::CHOWN_AT_ROOT_ATTACHED | wire::CHOWN_AT_BASE_ATTACHED,
            )
        } else {
            (b"/dev/null".as_slice(), PathAnchors::default(), 0, 0)
        };
        let chmod = wire::Header {
            mode: 0o2660,
            flags: chmod_flags,
            ..Default::default()
        };
        service
            .chmod_at(chmod, path, anchors, credentials(501, 30, &[]))
            .unwrap();
        assert_eq!(status(&service, file).mode & 0o7777, 0o660);
        service
            .chmod_at(chmod, path, anchors, credentials(501, 30, &[20]))
            .unwrap();
        assert_eq!(status(&service, file).mode & 0o7777, 0o2660);
        let chown_request = wire::Header {
            node_id: (30u64 << 32) | u64::from(u32::MAX),
            flags: chown_flags,
            ..Default::default()
        };
        let before = status(&service, file);
        assert!(matches!(
            service.chown_at(chown_request, path, anchors, credentials(501, 20, &[])),
            Err(1)
        ));
        assert_eq!(status(&service, file), before);
        service
            .chown_at(chown_request, path, anchors, credentials(501, 20, &[30]))
            .unwrap();
        assert_eq!(
            (
                status(&service, file).gid,
                status(&service, file).mode & 0o7777
            ),
            (30, 0o660)
        );
        let before = status(&service, file);
        CLOCK_ERROR.set(5);
        assert!(matches!(
            service.chmod_at(chmod, path, anchors, credentials(501, 30, &[])),
            Err(5)
        ));
        assert_eq!(status(&service, file), before);
        CLOCK_ERROR.set(0);
        chown(&mut service, file, 999, 99, credentials(0, 0, &[])).unwrap();
        let before = status(&service, file);
        assert!(matches!(
            service.chmod_at(chmod, path, anchors, credentials(501, 30, &[])),
            Err(1)
        ));
        assert_eq!(status(&service, file), before);
    }
}

#[test]
fn pathname_metadata_mutations_cannot_escape_a_retained_device_root() {
    let f = Fixture::new();
    let (mut service, parent, file) = fixture(&f);
    let anchors = PathAnchors {
        root_open_id: Some(parent),
        base_open_id: Some(parent),
    };
    let chmod = wire::Header {
        mode: 0o600,
        flags: wire::CHMOD_AT_ROOT_ATTACHED | wire::CHMOD_AT_BASE_ATTACHED,
        ..Default::default()
    };
    service
        .chmod_at(chmod, b"../../null", anchors, credentials(501, 20, &[]))
        .unwrap();
    assert_eq!(status(&service, file).mode & 0o7777, 0o600);
    for path in [b"../../file".as_slice(), b"/file"] {
        assert!(matches!(
            service.chmod_at(chmod, path, anchors, credentials(0, 0, &[])),
            Err(2)
        ));
        assert!(matches!(
            service.chown_at(
                wire::Header {
                    node_id: 0,
                    flags: wire::CHOWN_AT_ROOT_ATTACHED | wire::CHOWN_AT_BASE_ATTACHED,
                    ..Default::default()
                },
                path,
                anchors,
                credentials(0, 0, &[])
            ),
            Err(2)
        ));
    }
    let before = status(&service, file);
    service.provider_close(parent).unwrap();
    assert!(matches!(
        service.chmod_at(chmod, b"null", anchors, credentials(0, 0, &[])),
        Err(9)
    ));
    assert_eq!(status(&service, file), before);
}
