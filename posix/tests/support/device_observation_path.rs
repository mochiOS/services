use super::*;
use filesystem_service::{
    devfs::{Attributes, DeviceFilesystem, ExternalDevice, NodeKind},
    device_factory::Factory,
};
use protocol::device_observation::{REQUEST_LEN, Request};

#[derive(Debug)]
struct Calls {
    queries: Vec<Request>,
    reply: Result<Vec<u8>, i32>,
}
#[derive(Debug)]
struct Owner(Arc<Mutex<Calls>>);
impl Factory for Owner {
    fn open(
        &self,
        _: mnu_abi::IpcObjectHandle,
        _: protocol::device_open::Request,
    ) -> Result<mnu_abi::IpcObjectHandle, i32> {
        panic!("path observation must never open device data")
    }
    fn observe(&self, request: Request) -> Result<Vec<u8>, i32> {
        let mut calls = self.0.lock().unwrap();
        calls.queries.push(request);
        calls.reply.clone()
    }
}
fn attrs(mode: u16) -> Attributes {
    Attributes {
        mode,
        uid: 501,
        gid: 20,
    }
}
fn user() -> protocol::Credentials {
    credentials(501, 20, &[])
}
fn observation() -> Request {
    Request {
        selector: 0xabcdef,
        capacity: 16,
    }
}
fn payload(path: &[u8]) -> Vec<u8> {
    let mut bytes = observation().encode().to_vec();
    bytes.extend_from_slice(path);
    bytes
}
fn prepared() -> (FilesystemService, Arc<Mutex<Calls>>) {
    let calls = Arc::new(Mutex::new(Calls {
        queries: vec![],
        reply: Ok(b"owner bytes".to_vec()),
    }));
    let mut devices = DeviceFilesystem::default();
    let root = devices.root();
    devices
        .register_external(
            &root,
            b"terminal",
            attrs(0),
            ExternalDevice {
                special_device: 42,
                factory: Arc::new(Owner(calls.clone())),
            },
        )
        .unwrap();
    let hidden = devices
        .register(&root, b"hidden", NodeKind::Directory, attrs(0))
        .unwrap();
    devices
        .register_external(
            &hidden,
            b"terminal",
            attrs(0),
            ExternalDevice {
                special_device: 43,
                factory: Arc::new(Owner(calls.clone())),
            },
        )
        .unwrap();
    let mut service = test_filesystem();
    service
        .chmod_at(
            protocol::Header {
                mode: 0o755,
                ..Default::default()
            },
            b"/",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap();
    service.mount_devices(b"/dev", devices).unwrap();
    (service, calls)
}
fn query(fs: &FilesystemService, path: &[u8]) -> Result<Vec<u8>, i32> {
    fs.device_observation_at(
        protocol::Header {
            opcode: protocol::OP_DEVICE_OBSERVATION_AT,
            ..Default::default()
        },
        &payload(path),
        PathAnchors::default(),
        user(),
    )
    .map(|r| r.payload)
}

#[test]
fn observation_resolves_the_registered_owner_without_final_data_permission_or_open_allocation() {
    let (mut fs, calls) = prepared();
    let first = fs
        .open_at(
            protocol::Header {
                flags: protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
                ..Default::default()
            },
            b"/",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap()
        .header
        .open_id;
    assert_eq!(query(&fs, b"/dev/terminal").unwrap(), b"owner bytes");
    assert_eq!(calls.lock().unwrap().queries, [observation()]);
    let second = fs
        .open_at(
            protocol::Header {
                flags: protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
                ..Default::default()
            },
            b"/",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap()
        .header
        .open_id;
    assert_eq!(second, first + 1);
    assert_eq!(
        fs.open_at(
            protocol::Header {
                flags: protocol::OPEN_AT_READ,
                ..Default::default()
            },
            b"/dev/terminal",
            PathAnchors::default(),
            user()
        )
        .err(),
        Some(13)
    );
}

#[test]
fn errors_from_traversal_do_not_invoke_the_owner_or_open_a_replacement() {
    let (fs, calls) = prepared();
    for (path, error) in [
        (b"/dev/hidden/terminal".as_slice(), 13),
        (b"/dev/absent", 2),
        (b"/dev/terminal/", 20),
        (b"/dev/null", 95),
        (b"/dev", 95),
        (b"/", 95),
    ] {
        assert_eq!(query(&fs, path).err(), Some(error), "{path:?}");
    }
    assert!(calls.lock().unwrap().queries.is_empty());
}

#[test]
fn symlinks_and_retained_root_base_use_the_same_authenticated_walk() {
    let (mut fs, calls) = prepared();
    let mut link = b"/dev/terminal".to_vec();
    let length = link.len();
    link.extend_from_slice(b"/observation-link");
    fs.symlink_at(
        protocol::Header {
            mode: length as u32,
            ..Default::default()
        },
        &link,
        PathAnchors::default(),
        root_credentials(),
    )
    .unwrap();
    assert_eq!(query(&fs, b"/observation-link").unwrap(), b"owner bytes");
    let directory = fs
        .open_at(
            protocol::Header {
                flags: protocol::OPEN_AT_READ | protocol::OPEN_AT_DIRECTORY,
                ..Default::default()
            },
            b"/dev",
            PathAnchors::default(),
            root_credentials(),
        )
        .unwrap()
        .header
        .open_id;
    let anchors = PathAnchors {
        root_open_id: Some(directory),
        base_open_id: Some(directory),
    };
    let header = protocol::Header {
        flags: protocol::STAT_AT_ROOT_ATTACHED | protocol::STAT_AT_BASE_ATTACHED,
        ..Default::default()
    };
    for path in [b"terminal".as_slice(), b"/terminal", b"../../terminal"] {
        assert_eq!(
            fs.device_observation_at(header, &payload(path), anchors, user())
                .unwrap()
                .payload,
            b"owner bytes"
        );
    }
    assert_eq!(
        fs.device_observation_at(header, &payload(b"/observation-link"), anchors, user())
            .err(),
        Some(2)
    );
    assert_eq!(calls.lock().unwrap().queries.len(), 4);
    fs.provider_close(directory).unwrap();
    assert_eq!(
        fs.device_observation_at(header, &payload(b"terminal"), anchors, user())
            .err(),
        Some(9)
    );
}

#[test]
fn malformed_framing_and_anchor_flags_never_reach_a_factory() {
    let (fs, calls) = prepared();
    let valid = payload(b"/dev/terminal");
    for length in 0..REQUEST_LEN {
        assert_eq!(
            fs.device_observation_at(
                Default::default(),
                &valid[..length],
                PathAnchors::default(),
                user()
            )
            .err(),
            Some(22)
        );
    }
    assert_eq!(query(&fs, b"").err(), Some(2));
    for header in [
        protocol::Header {
            flags: protocol::STAT_AT_NOFOLLOW,
            ..Default::default()
        },
        protocol::Header {
            flags: protocol::STAT_AT_BASE_ATTACHED,
            ..Default::default()
        },
        protocol::Header {
            flags: protocol::STAT_AT_ROOT_ATTACHED,
            ..Default::default()
        },
        protocol::Header {
            open_id: 123,
            ..Default::default()
        },
        protocol::Header {
            node_id: 1,
            ..Default::default()
        },
    ] {
        assert_eq!(
            fs.device_observation_at(header, &valid, PathAnchors::default(), user())
                .err(),
            Some(22)
        );
    }
    let mut bad = valid.clone();
    bad[20] = 1;
    assert_eq!(
        fs.device_observation_at(Default::default(), &bad, PathAnchors::default(), user())
            .err(),
        Some(22)
    );
    assert!(calls.lock().unwrap().queries.is_empty());
}

#[test]
fn owner_failure_and_overlong_reply_are_not_replaced_with_filesystem_defaults() {
    let (fs, calls) = prepared();
    for error in [5, 9, 13, 95] {
        calls.lock().unwrap().reply = Err(error);
        assert_eq!(query(&fs, b"/dev/terminal"), Err(error));
    }
    calls.lock().unwrap().reply = Ok(vec![0; 17]);
    assert_eq!(query(&fs, b"/dev/terminal"), Err(5));
    assert_eq!(calls.lock().unwrap().queries.len(), 5);
}
