use super::{
    FilesystemService, Fixture, PathAnchors, configure_received_device, device_open,
    root_credentials,
};
use filesystem_service::{
    device_factory::Factory,
    open_publication::{self, METADATA_RIGHTS, Publisher},
};
use mnu_abi::{
    HANDLE_RIGHT_CONTROL as C, HANDLE_RIGHT_DUPLICATE as D, HANDLE_RIGHT_SEND as S,
    HANDLE_RIGHT_TRANSFER as T, IpcObjectHandle, IpcObjectHandles,
};
use mochios_filesystem_protocol as wire;
use std::sync::{Arc, Mutex};

#[derive(Debug, Default)]
struct State {
    calls: Vec<(IpcObjectHandle, wire::device_open::Request)>,
    error: Option<i32>,
    malformed: Option<IpcObjectHandle>,
}
#[derive(Debug)]
struct Device(Arc<Mutex<State>>);
impl Factory for Device {
    fn open(
        &self,
        metadata: IpcObjectHandle,
        request: wire::device_open::Request,
    ) -> Result<IpcObjectHandle, i32> {
        let mut state = self.0.lock().unwrap();
        state.calls.push((metadata, request));
        if let Some(error) = state.error {
            return Err(error);
        }
        Ok(state.malformed.unwrap_or(IpcObjectHandle {
            handle: 1000 + state.calls.len() as u32,
            reserved: 0,
            rights: request.rights,
        }))
    }
}
#[derive(Default)]
struct Native {
    created: Vec<(u64, u64)>,
    closed: Vec<u32>,
    error: Option<i32>,
}
impl Publisher for Native {
    fn create(&mut self, id: u64, rights: u64) -> Result<u32, i32> {
        self.created.push((id, rights));
        self.error.map_or(Ok(900), Err)
    }
    fn close(&mut self, handle: u32) {
        self.closed.push(handle);
    }
}

fn fixture(f: &Fixture, name: &str) -> (FilesystemService, u64, Arc<Mutex<State>>) {
    let mut service = FilesystemService::new(f.volume(name));
    service
        .mount_devices(
            b"/managed",
            filesystem_service::devfs::DeviceFilesystem::default(),
        )
        .unwrap();
    let parent = device_open(
        &mut service,
        b"/managed",
        wire::OPEN_AT_READ | wire::OPEN_AT_DIRECTORY,
        PathAnchors::default(),
    )
    .unwrap();
    let calls = Arc::new(Mutex::new(State::default()));
    let mut payload = vec![0; wire::device_registration::HEADER_LEN + 6];
    let length = wire::device_registration::encode(
        wire::device_registration::Request {
            mode: 0o620,
            uid: 501,
            gid: 20,
            special_device: 0x1234_5678,
            name: b"device",
        },
        &mut payload,
    )
    .unwrap();
    let mut received = IpcObjectHandles::default();
    received.delivery_flags = mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE;
    received.count = 3;
    for (slot, (handle, rights)) in
        received
            .handles
            .iter_mut()
            .zip([(70, C | T), (71, S), (72, D | T)])
    {
        *slot = IpcObjectHandle {
            handle,
            reserved: 0,
            rights,
        };
    }
    filesystem_service::device_registration_ipc::handle(
        &mut service,
        wire::Header {
            opcode: wire::OP_DEVICE_NODE_REGISTER_EXTERNAL,
            length: length as u32,
            ..Default::default()
        },
        &payload,
        &mut received,
        |_| Ok(parent),
        |_, _| Ok(Arc::new(Device(calls.clone()))),
    )
    .unwrap();
    (service, parent, calls)
}

#[test]
fn ordinary_and_admitted_opens_publish_real_owner_data_not_filesystem_byte_streams() {
    for admitted in [false, true] {
        let f = Fixture::new();
        let (mut service, _, calls) = fixture(&f, "external-publish");
        let flags = wire::OPEN_AT_READ | wire::OPEN_AT_NONBLOCK;
        let id = if admitted {
            match service.open_at_admitted(
                wire::Header {
                    flags,
                    ..Default::default()
                },
                b"/managed/device",
                PathAnchors::default(),
                root_credentials(),
                None,
            ) {
                filesystem_service::memory_updates::MutationResult::Complete(Ok(response)) => {
                    response.header.open_id
                }
                _ => panic!("external open must not enter regular-file growth admission"),
            }
        } else {
            device_open(
                &mut service,
                b"/managed/device",
                flags,
                PathAnchors::default(),
            )
            .unwrap()
        };
        let mut native = Native::default();
        assert!(calls.lock().unwrap().calls.is_empty());
        let opened = open_publication::publish(
            &mut service,
            id,
            filesystem_service::handle_access::open_rights(flags),
            &mut native,
        )
        .unwrap();
        assert_eq!(opened.handle, 1001);
        assert_eq!(native.created, [(id, METADATA_RIGHTS)]);
        assert_eq!(native.closed, [900]);
        let state = calls.lock().unwrap();
        assert_eq!(state.calls.len(), 1);
        assert_eq!(state.calls[0].0.rights, C | D | T);
        assert_eq!(state.calls[0].1.options, mnu_abi::HANDLE_OPTION_NONBLOCKING);
        assert_eq!(opened.rights, state.calls[0].1.rights);
        assert_eq!(opened.rights & mnu_abi::HANDLE_RIGHT_WRITE, 0);
        assert_ne!(opened.rights & mnu_abi::HANDLE_RIGHT_READ, 0);
        drop(state);
        assert_eq!(service.provider_read(id, 1), Err(95));
        assert_eq!(service.provider_write(id, b"x"), Err(95));
        assert_eq!(
            service.provider_seek(id, 0, mnu_abi::HANDLE_SEEK_START),
            Err(95)
        );
        assert!(matches!(
            service.get_flags_handle(wire::Header::default(), id),
            Err(95)
        ));
        // Local metadata close must not retire an inode still retained by the
        // data owner. Model native final-reference release explicitly.
        let status = service.stat_handle(wire::Header::default(), id).unwrap();
        assert_eq!(
            wire::decode_node_status(&status.payload)
                .unwrap()
                .special_device,
            0x1234_5678
        );
        service.provider_close(id).unwrap();
        assert!(matches!(
            service.stat_handle(wire::Header::default(), id),
            Err(9)
        ));
    }
}

#[test]
fn failed_creation_retires_unpublished_metadata_but_factory_failure_waits_for_native_release() {
    for factory_failure in [false, true] {
        let f = Fixture::new();
        let (mut service, _, calls) = fixture(&f, "external-publication-failure");
        let id = device_open(
            &mut service,
            b"/managed/device",
            wire::OPEN_AT_READ,
            PathAnchors::default(),
        )
        .unwrap();
        let mut native = Native {
            error: (!factory_failure).then_some(12),
            ..Default::default()
        };
        calls.lock().unwrap().error = factory_failure.then_some(5);
        assert_eq!(
            open_publication::publish(&mut service, id, 0, &mut native),
            Err(if factory_failure { 5 } else { 12 })
        );
        if factory_failure {
            assert_eq!(native.closed, [900]);
            assert!(service.stat_handle(wire::Header::default(), id).is_ok());
            service.provider_close(id).unwrap();
        } else {
            assert!(native.closed.is_empty());
            assert!(calls.lock().unwrap().calls.is_empty());
            assert!(matches!(
                service.stat_handle(wire::Header::default(), id),
                Err(9)
            ));
        }
    }
}

#[test]
fn malformed_factory_data_is_reclaimed_without_double_closing_metadata_aliases() {
    for (handle, rights, reserved, expected) in [
        (1001, 0, 0, vec![1001, 900]),
        (1001, u64::MAX, 1, vec![1001, 900]),
        (900, 0, 0, vec![900]),
        (0, 0, 0, vec![900]),
    ] {
        let f = Fixture::new();
        let (mut service, _, calls) = fixture(&f, "external-malformed-publication");
        let id = device_open(
            &mut service,
            b"/managed/device",
            wire::OPEN_AT_READ,
            PathAnchors::default(),
        )
        .unwrap();
        calls.lock().unwrap().malformed = Some(IpcObjectHandle {
            handle,
            rights,
            reserved,
        });
        let mut native = Native::default();
        assert_eq!(
            open_publication::publish(&mut service, id, 0, &mut native),
            Err(5)
        );
        assert_eq!(native.closed, expected);
        assert!(service.stat_handle(wire::Header::default(), id).is_ok());
    }
}

#[test]
fn unpublished_device_metadata_and_factory_identity_survive_name_removal() {
    let f = Fixture::new();
    let (mut service, parent, calls) = fixture(&f, "external-unpublished-node");
    let id = device_open(
        &mut service,
        b"/managed/device",
        wire::OPEN_AT_READ,
        PathAnchors::default(),
    )
    .unwrap();
    configure_received_device(
        &mut service,
        parent,
        wire::OP_DEVICE_NODE_REMOVE,
        wire::device_namespace::Request {
            kind: 0,
            mode: 0,
            uid: 0,
            gid: 0,
            name: b"device",
        },
    )
    .unwrap();
    let mut native = Native::default();
    let opened = open_publication::publish(&mut service, id, 0, &mut native).unwrap();
    assert_eq!(opened.handle, 1001);
    assert_eq!(calls.lock().unwrap().calls.len(), 1);
    let status = service.stat_handle(wire::Header::default(), id).unwrap();
    assert_eq!(
        wire::decode_node_status(&status.payload)
            .unwrap()
            .link_count,
        0
    );
}

#[test]
fn ordinary_descriptions_keep_requested_rights_and_share_the_publication_path() {
    let f = Fixture::new();
    let mut service = FilesystemService::new(f.volume("ordinary-publication"));
    let id = device_open(
        &mut service,
        b"/file",
        wire::OPEN_AT_READ,
        PathAnchors::default(),
    )
    .unwrap();
    let mut native = Native::default();
    let rights = filesystem_service::handle_access::open_rights(wire::OPEN_AT_READ);
    let opened = open_publication::publish(&mut service, id, rights, &mut native).unwrap();
    assert_eq!((opened.handle, opened.rights), (900, rights));
    assert!(native.closed.is_empty());
    let source = include_str!("../../../filesystem/src/main.rs");
    assert_eq!(
        source.matches("open_publication::publish_native(").count(),
        2
    );
    let admitted = source
        .split("fn reply_admitted_mutation(")
        .nth(1)
        .unwrap()
        .split("fn decode_open_pair(")
        .next()
        .unwrap();
    assert!(!admitted.contains("service.provider_close("));
}

#[test]
fn repeated_opens_get_distinct_descriptions_and_denied_access_never_reaches_factory() {
    let f = Fixture::new();
    let (mut service, _, calls) = fixture(&f, "external-independent-opens");
    let one = device_open(
        &mut service,
        b"/managed/device",
        wire::OPEN_AT_READ,
        PathAnchors::default(),
    )
    .unwrap();
    let two = device_open(
        &mut service,
        b"/managed/device",
        wire::OPEN_AT_WRITE,
        PathAnchors::default(),
    )
    .unwrap();
    assert_ne!(one, two);
    let mut native = Native::default();
    let reader = open_publication::publish(&mut service, one, 0, &mut native).unwrap();
    let writer = open_publication::publish(&mut service, two, 0, &mut native).unwrap();
    assert_ne!(reader.handle, writer.handle);
    assert_eq!(reader.rights & mnu_abi::HANDLE_RIGHT_WRITE, 0);
    assert_eq!(writer.rights & mnu_abi::HANDLE_RIGHT_READ, 0);
    assert_eq!(
        native.created,
        [(one, METADATA_RIGHTS), (two, METADATA_RIGHTS)]
    );
    let mut denied = root_credentials();
    denied.effective_uid = 999;
    denied.effective_gid = 999;
    assert!(matches!(
        service.open_at(
            wire::Header {
                flags: wire::OPEN_AT_READ,
                ..Default::default()
            },
            b"/managed/device",
            PathAnchors::default(),
            denied
        ),
        Err(13)
    ));
    assert_eq!(calls.lock().unwrap().calls.len(), 2);
}

#[test]
fn publication_failure_cannot_claim_retry_without_a_ticket() {
    let f = Fixture::new();
    let (mut service, _, calls) = fixture(&f, "external-terminal-publication-error");
    let id = device_open(
        &mut service,
        b"/managed/device",
        wire::OPEN_AT_READ,
        PathAnchors::default(),
    )
    .unwrap();
    calls.lock().unwrap().error = Some(wire::ERROR_MEMORY_ADMISSION_BUSY);
    let mut native = Native::default();
    assert_eq!(
        open_publication::publish(&mut service, id, 0, &mut native),
        Err(5)
    );
    assert_eq!(native.closed, [900]);
    assert!(service.stat_handle(wire::Header::default(), id).is_ok());
}
