use super::*;
use posix_service::read_scope::Registry;
use protocol::read_scope as wire;
use std::sync::{Arc, Mutex};

fn header(opcode: u16, payload: &[u8]) -> protocol::Header {
    protocol::Header {
        opcode,
        request_id: 259,
        payload_len: payload.len() as u32,
        ..Default::default()
    }
}

fn identity(state: &Mutex<PosixService>, peer: PeerIdentity, opcode: u16, value: u32) {
    let mut bytes = [0; protocol::CREDENTIAL_ID_PAYLOAD_LEN];
    protocol::encode_credential_id(value, &mut bytes).unwrap();
    assert_eq!(
        state
            .lock()
            .unwrap()
            .handle(peer, header(opcode, &bytes), &bytes)
            .header
            .status,
        0
    );
}

fn setup() -> (
    Arc<Mutex<PosixService>>,
    PeerIdentity,
    RecordingFilesystem,
    Registry<u32>,
) {
    let peer = PeerIdentity {
        process_id: 259,
        effective_uid: 0,
        effective_gid: 0,
    };
    let mut service = PosixService::new();
    service
        .initialize_bootstrap_process(
            AuthenticatedProcess {
                handle: 259,
                process_id: 259,
            },
            0,
            0,
            &[20, 42],
        )
        .unwrap();
    let state = Arc::new(Mutex::new(service));
    identity(&state, peer, protocol::OP_SET_EFFECTIVE_GID, 20);
    identity(&state, peer, protocol::OP_SET_EFFECTIVE_UID, 501);
    let observed = state.clone();
    let fs = RecordingFilesystem {
        open_rights: Some(
            wire::FILE_RIGHTS | mnu_abi::HANDLE_RIGHT_CONTROL | mnu_abi::HANDLE_RIGHT_SEEK,
        ),
        open_hook: Some(Box::new(move || {
            assert!(observed.try_lock().is_ok(), "FS RPC must be unlocked")
        })),
        ..Default::default()
    };
    (state, peer, fs, Registry::default())
}

fn create(
    state: &Mutex<PosixService>,
    peer: PeerIdentity,
    fs: &mut RecordingFilesystem,
    scopes: &mut Registry<u32>,
) -> u64 {
    let mut id = 0;
    let result = scopes.execute(
        state,
        peer,
        header(wire::OP_CREATE, &[]),
        &[],
        &[],
        fs,
        |value| {
            id = value;
            Ok(800)
        },
        |_| panic!("create has no incoming token"),
    );
    assert_eq!(result.response.header.status, 0);
    assert_eq!(
        result.handles,
        [OpenedObject {
            handle: 800,
            rights: wire::TOKEN_RIGHTS
        }]
    );
    id
}

fn invoke(
    state: &Mutex<PosixService>,
    peer: PeerIdentity,
    fs: &mut RecordingFilesystem,
    scopes: &mut Registry<u32>,
    id: u64,
    opcode: u16,
    payload: &[u8],
) -> posix_service::ObjectResponse<u32> {
    scopes.execute(
        state,
        peer,
        header(opcode, payload),
        payload,
        &[AttachedObject {
            handle: 900,
            rights: wire::ATTACH_RIGHTS,
        }],
        fs,
        |_| panic!("use must not allocate a token"),
        |_| Ok(id),
    )
}

fn path(base: protocol::OpenBase, options: u32) -> Vec<u8> {
    let mut bytes = vec![0; 128];
    let length = protocol::encode_open_at(
        protocol::OpenAtRequest {
            base,
            options,
            mode: 0,
            path: b"library-\xff.so",
        },
        &mut bytes,
    )
    .unwrap();
    bytes.truncate(length);
    bytes
}

fn release(
    scopes: &mut Registry<u32>,
    id: u64,
    flags: u32,
    count: usize,
    fs: &mut RecordingFilesystem,
) -> Result<(), i32> {
    let mut bytes = [0; mnu_abi::provider::REQUEST_HEADER_LEN];
    let length = mnu_abi::provider::RequestHeader {
        opcode: mnu_abi::provider::OP_RELEASE,
        object_id: id,
        argument: 0,
        basis: 0,
        length: 0,
        data_length: 0,
    }
    .encode(&[], &mut bytes)
    .unwrap();
    scopes.release_native(&bytes[..length], flags, count, fs)
}

#[test]
fn receiver_uses_captured_credentials_groups_and_anchors_after_source_changes() {
    let (state, peer, mut fs, mut scopes) = setup();
    let id = create(&state, peer, &mut fs, &mut scopes);
    assert_eq!(fs.root_credentials, Some((501, 20, vec![20, 42])));
    let captured = (fs.retained[2].handle + 1000, fs.retained[3].handle + 1000);
    identity(&state, peer, protocol::OP_SET_EFFECTIVE_UID, 0);
    identity(&state, peer, protocol::OP_SET_EFFECTIVE_GID, 0);
    // A real source cwd mutation releases its old reference. The captured
    // scope owns separate references and still resolves from its old cwd.
    let mut payload = [0; 128];
    let length = protocol::encode_stat_at(
        protocol::StatAtRequest {
            base: protocol::OpenBase::ProcessRoot,
            flags: 0,
            path: b"new-cwd",
        },
        &mut payload,
    )
    .unwrap();
    let reply = state.lock().unwrap().handle_objects(
        peer,
        header(protocol::OP_CHDIR_AT, &payload[..length]),
        &payload[..length],
        &[],
        &mut fs,
    );
    assert_eq!(reply.response.header.status, 0);
    let broker = PeerIdentity {
        process_id: 999,
        effective_uid: 0,
        effective_gid: 0,
    };
    let info = invoke(&state, broker, &mut fs, &mut scopes, id, wire::OP_INFO, &[]);
    let info = protocol::decode_session_info(&info.response.payload).unwrap();
    assert_eq!(
        (
            info.real_uid,
            info.effective_uid,
            info.real_gid,
            info.effective_gid
        ),
        (0, 501, 0, 20)
    );
    for base in [
        protocol::OpenBase::ProcessRoot,
        protocol::OpenBase::ProcessCwd,
    ] {
        let response = invoke(
            &state,
            broker,
            &mut fs,
            &mut scopes,
            id,
            wire::OP_OPEN,
            &path(base, protocol::OPEN_READ | protocol::OPEN_NONBLOCK),
        );
        assert_eq!(response.response.header.status, 0);
        assert_eq!(
            response.handles,
            [OpenedObject {
                handle: 1200,
                rights: wire::FILE_RIGHTS
            }]
        );
        let request = fs.request.as_ref().unwrap();
        assert_eq!((request.effective_uid, request.effective_gid), (501, 20));
        assert_eq!(request.supplementary_groups, [20, 42]);
        assert_eq!(request.path, b"library-\xff.so");
        assert_eq!(fs.root.unwrap().handle, captured.0);
        assert_eq!(
            fs.directory.map(|object| object.handle),
            (base == protocol::OpenBase::ProcessCwd).then_some(captured.1)
        );
        assert_eq!(fs.retained.last().unwrap().rights, wire::FILE_RIGHTS);
        assert_eq!(fs.released.last().unwrap().handle, 200);
    }
}

#[test]
fn only_authenticated_native_final_release_retires_scope_and_ids_are_not_reused() {
    let (state, peer, mut fs, mut scopes) = setup();
    let id = create(&state, peer, &mut fs, &mut scopes);
    let before = fs.released.len();
    for (flags, count) in [
        (0, 0),
        (mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE, 0),
        (mnu_abi::IPC_DELIVERY_NATIVE_OBJECT, 1),
    ] {
        assert_eq!(release(&mut scopes, id, flags, count, &mut fs), Err(-1));
        assert_eq!(fs.released.len(), before);
    }
    release(
        &mut scopes,
        id,
        mnu_abi::IPC_DELIVERY_NATIVE_OBJECT,
        0,
        &mut fs,
    )
    .unwrap();
    assert_eq!(fs.released.len(), before + 2);
    assert_eq!(
        invoke(&state, peer, &mut fs, &mut scopes, id, wire::OP_INFO, &[])
            .response
            .header
            .status,
        -9
    );
    let newer = create(&state, peer, &mut fs, &mut scopes);
    assert!(newer > id);
    release(
        &mut scopes,
        id,
        mnu_abi::IPC_DELIVERY_NATIVE_OBJECT,
        0,
        &mut fs,
    )
    .unwrap();
    assert_eq!(
        invoke(
            &state,
            peer,
            &mut fs,
            &mut scopes,
            newer,
            wire::OP_INFO,
            &[]
        )
        .response
        .header
        .status,
        0
    );
}

#[test]
fn capture_and_publication_failures_release_every_partial_reference() {
    for failure in 1..=5 {
        let (state, peer, mut fs, mut scopes) = setup();
        fs.retain_failure_at = (failure < 5).then_some(failure);
        let response = scopes.execute(
            &state,
            peer,
            header(wire::OP_CREATE, &[]),
            &[],
            &[],
            &mut fs,
            |_| Err(-12),
            |_| unreachable!(),
        );
        assert_eq!(
            response.response.header.status,
            if failure == 5 { -12 } else { -5 }
        );
        let expected = if failure == 5 { 4 } else { failure - 1 };
        assert_eq!(fs.released.len(), expected);
        for object in fs.retained.iter().take(expected) {
            assert!(
                fs.released
                    .iter()
                    .any(|released| released.handle == object.handle + 1000)
            );
        }
    }
}

#[test]
fn scope_open_rejects_mutation_directory_injection_and_missing_nonblock_before_fs() {
    let (state, peer, mut fs, mut scopes) = setup();
    let id = create(&state, peer, &mut fs, &mut scopes);
    for options in [
        protocol::OPEN_READ,
        protocol::OPEN_WRITE,
        protocol::OPEN_READ | protocol::OPEN_NONBLOCK | protocol::OPEN_CREATE,
        protocol::OPEN_READ | protocol::OPEN_NONBLOCK | protocol::OPEN_EXECUTE,
        protocol::OPEN_READ | protocol::OPEN_NONBLOCK | protocol::OPEN_DIRECTORY,
    ] {
        let response = invoke(
            &state,
            peer,
            &mut fs,
            &mut scopes,
            id,
            wire::OP_OPEN,
            &path(protocol::OpenBase::ProcessRoot, options),
        );
        assert_eq!(response.response.header.status, -22);
        assert!(fs.request.is_none());
    }
    assert_eq!(
        invoke(
            &state,
            peer,
            &mut fs,
            &mut scopes,
            id,
            wire::OP_OPEN,
            &path(
                protocol::OpenBase::AttachedDirectory,
                protocol::OPEN_READ | protocol::OPEN_NONBLOCK
            )
        )
        .response
        .header
        .status,
        -22
    );
    assert!(fs.request.is_none());
    let response = scopes.execute(
        &state,
        peer,
        header(wire::OP_INFO, &[]),
        &[],
        &[AttachedObject {
            handle: 900,
            rights: wire::TOKEN_RIGHTS,
        }],
        &mut fs,
        |_| unreachable!(),
        |_| panic!("wrong attachment rights must be rejected before identification"),
    );
    assert_eq!(response.response.header.status, -22);
}

#[test]
fn source_quota_is_bounded_and_release_restores_capacity() {
    let (state, peer, mut fs, mut scopes) = setup();
    let first = create(&state, peer, &mut fs, &mut scopes);
    for _ in 1..16 {
        create(&state, peer, &mut fs, &mut scopes);
    }
    let retained = fs.retained.len();
    let reply = scopes.execute(
        &state,
        peer,
        header(wire::OP_CREATE, &[]),
        &[],
        &[],
        &mut fs,
        |_| panic!("quota must precede allocation"),
        |_| unreachable!(),
    );
    assert_eq!(reply.response.header.status, -11);
    assert_eq!(fs.retained.len(), retained);
    release(
        &mut scopes,
        first,
        mnu_abi::IPC_DELIVERY_NATIVE_OBJECT,
        0,
        &mut fs,
    )
    .unwrap();
    create(&state, peer, &mut fs, &mut scopes);
}

#[test]
fn foreign_objects_guessed_ids_and_caller_supplied_identity_never_open_a_path() {
    let (state, peer, mut fs, mut scopes) = setup();
    let id = create(&state, peer, &mut fs, &mut scopes);
    let paths = path(
        protocol::OpenBase::ProcessRoot,
        protocol::OPEN_READ | protocol::OPEN_NONBLOCK,
    );
    for guessed in [0, id + 1, u64::MAX] {
        assert_eq!(
            invoke(
                &state,
                peer,
                &mut fs,
                &mut scopes,
                guessed,
                wire::OP_OPEN,
                &paths
            )
            .response
            .header
            .status,
            -9
        );
        assert!(fs.request.is_none());
    }
    let incoming = [AttachedObject {
        handle: 900,
        rights: wire::ATTACH_RIGHTS,
    }];
    let result = scopes.execute(
        &state,
        peer,
        header(wire::OP_OPEN, &paths),
        &paths,
        &incoming,
        &mut fs,
        |_| unreachable!(),
        |_| Err(-13),
    );
    assert_eq!(result.response.header.status, -13);
    assert!(fs.request.is_none());
    let retained = fs.retained.len();
    let supplied_pid = 999u64.to_le_bytes();
    let result = scopes.execute(
        &state,
        peer,
        header(wire::OP_CREATE, &supplied_pid),
        &supplied_pid,
        &[],
        &mut fs,
        |_| panic!("self capture has no subject selector"),
        |_| unreachable!(),
    );
    assert_eq!(result.response.header.status, -22);
    assert_eq!(fs.retained.len(), retained);
}

#[test]
fn failed_file_attenuation_closes_the_opened_file_and_preserves_the_scope() {
    for missing_rights in [false, true] {
        let (state, peer, mut fs, mut scopes) = setup();
        let id = create(&state, peer, &mut fs, &mut scopes);
        if missing_rights {
            fs.open_rights = Some(mnu_abi::HANDLE_RIGHT_READ);
        } else {
            fs.retain_failure_at = Some(fs.retained.len() + 1);
        }
        let before = fs.released.len();
        let result = invoke(
            &state,
            peer,
            &mut fs,
            &mut scopes,
            id,
            wire::OP_OPEN,
            &path(
                protocol::OpenBase::ProcessRoot,
                protocol::OPEN_READ | protocol::OPEN_NONBLOCK,
            ),
        );
        assert_eq!(result.response.header.status, -5);
        assert!(result.handles.is_empty());
        assert_eq!(
            fs.released[before..]
                .iter()
                .map(|object| object.handle)
                .collect::<Vec<_>>(),
            [200]
        );
        assert_eq!(
            invoke(&state, peer, &mut fs, &mut scopes, id, wire::OP_INFO, &[])
                .response
                .header
                .status,
            0
        );
    }
}

struct ReplyTransport {
    opcode: u16,
    handles: Vec<ObjectHandleAttachment<u32>>,
    flags: u32,
    closed: RefCell<Vec<u32>>,
}
impl Transport for ReplyTransport {
    type Error = ();
    fn call(&self, _: &[u8], _: &mut [u8]) -> Result<usize, ()> {
        panic!("objects required")
    }
}
impl ObjectTransport for ReplyTransport {
    type Handle = u32;
    fn close_received_handle(&self, handle: u32) {
        self.closed.borrow_mut().push(handle);
    }
    fn call_with_handles(
        &self,
        request: &[u8],
        response: &mut [u8],
        objects: &mut ObjectHandles<u32>,
    ) -> Result<usize, ()> {
        let (header, payload) = protocol::decode(request).unwrap();
        assert_eq!(header.opcode, self.opcode);
        if header.opcode == wire::OP_CREATE {
            assert!(payload.is_empty() && objects.is_empty());
        } else {
            assert_eq!(objects.get(0).unwrap().rights, wire::ATTACH_RIGHTS);
            if header.opcode == wire::OP_OPEN {
                wire::decode_open(payload).unwrap();
            }
        }
        objects.clear();
        for object in &self.handles {
            objects.push(*object).unwrap();
        }
        protocol::encode(
            protocol::Header {
                opcode: protocol::OP_STATUS,
                request_id: header.request_id,
                flags: self.flags,
                ..Default::default()
            },
            &[],
            response,
        )
        .map_err(|_| ())
    }
}

#[test]
fn client_rejects_excess_reply_authority_and_closes_owned_handles_once() {
    for opcode in [wire::OP_CREATE, wire::OP_OPEN] {
        for (rights, flags, valid) in [
            (
                if opcode == wire::OP_CREATE {
                    wire::TOKEN_RIGHTS
                } else {
                    wire::FILE_RIGHTS
                },
                0,
                true,
            ),
            (wire::FILE_RIGHTS | mnu_abi::HANDLE_RIGHT_CONTROL, 0, false),
            (wire::TOKEN_RIGHTS, 1, false),
            (0, 0, false),
        ] {
            let transport = ReplyTransport {
                opcode,
                handles: vec![ObjectHandleAttachment { handle: 44, rights }],
                flags,
                closed: RefCell::new(Vec::new()),
            };
            let client = Client::new(transport);
            let result = if opcode == wire::OP_CREATE {
                client.create_read_scope()
            } else {
                client.read_scope_open(
                    ObjectHandleAttachment {
                        handle: 99,
                        rights: wire::TOKEN_RIGHTS,
                    },
                    false,
                    b"lib.so",
                )
            };
            assert_eq!(result.is_ok(), valid);
            assert_eq!(
                *client.transport().closed.borrow(),
                if valid { vec![] } else { vec![44] }
            );
        }
    }
}
