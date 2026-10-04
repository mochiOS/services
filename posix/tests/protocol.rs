use std::cell::RefCell;

use mochios_posix_client::{
    Client, ClientError, ObjectHandleAttachment, ObjectHandles, ObjectTransport, Transport,
};
use mochios_posix_protocol as protocol;
use posix_service::{
    AttachedObject, FilesystemBackend, OpenedObject, PeerIdentity, PosixService, PreparedOpen,
    PreparedStat,
};

struct LocalTransport {
    service: RefCell<PosixService>,
    peer: PeerIdentity,
}

impl Transport for LocalTransport {
    type Error = ();

    fn call(&self, request: &[u8], response: &mut [u8]) -> Result<usize, Self::Error> {
        let (header, payload) = protocol::decode(request).map_err(|_| ())?;
        let reply = self.service.borrow_mut().handle(self.peer, header, payload);
        protocol::encode(reply.header, &reply.payload, response).map_err(|_| ())
    }
}

fn client(peer: PeerIdentity) -> Client<LocalTransport> {
    Client::new(LocalTransport {
        service: RefCell::new(PosixService::new()),
        peer,
    })
}

#[test]
fn ping_round_trip_preserves_request_identity() {
    client(PeerIdentity {
        process_id: 7,
        effective_uid: 501,
        effective_gid: 20,
    })
    .ping()
    .unwrap();
}

#[test]
fn unknown_opcode_returns_enosys() {
    let client = client(PeerIdentity {
        process_id: 7,
        effective_uid: 501,
        effective_gid: 20,
    });
    let error = client.request(0x7fff, 0, &[], &mut []).unwrap_err();
    assert_eq!(error, ClientError::Remote(protocol::STATUS_ENOSYS));
}

#[test]
fn session_uses_authenticated_peer_instead_of_request_payload() {
    let peer = PeerIdentity {
        process_id: 41,
        effective_uid: 501,
        effective_gid: 20,
    };
    let mut service = PosixService::new();
    let response = service.handle(
        peer,
        protocol::Header {
            opcode: protocol::OP_SESSION_REGISTER,
            request_id: 9,
            ..protocol::Header::default()
        },
        &[],
    );
    assert_eq!(response.header.status, protocol::STATUS_OK);
    let session = service.session(41).unwrap();
    assert_eq!(session.real_uid, 501);
    assert_eq!(session.real_gid, 20);
    assert_eq!(session.umask, 0o022);
}

#[test]
fn client_registers_an_authenticated_session() {
    let peer = PeerIdentity {
        process_id: 73,
        effective_uid: 502,
        effective_gid: 21,
    };
    let client = client(peer);
    client.register_session().unwrap();

    let transport = client.into_transport();
    let service = transport.service.borrow();
    let session = service.session(peer.process_id).unwrap();
    assert_eq!(session.effective_uid, peer.effective_uid);
    assert_eq!(session.effective_gid, peer.effective_gid);
}

#[test]
fn session_info_and_umask_round_trip_through_the_client() {
    let peer = PeerIdentity {
        process_id: 91,
        effective_uid: 503,
        effective_gid: 22,
    };
    let client = client(peer);
    assert_eq!(
        client.session_info().unwrap_err(),
        ClientError::Remote(protocol::STATUS_ESRCH)
    );

    client.register_session().unwrap();
    let initial = client.session_info().unwrap();
    assert_eq!(initial.real_uid, peer.effective_uid);
    assert_eq!(initial.effective_uid, peer.effective_uid);
    assert_eq!(initial.real_gid, peer.effective_gid);
    assert_eq!(initial.effective_gid, peer.effective_gid);
    assert_eq!(initial.umask, 0o022);

    assert_eq!(client.set_umask(0o1755).unwrap(), 0o022);
    assert_eq!(client.session_info().unwrap().umask, 0o755);
}

#[test]
fn fixed_size_session_payloads_reject_trailing_bytes() {
    let mut encoded = [0u8; protocol::SESSION_INFO_LEN + 1];
    protocol::encode_session_info(protocol::SessionInfo::default(), &mut encoded).unwrap();
    assert_eq!(
        protocol::decode_session_info(&encoded),
        Err(protocol::ProtocolError::InvalidLength)
    );
    assert_eq!(
        protocol::decode_umask(&[0; protocol::UMASK_PAYLOAD_LEN + 1]),
        Err(protocol::ProtocolError::InvalidLength)
    );
}

struct LocalObjectTransport;

impl Transport for LocalObjectTransport {
    type Error = ();

    fn call(&self, _request: &[u8], _response: &mut [u8]) -> Result<usize, Self::Error> {
        Err(())
    }
}

impl ObjectTransport for LocalObjectTransport {
    type Handle = u32;

    fn call_with_handles(
        &self,
        request: &[u8],
        response: &mut [u8],
        handles: &mut ObjectHandles<Self::Handle>,
    ) -> Result<usize, Self::Error> {
        let (header, _) = protocol::decode(request).map_err(|_| ())?;
        assert_eq!(
            handles.get(0),
            Some(ObjectHandleAttachment {
                handle: 41,
                rights: 0x5,
            })
        );
        handles.clear();
        handles
            .push(ObjectHandleAttachment {
                handle: 73,
                rights: 0x1,
            })
            .unwrap();
        protocol::encode(
            protocol::Header {
                opcode: protocol::OP_STATUS,
                request_id: header.request_id,
                status: protocol::STATUS_OK,
                ..protocol::Header::default()
            },
            &[],
            response,
        )
        .map_err(|_| ())
    }
}

#[test]
fn object_transport_replaces_request_handles_with_reply_handles() {
    let client = Client::new(LocalObjectTransport);
    let mut handles = ObjectHandles::new();
    handles
        .push(ObjectHandleAttachment {
            handle: 41,
            rights: 0x5,
        })
        .unwrap();

    client
        .request_with_handles(protocol::OP_PING, 0, &[], &mut [], &mut handles)
        .unwrap();

    assert_eq!(handles.len(), 1);
    assert_eq!(
        handles.get(0),
        Some(ObjectHandleAttachment {
            handle: 73,
            rights: 0x1,
        })
    );
}

#[test]
fn open_at_wire_format_is_strict_and_contains_no_descriptor_number() {
    let mut bytes = [0u8; protocol::OPEN_AT_HEADER_LEN + protocol::MAX_PATH_LEN];
    let length = protocol::encode_open_at(
        protocol::OpenAtRequest {
            base: protocol::OpenBase::AttachedDirectory,
            options: protocol::OPEN_READ | protocol::OPEN_NOFOLLOW,
            mode: 0o640,
            path: "child.txt",
        },
        &mut bytes,
    )
    .unwrap();
    let decoded = protocol::decode_open_at(&bytes[..length]).unwrap();
    assert_eq!(decoded.base, protocol::OpenBase::AttachedDirectory);
    assert_eq!(decoded.options, protocol::OPEN_READ | protocol::OPEN_NOFOLLOW);
    assert_eq!(decoded.mode, 0o640);
    assert_eq!(decoded.path, "child.txt");

    bytes[1] = 1;
    assert_eq!(
        protocol::decode_open_at(&bytes[..length]),
        Err(protocol::ProtocolError::InvalidLength)
    );
}

#[test]
fn service_prepares_open_with_authenticated_credentials_and_umask() {
    let peer = PeerIdentity {
        process_id: 101,
        effective_uid: 504,
        effective_gid: 23,
    };
    let mut service = PosixService::new();
    service.handle(
        peer,
        protocol::Header {
            opcode: protocol::OP_SESSION_REGISTER,
            ..protocol::Header::default()
        },
        &[],
    );
    let mut umask = [0u8; protocol::UMASK_PAYLOAD_LEN];
    protocol::encode_umask(0o027, &mut umask).unwrap();
    service.handle(
        peer,
        protocol::Header {
            opcode: protocol::OP_UMASK_SET,
            payload_len: umask.len() as u32,
            ..protocol::Header::default()
        },
        &umask,
    );

    let mut payload = [0u8; protocol::OPEN_AT_HEADER_LEN + 16];
    let length = protocol::encode_open_at(
        protocol::OpenAtRequest {
            base: protocol::OpenBase::ProcessCwd,
            options: protocol::OPEN_READ | protocol::OPEN_WRITE | protocol::OPEN_CREATE,
            mode: 0o666,
            path: "notes.txt",
        },
        &mut payload,
    )
    .unwrap();
    let open = service
        .prepare_open_at(peer, &payload[..length], 0)
        .unwrap();
    assert_eq!(open.mode, 0o640);
    assert_eq!(open.effective_uid, 504);
    assert_eq!(open.effective_gid, 23);
    assert_eq!(open.path, "notes.txt");
    assert_eq!(
        service.prepare_open_at(peer, &payload[..length], 1),
        Err(posix_service::STATUS_EINVAL)
    );
}

struct OpenTransport;

impl Transport for OpenTransport {
    type Error = ();

    fn call(&self, _request: &[u8], _response: &mut [u8]) -> Result<usize, Self::Error> {
        Err(())
    }
}

impl ObjectTransport for OpenTransport {
    type Handle = u32;

    fn call_with_handles(
        &self,
        request: &[u8],
        response: &mut [u8],
        handles: &mut ObjectHandles<Self::Handle>,
    ) -> Result<usize, Self::Error> {
        let (header, payload) = protocol::decode(request).map_err(|_| ())?;
        assert_eq!(header.opcode, protocol::OP_OPEN_AT);
        assert!(handles.is_empty());
        let open = protocol::decode_open_at(payload).map_err(|_| ())?;
        assert_eq!(open.base, protocol::OpenBase::ProcessCwd);
        assert_eq!(open.path, "document.txt");
        handles
            .push(ObjectHandleAttachment {
                handle: 91,
                rights: 0x81,
            })
            .unwrap();
        protocol::encode(
            protocol::Header {
                opcode: protocol::OP_STATUS,
                request_id: header.request_id,
                status: protocol::STATUS_OK,
                ..protocol::Header::default()
            },
            &[],
            response,
        )
        .map_err(|_| ())
    }
}

#[test]
fn client_open_at_returns_only_the_attached_file_handle() {
    let handle = Client::new(OpenTransport)
        .open_at(
            mochios_posix_client::OpenAtBase::ProcessCwd,
            protocol::OPEN_READ,
            0,
            "document.txt",
        )
        .unwrap();
    assert_eq!(handle.handle, 91);
    assert_eq!(handle.rights, 0x81);
}

#[derive(Default)]
struct RecordingFilesystem {
    request: Option<PreparedOpen>,
    stat_request: Option<PreparedStat>,
    directory: Option<AttachedObject<u32>>,
    stat_file: Option<AttachedObject<u32>>,
}

impl FilesystemBackend<u32> for RecordingFilesystem {
    fn open_at(
        &mut self,
        request: &PreparedOpen,
        directory: Option<AttachedObject<u32>>,
    ) -> Result<OpenedObject<u32>, i32> {
        self.request = Some(request.clone());
        self.directory = directory;
        Ok(OpenedObject {
            handle: 200,
            rights: 0x81,
        })
    }

    fn stat_at(
        &mut self,
        request: &PreparedStat,
        directory: Option<AttachedObject<u32>>,
    ) -> Result<protocol::FileStatus, i32> {
        self.stat_request = Some(request.clone());
        self.directory = directory;
        Ok(sample_status())
    }

    fn fstat(
        &mut self,
        file: AttachedObject<u32>,
    ) -> Result<protocol::FileStatus, i32> {
        self.stat_file = Some(file);
        Ok(sample_status())
    }
}

fn sample_status() -> protocol::FileStatus {
    protocol::FileStatus {
        device: 1,
        inode: 9,
        mode: 0o100640,
        link_count: 1,
        uid: 505,
        gid: 24,
        size: 32,
        block_size: 4096,
        blocks: 1,
        ..protocol::FileStatus::default()
    }
}

#[test]
fn service_submits_open_as_one_atomic_filesystem_operation() {
    let peer = PeerIdentity {
        process_id: 111,
        effective_uid: 505,
        effective_gid: 24,
    };
    let mut service = PosixService::new();
    service.handle(
        peer,
        protocol::Header {
            opcode: protocol::OP_SESSION_REGISTER,
            ..protocol::Header::default()
        },
        &[],
    );
    let mut payload = [0u8; protocol::OPEN_AT_HEADER_LEN + 16];
    let length = protocol::encode_open_at(
        protocol::OpenAtRequest {
            base: protocol::OpenBase::AttachedDirectory,
            options: protocol::OPEN_WRITE | protocol::OPEN_CREATE | protocol::OPEN_EXCLUSIVE,
            mode: 0o666,
            path: "result.txt",
        },
        &mut payload,
    )
    .unwrap();
    let directory = AttachedObject {
        handle: 55,
        rights: 0x85,
    };
    let mut filesystem = RecordingFilesystem::default();

    let result = service.handle_objects(
        peer,
        protocol::Header {
            opcode: protocol::OP_OPEN_AT,
            request_id: 13,
            payload_len: length as u32,
            ..protocol::Header::default()
        },
        &payload[..length],
        &[directory],
        &mut filesystem,
    );

    assert_eq!(result.response.header.status, protocol::STATUS_OK);
    assert_eq!(result.handles[0].handle, 200);
    assert_eq!(filesystem.directory, Some(directory));
    let request = filesystem.request.unwrap();
    assert_eq!(request.path, "result.txt");
    assert_eq!(request.effective_uid, 505);
    assert_eq!(request.effective_gid, 24);
    assert_eq!(request.mode, 0o644);
    assert_eq!(
        request.options,
        protocol::OPEN_WRITE | protocol::OPEN_CREATE | protocol::OPEN_EXCLUSIVE
    );
}

#[test]
fn service_submits_stat_as_one_atomic_filesystem_operation() {
    let peer = PeerIdentity {
        process_id: 112,
        effective_uid: 506,
        effective_gid: 25,
    };
    let mut service = PosixService::new();
    service.handle(
        peer,
        protocol::Header {
            opcode: protocol::OP_SESSION_REGISTER,
            ..protocol::Header::default()
        },
        &[],
    );
    let mut payload = [0u8; protocol::STAT_AT_HEADER_LEN + 16];
    let length = protocol::encode_stat_at(
        protocol::StatAtRequest {
            base: protocol::OpenBase::AttachedDirectory,
            flags: protocol::STAT_NOFOLLOW,
            path: "result.txt",
        },
        &mut payload,
    )
    .unwrap();
    let directory = AttachedObject {
        handle: 56,
        rights: 0x85,
    };
    let mut filesystem = RecordingFilesystem::default();

    let result = service.handle_objects(
        peer,
        protocol::Header {
            opcode: protocol::OP_STAT_AT,
            request_id: 14,
            payload_len: length as u32,
            ..protocol::Header::default()
        },
        &payload[..length],
        &[directory],
        &mut filesystem,
    );

    assert!(result.handles.is_empty());
    assert_eq!(result.response.header.status, protocol::STATUS_OK);
    assert_eq!(
        protocol::decode_file_status(&result.response.payload).unwrap(),
        sample_status()
    );
    assert_eq!(filesystem.directory, Some(directory));
    let request = filesystem.stat_request.unwrap();
    assert_eq!(request.path, "result.txt");
    assert_eq!(request.flags, protocol::STAT_NOFOLLOW);
    assert_eq!(request.effective_uid, 506);
    assert_eq!(request.effective_gid, 25);
}

#[test]
fn fstat_uses_only_the_explicitly_attached_file_handle() {
    let peer = PeerIdentity {
        process_id: 113,
        effective_uid: 507,
        effective_gid: 26,
    };
    let mut service = PosixService::new();
    service.handle(
        peer,
        protocol::Header {
            opcode: protocol::OP_SESSION_REGISTER,
            ..protocol::Header::default()
        },
        &[],
    );
    let file = AttachedObject {
        handle: 57,
        rights: 0x81,
    };
    let mut filesystem = RecordingFilesystem::default();

    let result = service.handle_objects(
        peer,
        protocol::Header {
            opcode: protocol::OP_FSTAT,
            request_id: 15,
            ..protocol::Header::default()
        },
        &[],
        &[file],
        &mut filesystem,
    );

    assert_eq!(result.response.header.status, protocol::STATUS_OK);
    assert_eq!(filesystem.stat_file, Some(file));
    assert_eq!(
        protocol::decode_file_status(&result.response.payload).unwrap(),
        sample_status()
    );

    let invalid = service.handle_objects(
        peer,
        protocol::Header {
            opcode: protocol::OP_FSTAT,
            request_id: 16,
            ..protocol::Header::default()
        },
        &[],
        &[],
        &mut filesystem,
    );
    assert_eq!(invalid.response.header.status, posix_service::STATUS_EINVAL);
}
