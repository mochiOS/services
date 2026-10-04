use std::cell::RefCell;

use mochios_filesystem_protocol as filesystem_protocol;
use mochios_posix_client::{
    Client, ClientError, ObjectHandleAttachment, ObjectHandles, ObjectTransport, Transport,
};
use mochios_posix_protocol as protocol;
use posix_service::{
    AttachedObject, FilesystemBackend, OpenedObject, PathObjects, PeerIdentity, PosixService,
    PreparedAccess, PreparedOpen, PreparedStat, SessionDirectories,
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
fn credential_changes_follow_posix_privilege_rules() {
    let unprivileged = client(PeerIdentity {
        process_id: 92,
        effective_uid: 503,
        effective_gid: 22,
    });
    unprivileged.register_session().unwrap();
    assert_eq!(
        unprivileged.set_uid(999).unwrap_err(),
        ClientError::Remote(-1)
    );
    assert_eq!(
        unprivileged.set_gid(999).unwrap_err(),
        ClientError::Remote(-1)
    );
    unprivileged.set_uid(503).unwrap();
    unprivileged.set_gid(22).unwrap();

    let privileged = client(PeerIdentity {
        process_id: 93,
        effective_uid: 0,
        effective_gid: 0,
    });
    privileged.register_session().unwrap();
    privileged.set_gid(42).unwrap();
    privileged.set_uid(501).unwrap();
    let session = privileged.session_info().unwrap();
    assert_eq!(session.real_uid, 501);
    assert_eq!(session.effective_uid, 501);
    assert_eq!(session.real_gid, 42);
    assert_eq!(session.effective_gid, 42);
    assert_eq!(privileged.set_uid(0).unwrap_err(), ClientError::Remote(-1));
}

struct GetcwdTransport;

impl Transport for GetcwdTransport {
    type Error = ();

    fn call(&self, request: &[u8], response: &mut [u8]) -> Result<usize, Self::Error> {
        let (header, payload) = protocol::decode(request).map_err(|_| ())?;
        assert_eq!(header.opcode, protocol::OP_GETCWD);
        assert!(payload.is_empty());
        protocol::encode(
            protocol::Header {
                opcode: protocol::OP_STATUS,
                request_id: header.request_id,
                payload_len: 5,
                status: protocol::STATUS_OK,
                ..protocol::Header::default()
            },
            b"/work",
            response,
        )
        .map_err(|_| ())
    }
}

#[test]
fn client_getcwd_returns_the_service_path() {
    let mut output = [0u8; 16];
    let length = Client::new(GetcwdTransport).getcwd(&mut output).unwrap();
    assert_eq!(&output[..length], b"/work");
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
    assert_eq!(
        protocol::decode_file_length(&[0; protocol::FILE_LENGTH_PAYLOAD_LEN + 1]),
        Err(protocol::ProtocolError::InvalidLength)
    );
}

#[test]
fn stat_at_wire_format_is_strict_and_contains_no_descriptor() {
    let mut bytes = [0u8; protocol::STAT_AT_HEADER_LEN + 16];
    let length = protocol::encode_stat_at(
        protocol::StatAtRequest {
            base: protocol::OpenBase::AttachedDirectory,
            flags: protocol::STAT_NOFOLLOW,
            path: "child",
        },
        &mut bytes,
    )
    .unwrap();
    assert_eq!(
        protocol::decode_stat_at(&bytes[..length]).unwrap(),
        protocol::StatAtRequest {
            base: protocol::OpenBase::AttachedDirectory,
            flags: protocol::STAT_NOFOLLOW,
            path: "child",
        }
    );
    bytes[1] = 1;
    assert_eq!(
        protocol::decode_stat_at(&bytes[..length]),
        Err(protocol::ProtocolError::InvalidLength)
    );
}

#[test]
fn access_at_wire_format_is_strict_and_contains_no_descriptor() {
    let mut bytes = [0u8; protocol::ACCESS_AT_HEADER_LEN + 16];
    let length = protocol::encode_access_at(
        protocol::AccessAtRequest {
            base: protocol::OpenBase::ProcessCwd,
            flags: protocol::ACCESS_EFFECTIVE_IDS,
            modes: protocol::ACCESS_READ | protocol::ACCESS_WRITE,
            path: "child",
        },
        &mut bytes,
    )
    .unwrap();
    let decoded = protocol::decode_access_at(&bytes[..length]).unwrap();
    assert_eq!(decoded.base, protocol::OpenBase::ProcessCwd);
    assert_eq!(decoded.flags, protocol::ACCESS_EFFECTIVE_IDS);
    assert_eq!(
        decoded.modes,
        protocol::ACCESS_READ | protocol::ACCESS_WRITE
    );
    assert_eq!(decoded.path, "child");
    bytes[2] = 1;
    assert_eq!(
        protocol::decode_access_at(&bytes[..length]),
        Err(protocol::ProtocolError::InvalidLength)
    );
}

#[test]
fn status_wire_formats_are_target_abi_independent() {
    let status = sample_status();
    let mut bytes = [0u8; protocol::FILE_STATUS_LEN];
    protocol::encode_file_status(status, &mut bytes).unwrap();
    assert_eq!(protocol::decode_file_status(&bytes).unwrap(), status);

    let node = filesystem_protocol::NodeStatus {
        device: 2,
        node_id: 17,
        size: 8193,
        blocks: 17,
        block_size: 4096,
        kind: filesystem_protocol::NODE_TYPE_REGULAR,
        mode: 0o640,
        uid: 501,
        gid: 20,
        link_count: 2,
        access_time_seconds: 10,
        access_time_nanoseconds: 11,
        modification_time_seconds: 12,
        modification_time_nanoseconds: 13,
        change_time_seconds: 14,
        change_time_nanoseconds: 15,
        ..filesystem_protocol::NodeStatus::default()
    };
    let mut bytes = [0u8; filesystem_protocol::NODE_STATUS_LEN];
    filesystem_protocol::encode_node_status(node, &mut bytes).unwrap();
    assert_eq!(
        filesystem_protocol::decode_node_status(&bytes).unwrap(),
        node
    );
}

#[test]
fn maximum_path_fits_in_a_control_message() {
    let path_bytes = [b'a'; protocol::MAX_PATH_LEN];
    let path = core::str::from_utf8(&path_bytes).unwrap();
    let mut payload = [0u8; protocol::MAX_CONTROL_PAYLOAD_LEN];
    let payload_len = protocol::encode_open_at(
        protocol::OpenAtRequest {
            base: protocol::OpenBase::ProcessCwd,
            options: protocol::OPEN_READ,
            mode: 0,
            path,
        },
        &mut payload,
    )
    .unwrap();
    assert!(protocol::HEADER_LEN + payload_len <= protocol::CONTROL_MESSAGE_LEN);

    let rename_len = protocol::encode_rename_at(
        protocol::RenameAtRequest {
            old_base: protocol::OpenBase::ProcessCwd,
            new_base: protocol::OpenBase::ProcessCwd,
            old_path: path,
            new_path: path,
        },
        &mut payload,
    )
    .unwrap();
    assert_eq!(rename_len, protocol::MAX_CONTROL_PAYLOAD_LEN);
    assert_eq!(protocol::HEADER_LEN + rename_len, protocol::CONTROL_MESSAGE_LEN);
}

#[test]
fn filesystem_at_protocol_has_distinct_root_and_base_anchors() {
    for (root, base, all) in [
        (
            filesystem_protocol::OPEN_AT_ROOT_ATTACHED,
            filesystem_protocol::OPEN_AT_BASE_ATTACHED,
            filesystem_protocol::OPEN_AT_FLAGS_ALL,
        ),
        (
            filesystem_protocol::STAT_AT_ROOT_ATTACHED,
            filesystem_protocol::STAT_AT_BASE_ATTACHED,
            filesystem_protocol::STAT_AT_FLAGS_ALL,
        ),
        (
            filesystem_protocol::ACCESS_AT_ROOT_ATTACHED,
            filesystem_protocol::ACCESS_AT_BASE_ATTACHED,
            filesystem_protocol::ACCESS_AT_FLAGS_ALL,
        ),
    ] {
        assert_ne!(root, base);
        assert_eq!(root & base, 0);
        assert_eq!(all & (root | base), root | base);
    }
}

#[test]
fn inherited_fd_launch_keys_are_opaque_disjoint_and_reversible() {
    for fd in [0, 1, 2, 42, i32::MAX] {
        let handle = protocol::fd_handle_key(fd).unwrap();
        let flags = protocol::fd_flags_key(fd).unwrap();
        let rights = protocol::fd_rights_key(fd).unwrap();
        assert_ne!(handle, flags);
        assert_ne!(handle, rights);
        assert_ne!(flags, rights);
        assert_ne!(handle, protocol::CONTROL_HANDLE_KEY);
        assert_eq!(protocol::inherited_fd_from_key(handle), Some(fd));
        assert_eq!(protocol::inherited_fd_from_key(flags), Some(fd));
        assert_eq!(protocol::inherited_fd_from_key(rights), Some(fd));
    }
    assert_eq!(protocol::fd_handle_key(-1), None);
    assert_eq!(protocol::fd_flags_key(-1), None);
    assert_eq!(protocol::fd_rights_key(-1), None);
    assert_eq!(protocol::inherited_fd_from_key(0), None);

    let encoded = protocol::encode_fd_flags(0xfeed_beef, 0x8000_0001);
    assert_eq!(
        protocol::decode_fd_flags(encoded),
        (0xfeed_beef, 0x8000_0001)
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
    assert_eq!(
        decoded.options,
        protocol::OPEN_READ | protocol::OPEN_NOFOLLOW
    );
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

struct DirectoryChangeTransport;

impl Transport for DirectoryChangeTransport {
    type Error = ();

    fn call(&self, _request: &[u8], _response: &mut [u8]) -> Result<usize, Self::Error> {
        Err(())
    }
}

impl ObjectTransport for DirectoryChangeTransport {
    type Handle = u32;

    fn call_with_handles(
        &self,
        request: &[u8],
        response: &mut [u8],
        handles: &mut ObjectHandles<Self::Handle>,
    ) -> Result<usize, Self::Error> {
        let (header, payload) = protocol::decode(request).map_err(|_| ())?;
        assert_eq!(handles.len(), 1);
        assert_eq!(handles.get(0).unwrap().handle, 77);
        match header.opcode {
            protocol::OP_CHDIR_AT => {
                let request = protocol::decode_stat_at(payload).map_err(|_| ())?;
                assert_eq!(request.base, protocol::OpenBase::AttachedDirectory);
                assert_eq!(request.flags, 0);
                assert_eq!(request.path, "child");
            }
            protocol::OP_FCHDIR => assert!(payload.is_empty()),
            _ => return Err(()),
        }
        handles.clear();
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
fn client_transfers_directory_handles_for_chdir_and_fchdir() {
    let directory = ObjectHandleAttachment {
        handle: 77,
        rights: 0x4000_0000_0000_0081,
    };
    let client = Client::new(DirectoryChangeTransport);
    client
        .chdir_at(
            mochios_posix_client::StatAtBase::Directory(directory),
            "child",
        )
        .unwrap();
    client.fchdir(directory).unwrap();
}

#[derive(Default)]
struct RecordingFilesystem {
    request: Option<PreparedOpen>,
    stat_request: Option<PreparedStat>,
    access_request: Option<PreparedAccess>,
    directory: Option<AttachedObject<u32>>,
    root: Option<AttachedObject<u32>>,
    roots_opened: usize,
    stat_file: Option<AttachedObject<u32>>,
    stat_mode: Option<u32>,
    truncated: Option<(AttachedObject<u32>, u64)>,
    chmod_file: Option<(AttachedObject<u32>, u32, u32, u32)>,
    chown_file: Option<(AttachedObject<u32>, u32, u32, u32, u32)>,
    synced: Option<AttachedObject<u32>>,
    status_flags: u32,
    flags_file: Option<AttachedObject<u32>>,
    mkdir_request: Option<posix_service::PreparedMkdir>,
    unlink_request: Option<posix_service::PreparedUnlink>,
    rename_request: Option<posix_service::PreparedRename>,
    rename_paths: Option<posix_service::RenamePathObjects<u32>>,
    truncate_request: Option<posix_service::PreparedTruncate>,
    symlink_request: Option<posix_service::PreparedSymlink>,
    readlink_request: Option<posix_service::PreparedReadlink>,
    chmod_request: Option<posix_service::PreparedChmod>,
    chown_request: Option<posix_service::PreparedChown>,
    retained: Vec<AttachedObject<u32>>,
    released: Vec<AttachedObject<u32>>,
    path_query: Option<(AttachedObject<u32>, AttachedObject<u32>)>,
    directory_path: Vec<u8>,
}

impl FilesystemBackend<u32> for RecordingFilesystem {
    fn open_session_root(
        &mut self,
        _effective_uid: u32,
        _effective_gid: u32,
    ) -> Result<SessionDirectories<u32>, i32> {
        self.roots_opened += 1;
        Ok(SessionDirectories {
            root: AttachedObject {
                handle: 100,
                rights: 0x81,
            },
            cwd: AttachedObject {
                handle: 101,
                rights: 0x81,
            },
        })
    }

    fn open_at(
        &mut self,
        request: &PreparedOpen,
        paths: PathObjects<u32>,
    ) -> Result<OpenedObject<u32>, i32> {
        self.request = Some(request.clone());
        self.root = Some(paths.root);
        self.directory = paths.base;
        Ok(OpenedObject {
            handle: 200,
            rights: 0x81,
        })
    }

    fn stat_at(
        &mut self,
        request: &PreparedStat,
        paths: PathObjects<u32>,
    ) -> Result<protocol::FileStatus, i32> {
        self.stat_request = Some(request.clone());
        self.root = Some(paths.root);
        self.directory = paths.base;
        Ok(sample_status())
    }

    fn fstat(&mut self, file: AttachedObject<u32>) -> Result<protocol::FileStatus, i32> {
        self.stat_file = Some(file);
        let mut status = sample_status();
        if let Some(mode) = self.stat_mode {
            status.mode = mode;
        }
        Ok(status)
    }

    fn ftruncate(&mut self, file: AttachedObject<u32>, length: u64) -> Result<(), i32> {
        self.truncated = Some((file, length));
        Ok(())
    }

    fn fchmod(
        &mut self,
        file: AttachedObject<u32>,
        mode: u32,
        effective_uid: u32,
        effective_gid: u32,
    ) -> Result<(), i32> {
        self.chmod_file = Some((file, mode, effective_uid, effective_gid));
        Ok(())
    }

    fn fchown(
        &mut self,
        file: AttachedObject<u32>,
        uid: u32,
        gid: u32,
        effective_uid: u32,
        effective_gid: u32,
    ) -> Result<(), i32> {
        self.chown_file = Some((file, uid, gid, effective_uid, effective_gid));
        Ok(())
    }

    fn fsync(&mut self, file: AttachedObject<u32>) -> Result<(), i32> {
        self.synced = Some(file);
        Ok(())
    }

    fn get_status_flags(&mut self, file: AttachedObject<u32>) -> Result<u32, i32> {
        self.flags_file = Some(file);
        Ok(self.status_flags)
    }

    fn set_status_flags(&mut self, file: AttachedObject<u32>, flags: u32) -> Result<(), i32> {
        self.flags_file = Some(file);
        self.status_flags = flags;
        Ok(())
    }

    fn mkdir_at(
        &mut self,
        request: &posix_service::PreparedMkdir,
        paths: PathObjects<u32>,
    ) -> Result<(), i32> {
        self.mkdir_request = Some(request.clone());
        self.root = Some(paths.root);
        self.directory = paths.base;
        Ok(())
    }

    fn unlink_at(
        &mut self,
        request: &posix_service::PreparedUnlink,
        paths: PathObjects<u32>,
    ) -> Result<(), i32> {
        self.unlink_request = Some(request.clone());
        self.root = Some(paths.root);
        self.directory = paths.base;
        Ok(())
    }

    fn rename_at(
        &mut self,
        request: &posix_service::PreparedRename,
        paths: posix_service::RenamePathObjects<u32>,
    ) -> Result<(), i32> {
        self.rename_request = Some(request.clone());
        self.rename_paths = Some(paths);
        Ok(())
    }

    fn truncate_at(
        &mut self,
        request: &posix_service::PreparedTruncate,
        paths: PathObjects<u32>,
    ) -> Result<(), i32> {
        self.truncate_request = Some(request.clone());
        self.root = Some(paths.root);
        self.directory = paths.base;
        Ok(())
    }

    fn symlink_at(
        &mut self,
        request: &posix_service::PreparedSymlink,
        paths: PathObjects<u32>,
    ) -> Result<(), i32> {
        self.symlink_request = Some(request.clone());
        self.root = Some(paths.root);
        self.directory = paths.base;
        Ok(())
    }

    fn readlink_at(
        &mut self,
        request: &posix_service::PreparedReadlink,
        paths: PathObjects<u32>,
    ) -> Result<Vec<u8>, i32> {
        self.readlink_request = Some(request.clone());
        self.root = Some(paths.root);
        self.directory = paths.base;
        Ok(b"../target".to_vec())
    }

    fn chmod_at(
        &mut self,
        request: &posix_service::PreparedChmod,
        paths: PathObjects<u32>,
    ) -> Result<(), i32> {
        self.chmod_request = Some(request.clone());
        self.root = Some(paths.root);
        self.directory = paths.base;
        Ok(())
    }

    fn chown_at(
        &mut self,
        request: &posix_service::PreparedChown,
        paths: PathObjects<u32>,
    ) -> Result<(), i32> {
        self.chown_request = Some(request.clone());
        self.root = Some(paths.root);
        self.directory = paths.base;
        Ok(())
    }

    fn access_at(&mut self, request: &PreparedAccess, paths: PathObjects<u32>) -> Result<(), i32> {
        self.access_request = Some(request.clone());
        self.root = Some(paths.root);
        self.directory = paths.base;
        Ok(())
    }

    fn retain_object(
        &mut self,
        object: AttachedObject<u32>,
    ) -> Result<AttachedObject<u32>, i32> {
        self.retained.push(object);
        Ok(AttachedObject {
            handle: object.handle + 1000,
            rights: object.rights,
        })
    }

    fn release_object(&mut self, object: AttachedObject<u32>) {
        self.released.push(object);
    }

    fn directory_path(
        &mut self,
        root: AttachedObject<u32>,
        directory: AttachedObject<u32>,
    ) -> Result<Vec<u8>, i32> {
        self.path_query = Some((root, directory));
        if self.directory_path.is_empty() {
            Ok(b"/".to_vec())
        } else {
            Ok(self.directory_path.clone())
        }
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
    assert_eq!(filesystem.roots_opened, 1);
    assert_eq!(filesystem.root.unwrap().handle, 100);
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
    assert_eq!(filesystem.root.unwrap().handle, 100);
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
    assert_eq!(filesystem.roots_opened, 0);
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

#[test]
fn file_mutations_use_only_the_explicitly_attached_handle() {
    let peer = PeerIdentity {
        process_id: 117,
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
        handle: 59,
        rights: 0x81,
    };
    let mut filesystem = RecordingFilesystem::default();
    let mut length = [0u8; protocol::FILE_LENGTH_PAYLOAD_LEN];
    protocol::encode_file_length(8192, &mut length).unwrap();

    let truncated = service.handle_objects(
        peer,
        protocol::Header {
            opcode: protocol::OP_FTRUNCATE,
            ..protocol::Header::default()
        },
        &length,
        &[file],
        &mut filesystem,
    );
    assert_eq!(truncated.response.header.status, protocol::STATUS_OK);
    assert_eq!(filesystem.truncated, Some((file, 8192)));

    let synced = service.handle_objects(
        peer,
        protocol::Header {
            opcode: protocol::OP_FSYNC,
            ..protocol::Header::default()
        },
        &[],
        &[file],
        &mut filesystem,
    );
    assert_eq!(synced.response.header.status, protocol::STATUS_OK);
    assert_eq!(filesystem.synced, Some(file));

    let changed_mode = service.handle_objects(
        peer,
        protocol::Header {
            opcode: protocol::OP_FCHMOD,
            ..protocol::Header::default()
        },
        &0o2750u32.to_le_bytes(),
        &[file],
        &mut filesystem,
    );
    assert_eq!(changed_mode.response.header.status, protocol::STATUS_OK);
    assert_eq!(filesystem.chmod_file, Some((file, 0o2750, 507, 26)));

    let mut owner = [0; protocol::FILE_OWNER_PAYLOAD_LEN];
    protocol::encode_file_owner(100, u32::MAX, &mut owner).unwrap();
    let changed_owner = service.handle_objects(
        peer,
        protocol::Header {
            opcode: protocol::OP_FCHOWN,
            ..protocol::Header::default()
        },
        &owner,
        &[file],
        &mut filesystem,
    );
    assert_eq!(changed_owner.response.header.status, protocol::STATUS_OK);
    assert_eq!(filesystem.chown_file, Some((file, 100, u32::MAX, 507, 26)));
    assert_eq!(filesystem.roots_opened, 0);
}

#[test]
fn file_status_flags_live_on_the_attached_open_description() {
    let peer = PeerIdentity {
        process_id: 118,
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
    let file = AttachedObject {
        handle: 60,
        rights: 0x81,
    };
    let mut filesystem = RecordingFilesystem::default();
    let wanted = protocol::OPEN_APPEND | protocol::OPEN_NONBLOCK;
    let mut flags = [0; protocol::FILE_FLAGS_PAYLOAD_LEN];
    protocol::encode_file_flags(wanted, &mut flags).unwrap();

    let set = service.handle_objects(
        peer,
        protocol::Header {
            opcode: protocol::OP_FSETFL,
            ..protocol::Header::default()
        },
        &flags,
        &[file],
        &mut filesystem,
    );
    assert_eq!(set.response.header.status, protocol::STATUS_OK);
    assert_eq!(filesystem.status_flags, wanted);
    assert_eq!(filesystem.flags_file, Some(file));

    let get = service.handle_objects(
        peer,
        protocol::Header {
            opcode: protocol::OP_FGETFL,
            ..protocol::Header::default()
        },
        &[],
        &[file],
        &mut filesystem,
    );
    assert_eq!(get.response.header.status, protocol::STATUS_OK);
    assert_eq!(
        protocol::decode_file_flags(&get.response.payload).unwrap(),
        wanted
    );
    assert_eq!(filesystem.roots_opened, 0);
}

#[test]
fn mkdir_uses_session_umask_credentials_and_directory_handles() {
    let peer = PeerIdentity {
        process_id: 119,
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
    let mut umask = [0; protocol::UMASK_PAYLOAD_LEN];
    protocol::encode_umask(0o027, &mut umask).unwrap();
    service.handle(
        peer,
        protocol::Header {
            opcode: protocol::OP_UMASK_SET,
            ..protocol::Header::default()
        },
        &umask,
    );
    let directory = AttachedObject {
        handle: 61,
        rights: 0x81,
    };
    let mut payload = [0; protocol::OPEN_AT_HEADER_LEN + protocol::MAX_PATH_LEN];
    let payload_len = protocol::encode_open_at(
        protocol::OpenAtRequest {
            base: protocol::OpenBase::AttachedDirectory,
            options: 0,
            mode: 0o777,
            path: "child",
        },
        &mut payload,
    )
    .unwrap();
    let mut filesystem = RecordingFilesystem::default();
    let result = service.handle_objects(
        peer,
        protocol::Header {
            opcode: protocol::OP_MKDIR_AT,
            ..protocol::Header::default()
        },
        &payload[..payload_len],
        &[directory],
        &mut filesystem,
    );

    assert_eq!(result.response.header.status, protocol::STATUS_OK);
    let request = filesystem.mkdir_request.unwrap();
    assert_eq!(request.path, "child");
    assert_eq!(request.mode, 0o750);
    assert_eq!(request.effective_uid, 505);
    assert_eq!(request.effective_gid, 24);
    assert_eq!(filesystem.directory, Some(directory));
}

#[test]
fn unlink_uses_authenticated_credentials_and_directory_handles() {
    let peer = PeerIdentity {
        process_id: 120,
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
    let directory = AttachedObject {
        handle: 62,
        rights: 0x81,
    };
    let mut payload = [0; protocol::STAT_AT_HEADER_LEN + protocol::MAX_PATH_LEN];
    let payload_len = protocol::encode_stat_at(
        protocol::StatAtRequest {
            base: protocol::OpenBase::AttachedDirectory,
            flags: protocol::UNLINK_REMOVE_DIRECTORY,
            path: "child",
        },
        &mut payload,
    )
    .unwrap();
    let mut filesystem = RecordingFilesystem::default();
    let result = service.handle_objects(
        peer,
        protocol::Header {
            opcode: protocol::OP_UNLINK_AT,
            ..protocol::Header::default()
        },
        &payload[..payload_len],
        &[directory],
        &mut filesystem,
    );

    assert_eq!(result.response.header.status, protocol::STATUS_OK);
    let request = filesystem.unlink_request.unwrap();
    assert_eq!(request.path, "child");
    assert_eq!(request.flags, protocol::UNLINK_REMOVE_DIRECTORY);
    assert_eq!(request.effective_uid, 504);
    assert_eq!(request.effective_gid, 23);
    assert_eq!(filesystem.directory, Some(directory));
}

#[test]
fn rename_wire_and_service_preserve_two_distinct_directory_handles() {
    let request = protocol::RenameAtRequest {
        old_base: protocol::OpenBase::AttachedDirectory,
        new_base: protocol::OpenBase::AttachedDirectory,
        old_path: "old/file",
        new_path: "new/file",
    };
    let mut encoded = [0; protocol::RENAME_AT_HEADER_LEN + protocol::MAX_PATH_LEN * 2];
    let length = protocol::encode_rename_at(request, &mut encoded).unwrap();
    assert_eq!(protocol::decode_rename_at(&encoded[..length]).unwrap(), request);

    let peer = PeerIdentity {
        process_id: 121,
        effective_uid: 503,
        effective_gid: 22,
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
    let old_directory = AttachedObject {
        handle: 63,
        rights: 0x81,
    };
    let new_directory = AttachedObject {
        handle: 64,
        rights: 0x81,
    };
    let mut filesystem = RecordingFilesystem::default();
    let result = service.handle_objects(
        peer,
        protocol::Header {
            opcode: protocol::OP_RENAME_AT,
            ..protocol::Header::default()
        },
        &encoded[..length],
        &[old_directory, new_directory],
        &mut filesystem,
    );

    assert_eq!(result.response.header.status, protocol::STATUS_OK);
    let prepared = filesystem.rename_request.unwrap();
    assert_eq!(prepared.old_path, "old/file");
    assert_eq!(prepared.new_path, "new/file");
    assert_eq!(prepared.effective_uid, 503);
    assert_eq!(prepared.effective_gid, 22);
    let paths = filesystem.rename_paths.unwrap();
    assert_eq!(paths.old_base, Some(old_directory));
    assert_eq!(paths.new_base, Some(new_directory));
    assert_eq!(filesystem.roots_opened, 1);
}

#[test]
fn truncate_path_uses_authenticated_session_and_explicit_base_handle() {
    let peer = PeerIdentity {
        process_id: 122,
        effective_uid: 502,
        effective_gid: 21,
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
    let directory = AttachedObject {
        handle: 65,
        rights: 0x81,
    };
    let mut payload = [0; protocol::TRUNCATE_AT_HEADER_LEN + protocol::MAX_PATH_LEN];
    let length = protocol::encode_truncate_at(
        protocol::TruncateAtRequest {
            base: protocol::OpenBase::AttachedDirectory,
            length: 1234,
            path: "file",
        },
        &mut payload,
    )
    .unwrap();
    let mut filesystem = RecordingFilesystem::default();
    let result = service.handle_objects(
        peer,
        protocol::Header {
            opcode: protocol::OP_TRUNCATE_AT,
            ..protocol::Header::default()
        },
        &payload[..length],
        &[directory],
        &mut filesystem,
    );

    assert_eq!(result.response.header.status, protocol::STATUS_OK);
    let prepared = filesystem.truncate_request.unwrap();
    assert_eq!(prepared.path, "file");
    assert_eq!(prepared.length, 1234);
    assert_eq!(prepared.effective_uid, 502);
    assert_eq!(prepared.effective_gid, 21);
    assert_eq!(filesystem.directory, Some(directory));
}

#[test]
fn symlink_wire_and_service_preserve_target_credentials_and_directory_handle() {
    let request = protocol::SymlinkAtRequest {
        base: protocol::OpenBase::AttachedDirectory,
        target: "../target",
        link_path: "links/name",
    };
    let mut encoded = [0; protocol::SYMLINK_AT_HEADER_LEN + protocol::MAX_PATH_LEN * 2];
    let length = protocol::encode_symlink_at(request, &mut encoded).unwrap();
    assert_eq!(protocol::decode_symlink_at(&encoded[..length]).unwrap(), request);

    let peer = PeerIdentity {
        process_id: 123,
        effective_uid: 501,
        effective_gid: 20,
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
    let directory = AttachedObject {
        handle: 66,
        rights: 0x81,
    };
    let mut filesystem = RecordingFilesystem::default();
    let result = service.handle_objects(
        peer,
        protocol::Header {
            opcode: protocol::OP_SYMLINK_AT,
            ..protocol::Header::default()
        },
        &encoded[..length],
        &[directory],
        &mut filesystem,
    );

    assert_eq!(result.response.header.status, protocol::STATUS_OK);
    let prepared = filesystem.symlink_request.unwrap();
    assert_eq!(prepared.target, "../target");
    assert_eq!(prepared.link_path, "links/name");
    assert_eq!(prepared.effective_uid, 501);
    assert_eq!(prepared.effective_gid, 20);
    assert_eq!(filesystem.directory, Some(directory));
}

#[test]
fn readlink_uses_authenticated_session_and_returns_only_the_target_bytes() {
    let peer = PeerIdentity {
        process_id: 124,
        effective_uid: 500,
        effective_gid: 19,
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
    let directory = AttachedObject {
        handle: 67,
        rights: 0x81,
    };
    let mut payload = [0; protocol::STAT_AT_HEADER_LEN + protocol::MAX_PATH_LEN];
    let length = protocol::encode_stat_at(
        protocol::StatAtRequest {
            base: protocol::OpenBase::AttachedDirectory,
            flags: 0,
            path: "links/name",
        },
        &mut payload,
    )
    .unwrap();
    let mut filesystem = RecordingFilesystem::default();
    let result = service.handle_objects(
        peer,
        protocol::Header {
            opcode: protocol::OP_READLINK_AT,
            ..protocol::Header::default()
        },
        &payload[..length],
        &[directory],
        &mut filesystem,
    );

    assert_eq!(result.response.header.status, protocol::STATUS_OK);
    assert_eq!(result.response.payload, b"../target");
    let prepared = filesystem.readlink_request.unwrap();
    assert_eq!(prepared.path, "links/name");
    assert_eq!(prepared.effective_uid, 500);
    assert_eq!(prepared.effective_gid, 19);
    assert_eq!(filesystem.directory, Some(directory));
}

#[test]
fn chmod_uses_authenticated_session_and_an_explicit_directory_handle() {
    let peer = PeerIdentity {
        process_id: 125,
        effective_uid: 499,
        effective_gid: 18,
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
    let directory = AttachedObject {
        handle: 68,
        rights: 0x81,
    };
    let mut payload = [0; protocol::OPEN_AT_HEADER_LEN + protocol::MAX_PATH_LEN];
    let length = protocol::encode_open_at(
        protocol::OpenAtRequest {
            base: protocol::OpenBase::AttachedDirectory,
            options: 0,
            mode: 0o2750,
            path: "file",
        },
        &mut payload,
    )
    .unwrap();
    let mut filesystem = RecordingFilesystem::default();
    let result = service.handle_objects(
        peer,
        protocol::Header {
            opcode: protocol::OP_CHMOD_AT,
            ..protocol::Header::default()
        },
        &payload[..length],
        &[directory],
        &mut filesystem,
    );

    assert_eq!(result.response.header.status, protocol::STATUS_OK);
    let prepared = filesystem.chmod_request.unwrap();
    assert_eq!(prepared.path, "file");
    assert_eq!(prepared.mode, 0o2750);
    assert_eq!(prepared.effective_uid, 499);
    assert_eq!(prepared.effective_gid, 18);
    assert_eq!(filesystem.directory, Some(directory));
}

#[test]
fn chown_wire_and_service_use_authenticated_credentials() {
    let request = protocol::ChownAtRequest {
        base: protocol::OpenBase::AttachedDirectory,
        flags: protocol::CHOWN_NOFOLLOW,
        uid: 42,
        gid: u32::MAX,
        path: "link",
    };
    let mut payload = [0; protocol::CHOWN_AT_HEADER_LEN + protocol::MAX_PATH_LEN];
    let length = protocol::encode_chown_at(request, &mut payload).unwrap();
    assert_eq!(protocol::decode_chown_at(&payload[..length]).unwrap(), request);

    let peer = PeerIdentity {
        process_id: 126,
        effective_uid: 498,
        effective_gid: 17,
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
    let directory = AttachedObject {
        handle: 69,
        rights: 0x81,
    };
    let mut filesystem = RecordingFilesystem::default();
    let result = service.handle_objects(
        peer,
        protocol::Header {
            opcode: protocol::OP_CHOWN_AT,
            ..protocol::Header::default()
        },
        &payload[..length],
        &[directory],
        &mut filesystem,
    );

    assert_eq!(result.response.header.status, protocol::STATUS_OK);
    let prepared = filesystem.chown_request.unwrap();
    assert_eq!(prepared.path, "link");
    assert_eq!(prepared.uid, 42);
    assert_eq!(prepared.gid, u32::MAX);
    assert_eq!(prepared.flags, protocol::CHOWN_NOFOLLOW);
    assert_eq!(prepared.effective_uid, 498);
    assert_eq!(prepared.effective_gid, 17);
    assert_eq!(filesystem.directory, Some(directory));
}

#[test]
fn access_uses_authenticated_session_credentials_and_one_atomic_operation() {
    let peer = PeerIdentity {
        process_id: 114,
        effective_uid: 508,
        effective_gid: 27,
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
    let mut payload = [0u8; protocol::ACCESS_AT_HEADER_LEN + 16];
    let length = protocol::encode_access_at(
        protocol::AccessAtRequest {
            base: protocol::OpenBase::ProcessCwd,
            flags: protocol::ACCESS_EFFECTIVE_IDS,
            modes: protocol::ACCESS_READ | protocol::ACCESS_EXECUTE,
            path: "tool",
        },
        &mut payload,
    )
    .unwrap();
    let mut filesystem = RecordingFilesystem::default();
    let result = service.handle_objects(
        peer,
        protocol::Header {
            opcode: protocol::OP_ACCESS_AT,
            request_id: 17,
            payload_len: length as u32,
            ..protocol::Header::default()
        },
        &payload[..length],
        &[],
        &mut filesystem,
    );

    assert_eq!(result.response.header.status, protocol::STATUS_OK);
    assert!(result.handles.is_empty());
    assert_eq!(filesystem.roots_opened, 1);
    assert_eq!(filesystem.root.unwrap().handle, 100);
    assert_eq!(filesystem.directory.unwrap().handle, 101);
    let repeated = service.handle_objects(
        peer,
        protocol::Header {
            opcode: protocol::OP_ACCESS_AT,
            request_id: 18,
            payload_len: length as u32,
            ..protocol::Header::default()
        },
        &payload[..length],
        &[],
        &mut filesystem,
    );
    assert_eq!(repeated.response.header.status, protocol::STATUS_OK);
    assert_eq!(filesystem.roots_opened, 1);
    let request = filesystem.access_request.unwrap();
    assert_eq!(request.path, "tool");
    assert_eq!(request.uid, peer.effective_uid);
    assert_eq!(request.gid, peer.effective_gid);
    assert_eq!(
        request.modes,
        protocol::ACCESS_READ | protocol::ACCESS_EXECUTE
    );
}

#[test]
fn chdir_replaces_the_session_cwd_with_an_open_directory() {
    let peer = PeerIdentity {
        process_id: 115,
        effective_uid: 509,
        effective_gid: 28,
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
    let mut payload = [0u8; protocol::STAT_AT_HEADER_LEN + 8];
    let length = protocol::encode_stat_at(
        protocol::StatAtRequest {
            base: protocol::OpenBase::ProcessCwd,
            flags: 0,
            path: "work",
        },
        &mut payload,
    )
    .unwrap();
    let mut filesystem = RecordingFilesystem::default();

    let result = service.handle_objects(
        peer,
        protocol::Header {
            opcode: protocol::OP_CHDIR_AT,
            request_id: 19,
            payload_len: length as u32,
            ..protocol::Header::default()
        },
        &payload[..length],
        &[],
        &mut filesystem,
    );

    assert_eq!(result.response.header.status, protocol::STATUS_OK);
    assert!(result.handles.is_empty());
    let request = filesystem.request.as_ref().unwrap();
    assert_eq!(request.path, "work");
    assert_eq!(request.options, protocol::OPEN_READ | protocol::OPEN_DIRECTORY);
    assert_eq!(filesystem.directory.unwrap().handle, 101);
    assert_eq!(service.session_directories(peer.process_id).unwrap().cwd.handle, 200);
    assert_eq!(filesystem.released, vec![AttachedObject { handle: 101, rights: 0x81 }]);
}

#[test]
fn getcwd_resolves_the_live_root_and_cwd_handles() {
    let peer = PeerIdentity {
        process_id: 117,
        effective_uid: 511,
        effective_gid: 30,
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
    let mut filesystem = RecordingFilesystem {
        directory_path: b"/renamed/work".to_vec(),
        ..RecordingFilesystem::default()
    };

    let result = service.handle_objects(
        peer,
        protocol::Header {
            opcode: protocol::OP_GETCWD,
            request_id: 22,
            ..protocol::Header::default()
        },
        &[],
        &[],
        &mut filesystem,
    );

    assert_eq!(result.response.header.status, protocol::STATUS_OK);
    assert_eq!(result.response.payload, b"/renamed/work");
    assert_eq!(result.response.header.payload_len, 13);
    assert_eq!(
        filesystem.path_query,
        Some((
            AttachedObject {
                handle: 100,
                rights: 0x81,
            },
            AttachedObject {
                handle: 101,
                rights: 0x81,
            },
        ))
    );
}

#[test]
fn fchdir_retains_a_directory_handle_and_rejects_regular_files() {
    let peer = PeerIdentity {
        process_id: 116,
        effective_uid: 510,
        effective_gid: 29,
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
    let directory = AttachedObject {
        handle: 58,
        rights: 0x4000_0000_0000_0081,
    };
    let mut filesystem = RecordingFilesystem {
        stat_mode: Some(0o040755),
        ..RecordingFilesystem::default()
    };

    let result = service.handle_objects(
        peer,
        protocol::Header {
            opcode: protocol::OP_FCHDIR,
            request_id: 20,
            ..protocol::Header::default()
        },
        &[],
        &[directory],
        &mut filesystem,
    );

    assert_eq!(result.response.header.status, protocol::STATUS_OK);
    assert_eq!(filesystem.stat_file, Some(directory));
    assert_eq!(filesystem.retained, vec![directory]);
    assert_eq!(service.session_directories(peer.process_id).unwrap().cwd.handle, 1058);
    assert_eq!(filesystem.released, vec![AttachedObject { handle: 101, rights: 0x81 }]);

    filesystem.stat_mode = Some(0o100644);
    let regular = AttachedObject {
        handle: 59,
        rights: directory.rights,
    };
    let rejected = service.handle_objects(
        peer,
        protocol::Header {
            opcode: protocol::OP_FCHDIR,
            request_id: 21,
            ..protocol::Header::default()
        },
        &[],
        &[regular],
        &mut filesystem,
    );
    assert_eq!(rejected.response.header.status, -20);
    assert_eq!(filesystem.retained, vec![directory]);
    assert_eq!(service.session_directories(peer.process_id).unwrap().cwd.handle, 1058);
}
