use std::cell::RefCell;
use std::collections::BTreeMap;

use mochios_filesystem_protocol as filesystem_protocol;
use mochios_posix_client::{
    Client, ClientError, ObjectHandleAttachment, ObjectHandles, ObjectTransport, Transport,
};
use mochios_posix_protocol as protocol;
use posix_service::{
    AttachedObject, AuthenticatedProcess, FilesystemBackend, OpenedObject, PathObjects,
    PeerIdentity, PosixService, PreparedAccess, PreparedOpen, PreparedStat, ProcessBackend,
    ProcessLifecycle, STATUS_EINVAL, SessionDirectories,
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
        service: RefCell::new(service_for(peer)),
        peer,
    })
}

fn service_for(peer: PeerIdentity) -> PosixService {
    let mut service = PosixService::new();
    assert_eq!(
        service.bind_process(
            peer,
            AuthenticatedProcess {
                handle: u32::try_from(peer.process_id).unwrap(),
                process_id: peer.process_id,
            },
        ),
        Ok(true)
    );
    service
}

#[test]
fn session_registration_requires_a_matching_authenticated_process() {
    let peer = PeerIdentity {
        process_id: 40,
        effective_uid: 501,
        effective_gid: 20,
    };
    let mut service = PosixService::new();
    let header = protocol::Header {
        opcode: protocol::OP_SESSION_REGISTER,
        request_id: 8,
        ..protocol::Header::default()
    };
    assert_eq!(
        service.handle(peer, header, &[]).header.status,
        STATUS_EINVAL
    );
    assert_eq!(
        service.bind_process(
            peer,
            AuthenticatedProcess {
                handle: 9,
                process_id: 41,
            },
        ),
        Err(STATUS_EINVAL)
    );
    assert!(service.session(peer.process_id).is_none());
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
    let mut service = service_for(peer);
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

#[test]
fn effective_credentials_change_independently_and_reset_atomically() {
    let client = client(PeerIdentity {
        process_id: 94,
        effective_uid: 0,
        effective_gid: 0,
    });
    client.register_session().unwrap();

    client.set_effective_gid(42).unwrap();
    client.set_effective_uid(501).unwrap();
    let changed = client.session_info().unwrap();
    assert_eq!(changed.real_uid, 0);
    assert_eq!(changed.effective_uid, 501);
    assert_eq!(changed.real_gid, 0);
    assert_eq!(changed.effective_gid, 42);
    assert_eq!(
        client.set_effective_uid(777).unwrap_err(),
        ClientError::Remote(protocol::STATUS_EPERM)
    );
    assert_eq!(
        client.set_effective_gid(777).unwrap_err(),
        ClientError::Remote(protocol::STATUS_EPERM)
    );

    client.reset_effective_ids().unwrap();
    let reset = client.session_info().unwrap();
    assert_eq!(reset.real_uid, 0);
    assert_eq!(reset.effective_uid, 0);
    assert_eq!(reset.real_gid, 0);
    assert_eq!(reset.effective_gid, 0);
    let transport = client.into_transport();
    let service = transport.service.borrow();
    let stored = service.session(94).unwrap();
    assert_eq!(stored.saved_uid, 0);
    assert_eq!(stored.saved_gid, 0);
}

#[test]
fn supplementary_groups_round_trip_and_require_privilege() {
    let privileged = client(PeerIdentity {
        process_id: 95,
        effective_uid: 0,
        effective_gid: 0,
    });
    let mut groups = [0u32; protocol::MAX_SUPPLEMENTARY_GROUPS];
    assert_eq!(
        privileged.get_groups(&mut groups).unwrap_err(),
        ClientError::Remote(protocol::STATUS_ESRCH)
    );
    privileged.register_session().unwrap();
    assert_eq!(privileged.get_groups(&mut groups).unwrap(), 0);
    privileged.set_groups(&[20, 42, 501]).unwrap();
    assert_eq!(privileged.get_groups(&mut groups).unwrap(), 3);
    assert_eq!(&groups[..3], &[20, 42, 501]);
    privileged.set_groups(&[]).unwrap();
    assert_eq!(privileged.get_groups(&mut groups).unwrap(), 0);

    let unprivileged = client(PeerIdentity {
        process_id: 96,
        effective_uid: 501,
        effective_gid: 20,
    });
    unprivileged.register_session().unwrap();
    assert_eq!(
        unprivileged.set_groups(&[42]).unwrap_err(),
        ClientError::Remote(protocol::STATUS_EPERM)
    );
}

#[test]
fn supplementary_group_wire_format_is_bounded_and_strict() {
    let mut encoded = [0u8; protocol::GROUP_LIST_MAX_LEN];
    let length = protocol::encode_group_list(&[7, 11, 13], &mut encoded).unwrap();
    let mut decoded = [0u32; protocol::MAX_SUPPLEMENTARY_GROUPS];
    assert_eq!(
        protocol::decode_group_list(&encoded[..length], &mut decoded),
        Ok(3)
    );
    assert_eq!(&decoded[..3], &[7, 11, 13]);
    assert_eq!(
        protocol::decode_group_list(&encoded[..length], &mut decoded[..2]),
        Err(protocol::ProtocolError::BufferTooSmall)
    );
    assert_eq!(
        protocol::decode_group_list(&encoded[..length + 1], &mut decoded),
        Err(protocol::ProtocolError::InvalidLength)
    );
    assert_eq!(
        protocol::encode_group_list(&[0; protocol::MAX_SUPPLEMENTARY_GROUPS + 1], &mut encoded),
        Err(protocol::ProtocolError::InvalidLength)
    );
}

#[test]
fn resource_limits_round_trip_and_enforce_soft_hard_rules() {
    let client = client(PeerIdentity {
        process_id: 94,
        effective_uid: 503,
        effective_gid: 22,
    });
    client.register_session().unwrap();
    assert_eq!(
        client
            .resource_limit(0, protocol::RLIMIT_NOFILE, None)
            .unwrap(),
        protocol::ResourceLimit::INFINITY
    );
    let finite = protocol::ResourceLimit {
        soft: 64,
        hard: 128,
    };
    assert_eq!(
        client
            .resource_limit(0, protocol::RLIMIT_NOFILE, Some(finite))
            .unwrap(),
        protocol::ResourceLimit::INFINITY
    );
    assert_eq!(
        client
            .resource_limit(0, protocol::RLIMIT_NOFILE, None)
            .unwrap(),
        finite
    );
    assert_eq!(
        client
            .resource_limit(
                0,
                protocol::RLIMIT_NOFILE,
                Some(protocol::ResourceLimit {
                    soft: 64,
                    hard: 129,
                }),
            )
            .unwrap_err(),
        ClientError::Remote(protocol::STATUS_EPERM)
    );
    assert_eq!(
        client
            .resource_limit(
                0,
                protocol::RLIMIT_NOFILE,
                Some(protocol::ResourceLimit {
                    soft: 129,
                    hard: 128,
                }),
            )
            .unwrap_err(),
        ClientError::Remote(STATUS_EINVAL)
    );
    assert_eq!(
        client
            .resource_limit(0, protocol::RLIMIT_COUNT, None)
            .unwrap_err(),
        ClientError::Remote(STATUS_EINVAL)
    );
}

#[test]
fn resource_limit_wire_format_is_fixed_and_strict() {
    let request = protocol::ResourceLimitRequest {
        process_id: 42,
        resource: protocol::RLIMIT_AS,
        flags: protocol::RESOURCE_LIMIT_SET,
        limit: protocol::ResourceLimit {
            soft: 1024,
            hard: 2048,
        },
    };
    let mut encoded = [0u8; protocol::RESOURCE_LIMIT_REQUEST_LEN];
    protocol::encode_resource_limit_request(request, &mut encoded).unwrap();
    assert_eq!(
        protocol::decode_resource_limit_request(&encoded),
        Ok(request)
    );

    let mut trailing = [0u8; protocol::RESOURCE_LIMIT_REQUEST_LEN + 1];
    trailing[..protocol::RESOURCE_LIMIT_REQUEST_LEN].copy_from_slice(&encoded);
    assert_eq!(
        protocol::decode_resource_limit_request(&trailing),
        Err(protocol::ProtocolError::InvalidLength)
    );
    encoded[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(
        protocol::decode_resource_limit_request(&encoded),
        Err(protocol::ProtocolError::InvalidLength)
    );
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
    let mut wait = [0u8; protocol::WAIT_REQUEST_LEN];
    protocol::encode_wait_request(
        protocol::WaitRequest {
            selector: -7,
            options: protocol::WAIT_NOHANG | protocol::WAIT_UNTRACED | protocol::WAIT_CONTINUED,
        },
        &mut wait,
    )
    .unwrap();
    assert_eq!(
        protocol::decode_wait_request(&wait).unwrap(),
        protocol::WaitRequest {
            selector: -7,
            options: protocol::WAIT_NOHANG | protocol::WAIT_UNTRACED | protocol::WAIT_CONTINUED,
        }
    );
    wait[12] = 1;
    assert_eq!(
        protocol::decode_wait_request(&wait),
        Err(protocol::ProtocolError::InvalidLength)
    );

    let delivery = protocol::SignalDelivery {
        signal: protocol::SIGNAL_TSTP,
        token: 0x1020_3040_5060_7080,
    };
    let mut encoded_delivery = [0u8; protocol::SIGNAL_DELIVERY_LEN];
    protocol::encode_signal_delivery(delivery, &mut encoded_delivery).unwrap();
    assert_eq!(
        protocol::decode_signal_delivery(&encoded_delivery),
        Ok(delivery)
    );
    encoded_delivery[4] = 1;
    assert_eq!(
        protocol::decode_signal_delivery(&encoded_delivery),
        Err(protocol::ProtocolError::InvalidLength)
    );
    assert_eq!(
        protocol::encode_signal_delivery(
            protocol::SignalDelivery {
                signal: 0,
                token: 1,
            },
            &mut encoded_delivery,
        ),
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
    assert_eq!(
        protocol::HEADER_LEN + rename_len,
        protocol::CONTROL_MESSAGE_LEN
    );
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
        let metadata = protocol::fd_metadata_key(fd).unwrap();
        assert_ne!(handle, metadata);
        assert_ne!(handle, protocol::CONTROL_HANDLE_KEY);
        assert_eq!(protocol::inherited_fd_from_key(handle), Some(fd));
        assert_eq!(protocol::inherited_fd_from_key(metadata), Some(fd));
    }
    assert_eq!(protocol::fd_handle_key(-1), None);
    assert_eq!(protocol::fd_metadata_key(-1), None);
    assert_eq!(protocol::inherited_fd_from_key(0), None);

    let metadata = protocol::InheritedFdMetadata {
        kind: protocol::INHERITED_FD_KIND_FILE,
        open_flags: 0xfeed_beef,
        descriptor_flags: protocol::INHERITED_FD_DESCRIPTOR_CLOEXEC,
    };
    let encoded = protocol::encode_inherited_fd_metadata(metadata).unwrap();
    assert_eq!(
        protocol::decode_inherited_fd_metadata(encoded),
        Some(metadata)
    );
    assert_eq!(protocol::decode_inherited_fd_metadata(0), None);
    assert_eq!(
        protocol::encode_inherited_fd_metadata(protocol::InheritedFdMetadata {
            kind: 4,
            ..metadata
        }),
        None
    );
    assert_eq!(
        protocol::encode_inherited_fd_metadata(protocol::InheritedFdMetadata {
            descriptor_flags: 2,
            ..metadata
        }),
        None
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

struct ChildRegistrationTransport;

impl Transport for ChildRegistrationTransport {
    type Error = ();

    fn call(&self, _request: &[u8], _response: &mut [u8]) -> Result<usize, Self::Error> {
        Err(())
    }
}

impl ObjectTransport for ChildRegistrationTransport {
    type Handle = u32;

    fn call_with_handles(
        &self,
        request: &[u8],
        response: &mut [u8],
        handles: &mut ObjectHandles<Self::Handle>,
    ) -> Result<usize, Self::Error> {
        let (header, payload) = protocol::decode(request).map_err(|_| ())?;
        assert_eq!(header.opcode, protocol::OP_PROCESS_FORKED);
        assert!(payload.is_empty());
        assert_eq!(
            handles.get(0),
            Some(ObjectHandleAttachment {
                handle: 52,
                rights: mnu_abi::HANDLE_RIGHT_WAIT | mnu_abi::HANDLE_RIGHT_SIGNAL,
            })
        );
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
fn client_registers_a_child_only_by_transferring_its_process_handle() {
    Client::new(ChildRegistrationTransport)
        .register_child(ObjectHandleAttachment {
            handle: 52,
            rights: mnu_abi::HANDLE_RIGHT_WAIT | mnu_abi::HANDLE_RIGHT_SIGNAL,
        })
        .unwrap();
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
    let mut service = service_for(peer);
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

#[test]
fn prepared_filesystem_request_carries_supplementary_groups() {
    let peer = PeerIdentity {
        process_id: 102,
        effective_uid: 0,
        effective_gid: 0,
    };
    let mut service = service_for(peer);
    service.handle(
        peer,
        protocol::Header {
            opcode: protocol::OP_SESSION_REGISTER,
            ..protocol::Header::default()
        },
        &[],
    );
    let mut groups = [0u8; protocol::GROUP_LIST_MAX_LEN];
    let groups_len = protocol::encode_group_list(&[20, 42], &mut groups).unwrap();
    assert_eq!(
        service
            .handle(
                peer,
                protocol::Header {
                    opcode: protocol::OP_GROUPS_SET,
                    ..protocol::Header::default()
                },
                &groups[..groups_len],
            )
            .header
            .status,
        protocol::STATUS_OK
    );
    let mut payload = [0u8; protocol::OPEN_AT_HEADER_LEN + 16];
    let length = protocol::encode_open_at(
        protocol::OpenAtRequest {
            base: protocol::OpenBase::ProcessCwd,
            options: protocol::OPEN_READ,
            mode: 0,
            path: "notes.txt",
        },
        &mut payload,
    )
    .unwrap();

    let open = service
        .prepare_open_at(peer, &payload[..length], 0)
        .unwrap();
    assert_eq!(open.supplementary_groups, vec![20, 42]);
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
            protocol::OP_CHDIR_AT | protocol::OP_CHROOT_AT => {
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
fn client_transfers_directory_handles_for_chdir_chroot_and_fchdir() {
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
    client
        .chroot_at(
            mochios_posix_client::StatAtBase::Directory(directory),
            "child",
        )
        .unwrap();
    client.fchdir(directory).unwrap();
}

#[derive(Default)]
struct RecordingFilesystem {
    request: Option<PreparedOpen>,
    directory_request: Option<PreparedStat>,
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
    link_request: Option<posix_service::PreparedLink>,
    link_paths: Option<posix_service::RenamePathObjects<u32>>,
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

#[derive(Default)]
struct RecordingProcesses {
    states: BTreeMap<u32, ProcessLifecycle>,
    suspend_error: Option<i32>,
    terminate_error: Option<i32>,
    suspended: Vec<u32>,
    terminated: Vec<(u32, u64)>,
    released: Vec<u32>,
}

impl ProcessBackend<u32> for RecordingProcesses {
    fn status(&mut self, process: u32) -> Result<ProcessLifecycle, i32> {
        self.states.get(&process).copied().ok_or(-3)
    }

    fn suspend(&mut self, process: u32) -> Result<(), i32> {
        if let Some(error) = self.suspend_error {
            return Err(error);
        }
        if !self.states.contains_key(&process) {
            return Err(-3);
        }
        self.suspended.push(process);
        Ok(())
    }

    fn terminate(&mut self, process: u32, exit_code: u64) -> Result<(), i32> {
        if let Some(error) = self.terminate_error {
            return Err(error);
        }
        if !self.states.contains_key(&process) {
            return Err(-3);
        }
        self.terminated.push((process, exit_code));
        self.states
            .insert(process, ProcessLifecycle::Exited { exit_code });
        Ok(())
    }

    fn release(&mut self, process: u32) {
        self.released.push(process);
    }
}

impl FilesystemBackend<u32> for RecordingFilesystem {
    fn open_session_root(
        &mut self,
        _effective_uid: u32,
        _effective_gid: u32,
        _supplementary_groups: &[u32],
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

    fn open_directory_at(
        &mut self,
        request: &PreparedStat,
        paths: PathObjects<u32>,
    ) -> Result<OpenedObject<u32>, i32> {
        self.directory_request = Some(request.clone());
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
        _supplementary_groups: &[u32],
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
        _supplementary_groups: &[u32],
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

    fn link_at(
        &mut self,
        request: &posix_service::PreparedLink,
        paths: posix_service::RenamePathObjects<u32>,
    ) -> Result<(), i32> {
        self.link_request = Some(request.clone());
        self.link_paths = Some(paths);
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

    fn retain_object(&mut self, object: AttachedObject<u32>) -> Result<AttachedObject<u32>, i32> {
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
fn adopted_child_inherits_posix_state_and_retained_directories() {
    let peer = PeerIdentity {
        process_id: 111,
        effective_uid: 505,
        effective_gid: 24,
    };
    let mut service = service_for(peer);
    assert_eq!(
        service
            .handle(
                peer,
                protocol::Header {
                    opcode: protocol::OP_SESSION_REGISTER,
                    ..protocol::Header::default()
                },
                &[],
            )
            .header
            .status,
        protocol::STATUS_OK
    );
    let mut filesystem = RecordingFilesystem::default();
    assert_eq!(
        service
            .handle_objects(
                peer,
                protocol::Header {
                    opcode: protocol::OP_GETCWD,
                    ..protocol::Header::default()
                },
                &[],
                &[],
                &mut filesystem,
            )
            .response
            .header
            .status,
        protocol::STATUS_OK
    );
    service
        .adopt_child(
            peer,
            AuthenticatedProcess {
                handle: 52,
                process_id: 112,
            },
            &mut filesystem,
        )
        .unwrap();

    assert_eq!(service.parent_id(112), Some(111));
    assert!(service.is_child(111, 112));
    assert_eq!(service.process_handle(112), Some(52));
    let child = service.session(112).unwrap();
    assert_eq!(child.effective_uid, 505);
    assert_eq!(child.effective_gid, 24);
    assert_eq!(child.umask, 0o022);
    assert_eq!(
        service.session_directories(112),
        Some(&SessionDirectories {
            root: AttachedObject {
                handle: 1100,
                rights: 0x81,
            },
            cwd: AttachedObject {
                handle: 1101,
                rights: 0x81,
            },
        })
    );
    assert_eq!(filesystem.retained.len(), 2);
}

#[test]
fn adopted_child_inherits_an_independent_supplementary_group_list() {
    let parent = PeerIdentity {
        process_id: 115,
        effective_uid: 0,
        effective_gid: 0,
    };
    let child = PeerIdentity {
        process_id: 116,
        effective_uid: 0,
        effective_gid: 0,
    };
    let mut service = service_for(parent);
    service.handle(
        parent,
        protocol::Header {
            opcode: protocol::OP_SESSION_REGISTER,
            ..protocol::Header::default()
        },
        &[],
    );
    let mut groups = [0u8; protocol::GROUP_LIST_MAX_LEN];
    let length = protocol::encode_group_list(&[10, 20], &mut groups).unwrap();
    assert_eq!(
        service
            .handle(
                parent,
                protocol::Header {
                    opcode: protocol::OP_GROUPS_SET,
                    ..protocol::Header::default()
                },
                &groups[..length],
            )
            .header
            .status,
        protocol::STATUS_OK
    );

    let mut filesystem = RecordingFilesystem::default();
    service
        .adopt_child(
            parent,
            AuthenticatedProcess {
                handle: 54,
                process_id: child.process_id,
            },
            &mut filesystem,
        )
        .unwrap();
    assert_eq!(
        service.supplementary_groups(child.process_id),
        Some(&[10, 20][..])
    );

    let length = protocol::encode_group_list(&[30], &mut groups).unwrap();
    assert_eq!(
        service
            .handle(
                child,
                protocol::Header {
                    opcode: protocol::OP_GROUPS_SET,
                    ..protocol::Header::default()
                },
                &groups[..length],
            )
            .header
            .status,
        protocol::STATUS_OK
    );
    assert_eq!(
        service.supplementary_groups(parent.process_id),
        Some(&[10, 20][..])
    );
    assert_eq!(
        service.supplementary_groups(child.process_id),
        Some(&[30][..])
    );
}

#[test]
fn adopted_child_inherits_an_independent_resource_limit_table() {
    let parent = PeerIdentity {
        process_id: 113,
        effective_uid: 505,
        effective_gid: 24,
    };
    let child = PeerIdentity {
        process_id: 114,
        effective_uid: 505,
        effective_gid: 24,
    };
    let mut service = service_for(parent);
    service.handle(
        parent,
        protocol::Header {
            opcode: protocol::OP_SESSION_REGISTER,
            ..protocol::Header::default()
        },
        &[],
    );
    let inherited = protocol::ResourceLimit { soft: 32, hard: 64 };
    let mut request = [0u8; protocol::RESOURCE_LIMIT_REQUEST_LEN];
    protocol::encode_resource_limit_request(
        protocol::ResourceLimitRequest {
            process_id: 0,
            resource: protocol::RLIMIT_NOFILE,
            flags: protocol::RESOURCE_LIMIT_SET,
            limit: inherited,
        },
        &mut request,
    )
    .unwrap();
    assert_eq!(
        service
            .handle(
                parent,
                protocol::Header {
                    opcode: protocol::OP_RESOURCE_LIMIT,
                    ..protocol::Header::default()
                },
                &request,
            )
            .header
            .status,
        protocol::STATUS_OK
    );

    let mut filesystem = RecordingFilesystem::default();
    service
        .adopt_child(
            parent,
            AuthenticatedProcess {
                handle: 53,
                process_id: child.process_id,
            },
            &mut filesystem,
        )
        .unwrap();

    protocol::encode_resource_limit_request(
        protocol::ResourceLimitRequest {
            process_id: 0,
            resource: protocol::RLIMIT_NOFILE,
            flags: 0,
            limit: protocol::ResourceLimit::default(),
        },
        &mut request,
    )
    .unwrap();
    let response = service.handle(
        child,
        protocol::Header {
            opcode: protocol::OP_RESOURCE_LIMIT,
            ..protocol::Header::default()
        },
        &request,
    );
    assert_eq!(
        protocol::decode_resource_limit(&response.payload),
        Ok(inherited)
    );

    protocol::encode_resource_limit_request(
        protocol::ResourceLimitRequest {
            process_id: 0,
            resource: protocol::RLIMIT_NOFILE,
            flags: protocol::RESOURCE_LIMIT_SET,
            limit: protocol::ResourceLimit { soft: 16, hard: 64 },
        },
        &mut request,
    )
    .unwrap();
    service.handle(
        child,
        protocol::Header {
            opcode: protocol::OP_RESOURCE_LIMIT,
            ..protocol::Header::default()
        },
        &request,
    );

    protocol::encode_resource_limit_request(
        protocol::ResourceLimitRequest {
            process_id: 0,
            resource: protocol::RLIMIT_NOFILE,
            flags: 0,
            limit: protocol::ResourceLimit::default(),
        },
        &mut request,
    )
    .unwrap();
    let parent_response = service.handle(
        parent,
        protocol::Header {
            opcode: protocol::OP_RESOURCE_LIMIT,
            ..protocol::Header::default()
        },
        &request,
    );
    assert_eq!(
        protocol::decode_resource_limit(&parent_response.payload),
        Ok(inherited)
    );
}

#[test]
fn wait_selects_and_reaps_only_authenticated_children() {
    let peer = PeerIdentity {
        process_id: 121,
        effective_uid: 505,
        effective_gid: 24,
    };
    let mut service = service_for(peer);
    service.handle(
        peer,
        protocol::Header {
            opcode: protocol::OP_SESSION_REGISTER,
            ..protocol::Header::default()
        },
        &[],
    );
    let mut filesystem = RecordingFilesystem::default();
    for (handle, process_id) in [(62, 122), (63, 123)] {
        service
            .adopt_child(
                peer,
                AuthenticatedProcess { handle, process_id },
                &mut filesystem,
            )
            .unwrap();
    }
    let mut processes = RecordingProcesses::default();
    processes.states.insert(62, ProcessLifecycle::Running);
    processes
        .states
        .insert(63, ProcessLifecycle::Exited { exit_code: 7 });

    assert_eq!(
        service
            .wait_handles(
                peer,
                protocol::WaitRequest {
                    selector: 122,
                    options: 0,
                },
            )
            .unwrap(),
        vec![62]
    );

    let waited = service
        .wait_child(
            peer,
            protocol::WaitRequest {
                selector: -1,
                options: 0,
            },
            &mut filesystem,
            &mut processes,
        )
        .unwrap();
    assert_eq!(waited.process_id, 123);
    assert_eq!(waited.status, 7 << 8);
    assert_eq!(processes.released, vec![63]);
    assert!(!service.is_child(121, 123));
    assert!(service.session(123).is_none());

    assert_eq!(
        service
            .wait_child(
                peer,
                protocol::WaitRequest {
                    selector: 122,
                    options: protocol::WAIT_NOHANG,
                },
                &mut filesystem,
                &mut processes,
            )
            .unwrap(),
        protocol::WaitResult::default()
    );
    assert_eq!(
        service.wait_child(
            peer,
            protocol::WaitRequest {
                selector: 122,
                options: 0,
            },
            &mut filesystem,
            &mut processes,
        ),
        Err(protocol::STATUS_EAGAIN)
    );
    assert_eq!(
        service.wait_child(
            peer,
            protocol::WaitRequest {
                selector: 999,
                options: protocol::WAIT_NOHANG,
            },
            &mut filesystem,
            &mut processes,
        ),
        Err(protocol::STATUS_ECHILD)
    );
}

fn send_signal(
    service: &mut PosixService,
    sender: PeerIdentity,
    receiver: PeerIdentity,
    signal: u32,
) {
    let mut send = [0u8; protocol::SIGNAL_SEND_REQUEST_LEN];
    protocol::encode_signal_send_request(
        protocol::SignalSendRequest {
            selector: receiver.process_id as i64,
            signal,
        },
        &mut send,
    )
    .unwrap();
    assert_eq!(
        service
            .handle(
                sender,
                protocol::Header {
                    opcode: protocol::OP_SIGNAL_SEND,
                    ..protocol::Header::default()
                },
                &send,
            )
            .header
            .status,
        protocol::STATUS_OK
    );
}

fn dequeue_signal(service: &mut PosixService, receiver: PeerIdentity) -> protocol::SignalDelivery {
    let mut mask = [0u8; protocol::SIGNAL_MASK_LEN];
    protocol::encode_signal_mask(0, &mut mask).unwrap();
    let response = service.handle(
        receiver,
        protocol::Header {
            opcode: protocol::OP_SIGNAL_DEQUEUE,
            ..protocol::Header::default()
        },
        &mask,
    );
    assert_eq!(response.header.status, protocol::STATUS_OK);
    protocol::decode_signal_delivery(&response.payload).unwrap()
}

fn deliver_signal(
    service: &mut PosixService,
    sender: PeerIdentity,
    receiver: PeerIdentity,
    signal: u32,
) -> protocol::SignalDelivery {
    send_signal(service, sender, receiver, signal);
    dequeue_signal(service, receiver)
}

#[test]
fn wait_reports_authenticated_stop_and_continue_transitions_once() {
    let parent = PeerIdentity {
        process_id: 124,
        effective_uid: 505,
        effective_gid: 24,
    };
    let child = PeerIdentity {
        process_id: 125,
        ..parent
    };
    let mut service = service_for(parent);
    service.handle(
        parent,
        protocol::Header {
            opcode: protocol::OP_SESSION_REGISTER,
            ..protocol::Header::default()
        },
        &[],
    );
    let mut filesystem = RecordingFilesystem::default();
    service
        .adopt_child(
            parent,
            AuthenticatedProcess {
                handle: 64,
                process_id: child.process_id,
            },
            &mut filesystem,
        )
        .unwrap();
    let mut processes = RecordingProcesses::default();
    processes.states.insert(64, ProcessLifecycle::Running);
    let no_state_options = protocol::WaitRequest {
        selector: child.process_id as i64,
        options: protocol::WAIT_NOHANG,
    };

    let delivery = deliver_signal(&mut service, parent, child, protocol::SIGNAL_TSTP);
    assert_ne!(delivery.token, 0);
    let mut delivery_bytes = [0u8; protocol::SIGNAL_DELIVERY_LEN];
    protocol::encode_signal_delivery(delivery, &mut delivery_bytes).unwrap();
    send_signal(&mut service, parent, child, protocol::SIGNAL_CONT);
    assert_eq!(
        service.report_process_stopped(child, &delivery_bytes, &mut processes),
        Err(protocol::STATUS_EAGAIN)
    );
    assert!(processes.suspended.is_empty());
    assert_eq!(
        service
            .wait_child(
                parent,
                protocol::WaitRequest {
                    options: protocol::WAIT_NOHANG | protocol::WAIT_CONTINUED,
                    ..no_state_options
                },
                &mut filesystem,
                &mut processes,
            )
            .unwrap(),
        protocol::WaitResult::default()
    );

    let delivery = deliver_signal(&mut service, parent, child, protocol::SIGNAL_TSTP);
    protocol::encode_signal_delivery(delivery, &mut delivery_bytes).unwrap();
    processes.suspend_error = Some(-5);
    assert_eq!(
        service.report_process_stopped(child, &delivery_bytes, &mut processes),
        Err(-5)
    );
    assert!(processes.suspended.is_empty());
    assert_eq!(
        service
            .wait_child(
                parent,
                protocol::WaitRequest {
                    options: protocol::WAIT_NOHANG | protocol::WAIT_UNTRACED,
                    ..no_state_options
                },
                &mut filesystem,
                &mut processes,
            )
            .unwrap(),
        protocol::WaitResult::default()
    );
    processes.suspend_error = None;
    let delivery = deliver_signal(&mut service, parent, child, protocol::SIGNAL_TSTP);
    protocol::encode_signal_delivery(delivery, &mut delivery_bytes).unwrap();
    let stopped = service.report_process_stopped(child, &delivery_bytes, &mut processes);
    assert_eq!(stopped, Ok(()));
    assert_eq!(processes.suspended, vec![64]);

    assert_eq!(
        service
            .wait_child(parent, no_state_options, &mut filesystem, &mut processes)
            .unwrap(),
        protocol::WaitResult::default()
    );
    let stopped_result = service
        .wait_child(
            parent,
            protocol::WaitRequest {
                options: protocol::WAIT_UNTRACED,
                ..no_state_options
            },
            &mut filesystem,
            &mut processes,
        )
        .unwrap();
    assert_eq!(stopped_result.process_id, child.process_id);
    assert_eq!(stopped_result.status, (protocol::SIGNAL_TSTP << 8) | 0x7f);
    assert_eq!(
        service
            .wait_child(
                parent,
                protocol::WaitRequest {
                    options: protocol::WAIT_NOHANG | protocol::WAIT_UNTRACED,
                    ..no_state_options
                },
                &mut filesystem,
                &mut processes,
            )
            .unwrap(),
        protocol::WaitResult::default()
    );

    send_signal(&mut service, parent, child, protocol::SIGNAL_CONT);
    let continued = service
        .wait_child(
            parent,
            protocol::WaitRequest {
                options: protocol::WAIT_CONTINUED,
                ..no_state_options
            },
            &mut filesystem,
            &mut processes,
        )
        .unwrap();
    assert_eq!(continued.process_id, child.process_id);
    assert_eq!(continued.status, protocol::WAIT_STATUS_CONTINUED);
    assert_eq!(
        service
            .wait_child(
                parent,
                protocol::WaitRequest {
                    options: protocol::WAIT_NOHANG | protocol::WAIT_CONTINUED,
                    ..no_state_options
                },
                &mut filesystem,
                &mut processes,
            )
            .unwrap(),
        protocol::WaitResult::default()
    );

    let invalid_delivery = protocol::SignalDelivery {
        signal: protocol::SIGNAL_KILL,
        token: 99,
    };
    protocol::encode_signal_delivery(invalid_delivery, &mut delivery_bytes).unwrap();
    assert_eq!(
        service
            .report_process_stopped(child, &delivery_bytes, &mut processes)
            .unwrap_err(),
        STATUS_EINVAL
    );
}

#[test]
fn signal_delivery_tokens_are_scoped_exact_and_single_use() {
    let process = PeerIdentity {
        process_id: 126,
        effective_uid: 505,
        effective_gid: 24,
    };
    let mut service = service_for(process);
    assert_eq!(
        service
            .handle(
                process,
                protocol::Header {
                    opcode: protocol::OP_SESSION_REGISTER,
                    ..protocol::Header::default()
                },
                &[],
            )
            .header
            .status,
        protocol::STATUS_OK
    );

    let delivery = deliver_signal(&mut service, process, process, protocol::SIGNAL_HUP);
    assert_ne!(delivery.token, 0);
    let second = deliver_signal(&mut service, process, process, protocol::SIGNAL_INT);
    assert_ne!(second.token, 0);
    assert_ne!(delivery.token, second.token);
    let mut encoded = [0u8; protocol::SIGNAL_DELIVERY_LEN];
    protocol::encode_signal_delivery(
        protocol::SignalDelivery {
            signal: second.signal,
            token: delivery.token,
        },
        &mut encoded,
    )
    .unwrap();
    assert_eq!(
        service.complete_signal_delivery(process, &encoded),
        Err(protocol::STATUS_EAGAIN)
    );

    protocol::encode_signal_delivery(second, &mut encoded).unwrap();
    assert_eq!(service.complete_signal_delivery(process, &encoded), Ok(()));
    protocol::encode_signal_delivery(delivery, &mut encoded).unwrap();
    assert_eq!(service.complete_signal_delivery(process, &encoded), Ok(()));
    assert_eq!(
        service.complete_signal_delivery(process, &encoded),
        Err(protocol::STATUS_EAGAIN)
    );
}

#[test]
fn outstanding_signal_deliveries_are_bounded_without_losing_pending_state() {
    let process = PeerIdentity {
        process_id: 1260,
        effective_uid: 505,
        effective_gid: 24,
    };
    let mut service = service_for(process);
    service.handle(
        process,
        protocol::Header {
            opcode: protocol::OP_SESSION_REGISTER,
            ..protocol::Header::default()
        },
        &[],
    );
    let mut deliveries = Vec::new();
    for _ in 0..protocol::SIGNAL_MAX {
        deliveries.push(deliver_signal(
            &mut service,
            process,
            process,
            protocol::SIGNAL_HUP,
        ));
    }

    send_signal(&mut service, process, process, protocol::SIGNAL_INT);
    let mut mask = [0u8; protocol::SIGNAL_MASK_LEN];
    protocol::encode_signal_mask(0, &mut mask).unwrap();
    let response = service.handle(
        process,
        protocol::Header {
            opcode: protocol::OP_SIGNAL_DEQUEUE,
            ..protocol::Header::default()
        },
        &mask,
    );
    assert_eq!(response.header.status, protocol::STATUS_EAGAIN);

    let mut encoded = [0u8; protocol::SIGNAL_DELIVERY_LEN];
    protocol::encode_signal_delivery(deliveries[0], &mut encoded).unwrap();
    service
        .complete_signal_delivery(process, &encoded)
        .unwrap();
    let delivery = dequeue_signal(&mut service, process);
    assert_eq!(delivery.signal, protocol::SIGNAL_INT);
    assert_ne!(delivery.token, 0);
}

#[test]
fn wait_reports_default_signal_termination_without_faking_normal_exit() {
    let parent = PeerIdentity {
        process_id: 127,
        effective_uid: 505,
        effective_gid: 24,
    };
    let child = PeerIdentity {
        process_id: 128,
        ..parent
    };
    let mut service = service_for(parent);
    service.handle(
        parent,
        protocol::Header {
            opcode: protocol::OP_SESSION_REGISTER,
            ..protocol::Header::default()
        },
        &[],
    );
    let mut filesystem = RecordingFilesystem::default();
    service
        .adopt_child(
            parent,
            AuthenticatedProcess {
                handle: 65,
                process_id: child.process_id,
            },
            &mut filesystem,
        )
        .unwrap();
    let mut processes = RecordingProcesses::default();
    processes.states.insert(65, ProcessLifecycle::Running);

    let delivery = deliver_signal(&mut service, parent, child, 15);
    let mut encoded = [0u8; protocol::SIGNAL_DELIVERY_LEN];
    protocol::encode_signal_delivery(delivery, &mut encoded).unwrap();
    assert_eq!(
        service.report_process_signaled(child, &encoded, &mut processes),
        Ok(())
    );
    assert_eq!(processes.terminated, vec![(65, 143)]);

    let waited = service
        .wait_child(
            parent,
            protocol::WaitRequest {
                selector: child.process_id as i64,
                options: 0,
            },
            &mut filesystem,
            &mut processes,
        )
        .unwrap();
    assert_eq!(waited.process_id, child.process_id);
    assert_eq!(waited.status, 15);
    assert_eq!(processes.released, vec![65]);
}

#[test]
fn failed_native_termination_does_not_publish_signaled_wait_state() {
    let parent = PeerIdentity {
        process_id: 129,
        effective_uid: 505,
        effective_gid: 24,
    };
    let child = PeerIdentity {
        process_id: 130,
        ..parent
    };
    let mut service = service_for(parent);
    service.handle(
        parent,
        protocol::Header {
            opcode: protocol::OP_SESSION_REGISTER,
            ..protocol::Header::default()
        },
        &[],
    );
    let mut filesystem = RecordingFilesystem::default();
    service
        .adopt_child(
            parent,
            AuthenticatedProcess {
                handle: 66,
                process_id: child.process_id,
            },
            &mut filesystem,
        )
        .unwrap();
    let mut processes = RecordingProcesses::default();
    processes.states.insert(66, ProcessLifecycle::Running);
    processes.terminate_error = Some(-5);

    let delivery = deliver_signal(&mut service, parent, child, 15);
    let mut encoded = [0u8; protocol::SIGNAL_DELIVERY_LEN];
    protocol::encode_signal_delivery(delivery, &mut encoded).unwrap();
    assert_eq!(
        service.report_process_signaled(child, &encoded, &mut processes),
        Err(-5)
    );
    assert!(processes.terminated.is_empty());

    processes.terminate_error = None;
    processes
        .states
        .insert(66, ProcessLifecycle::Exited { exit_code: 143 });
    let waited = service
        .wait_child(
            parent,
            protocol::WaitRequest {
                selector: child.process_id as i64,
                options: 0,
            },
            &mut filesystem,
            &mut processes,
        )
        .unwrap();
    assert_eq!(waited.status, 143 << 8);
}

#[test]
fn wait_option_values_match_the_newlib_target_abi() {
    assert_eq!(protocol::SIGNAL_DELIVERY_LEN, 16);
    assert_eq!(protocol::OP_SIGNAL_DELIVERY_COMPLETE, 51);
    assert_eq!(protocol::OP_PROCESS_SIGNALED, 52);
    assert_eq!(protocol::WAIT_NOHANG, 1);
    assert_eq!(protocol::WAIT_UNTRACED, 2);
    assert_eq!(protocol::WAIT_CONTINUED, 8);
    assert_eq!(protocol::WAIT_STATUS_CONTINUED, 0xffff);

    let newlib = include_str!("../../../libraries/newlib/newlib/libc/include/sys/wait.h");
    for definition in [
        "#define WNOHANG 1",
        "#define WUNTRACED 2",
        "#define WCONTINUED 8",
        "#define WIFCONTINUED(w)\t((w) == 0xffff)",
    ] {
        assert!(newlib.contains(definition), "missing {definition}");
    }
}

#[test]
fn process_groups_and_sessions_are_managed_by_posix_state() {
    let parent = PeerIdentity {
        process_id: 131,
        effective_uid: 505,
        effective_gid: 24,
    };
    let child = PeerIdentity {
        process_id: 132,
        effective_uid: 505,
        effective_gid: 24,
    };
    let mut service = service_for(parent);
    service.handle(
        parent,
        protocol::Header {
            opcode: protocol::OP_SESSION_REGISTER,
            ..protocol::Header::default()
        },
        &[],
    );
    let mut filesystem = RecordingFilesystem::default();
    service
        .adopt_child(
            parent,
            AuthenticatedProcess {
                handle: 72,
                process_id: child.process_id,
            },
            &mut filesystem,
        )
        .unwrap();

    let mut id_request = [0u8; protocol::PROCESS_ID_REQUEST_LEN];
    protocol::encode_process_id_request(0, &mut id_request).unwrap();
    let response = service.handle(
        child,
        protocol::Header {
            opcode: protocol::OP_PROCESS_INFO,
            ..protocol::Header::default()
        },
        &id_request,
    );
    let info = protocol::decode_process_info(&response.payload).unwrap();
    assert_eq!(info.process_id, 132);
    assert_eq!(info.parent_id, 131);
    assert_eq!(info.process_group_id, 131);
    assert_eq!(info.session_id, 131);

    let response = service.handle(
        child,
        protocol::Header {
            opcode: protocol::OP_CREATE_SESSION,
            ..protocol::Header::default()
        },
        &[],
    );
    assert_eq!(response.header.status, protocol::STATUS_OK);
    let info = protocol::decode_process_info(&response.payload).unwrap();
    assert_eq!(info.process_group_id, 132);
    assert_eq!(info.session_id, 132);

    let mut group_request = [0u8; protocol::PROCESS_GROUP_REQUEST_LEN];
    protocol::encode_process_group_request(0, 0, &mut group_request).unwrap();
    assert_eq!(
        service
            .handle(
                child,
                protocol::Header {
                    opcode: protocol::OP_SET_PROCESS_GROUP,
                    ..protocol::Header::default()
                },
                &group_request,
            )
            .header
            .status,
        protocol::STATUS_EPERM
    );
}

#[test]
fn controlling_terminals_are_bound_to_sessions_and_foreground_groups() {
    let leader = PeerIdentity {
        process_id: 141,
        effective_uid: 505,
        effective_gid: 24,
    };
    let member = PeerIdentity {
        process_id: 142,
        effective_uid: 505,
        effective_gid: 24,
    };
    let other_leader = PeerIdentity {
        process_id: 143,
        effective_uid: 505,
        effective_gid: 24,
    };
    let mut service = service_for(leader);
    service.handle(
        leader,
        protocol::Header {
            opcode: protocol::OP_SESSION_REGISTER,
            ..protocol::Header::default()
        },
        &[],
    );
    let mut filesystem = RecordingFilesystem::default();
    for process in [member, other_leader] {
        service
            .adopt_child(
                leader,
                AuthenticatedProcess {
                    handle: process.process_id as u32,
                    process_id: process.process_id,
                },
                &mut filesystem,
            )
            .unwrap();
    }

    let terminal_request = |opcode| protocol::Header {
        opcode,
        request_id: 41,
        ..protocol::Header::default()
    };
    assert_eq!(
        service
            .handle_terminal(
                leader,
                terminal_request(protocol::OP_TERMINAL_ACQUIRE),
                &[],
                77,
            )
            .header
            .status,
        protocol::STATUS_OK
    );
    assert_eq!(
        service.controlling_terminal(77),
        Some(posix_service::ControllingTerminal {
            session_id: 141,
            foreground_process_group: 141,
        })
    );
    assert_eq!(
        service
            .handle_terminal(
                member,
                terminal_request(protocol::OP_TERMINAL_ACQUIRE),
                &[],
                78,
            )
            .header
            .status,
        protocol::STATUS_EPERM
    );

    let mut group_request = [0u8; protocol::PROCESS_GROUP_REQUEST_LEN];
    protocol::encode_process_group_request(142, 142, &mut group_request).unwrap();
    assert_eq!(
        service
            .handle(
                leader,
                protocol::Header {
                    opcode: protocol::OP_SET_PROCESS_GROUP,
                    ..protocol::Header::default()
                },
                &group_request,
            )
            .header
            .status,
        protocol::STATUS_OK
    );
    let mut foreground = [0u8; protocol::PROCESS_ID_REQUEST_LEN];
    protocol::encode_process_id_request(142, &mut foreground).unwrap();
    assert_eq!(
        service
            .handle_terminal(
                member,
                terminal_request(protocol::OP_TERMINAL_SET_FOREGROUND),
                &foreground,
                77,
            )
            .header
            .status,
        protocol::STATUS_OK
    );
    let response = service.handle_terminal(
        leader,
        terminal_request(protocol::OP_TERMINAL_GET_FOREGROUND),
        &[],
        77,
    );
    assert_eq!(response.header.status, protocol::STATUS_OK);
    assert_eq!(
        protocol::decode_process_id_request(&response.payload),
        Ok(142)
    );
    assert_eq!(
        service.signal_terminal_foreground_group(77, protocol::SIGNAL_TSTP),
        Ok(1)
    );
    assert_eq!(
        service.signal_state(leader.process_id).unwrap().pending(),
        0
    );
    assert_eq!(
        service.signal_state(member.process_id).unwrap().pending(),
        1u64 << (protocol::SIGNAL_TSTP - 1)
    );
    assert_eq!(
        service.signal_notification_processes().collect::<Vec<_>>(),
        vec![member.process_id]
    );
    assert_eq!(
        service.signal_terminal_foreground_group(999, protocol::SIGNAL_INT),
        Err(protocol::STATUS_ENOTTY)
    );

    let response = service.handle(
        other_leader,
        protocol::Header {
            opcode: protocol::OP_CREATE_SESSION,
            ..protocol::Header::default()
        },
        &[],
    );
    assert_eq!(response.header.status, protocol::STATUS_OK);
    assert_eq!(
        service
            .handle_terminal(
                other_leader,
                terminal_request(protocol::OP_TERMINAL_GET_FOREGROUND),
                &[],
                77,
            )
            .header
            .status,
        protocol::STATUS_ENOTTY
    );
    assert_eq!(
        service
            .handle_terminal(
                other_leader,
                terminal_request(protocol::OP_TERMINAL_ACQUIRE),
                &[],
                77,
            )
            .header
            .status,
        protocol::STATUS_EPERM
    );
    assert_eq!(
        service
            .handle_terminal(
                member,
                terminal_request(protocol::OP_TERMINAL_RELEASE),
                &[],
                77,
            )
            .header
            .status,
        protocol::STATUS_ENOTTY
    );
    assert_eq!(
        service
            .handle_terminal(
                leader,
                terminal_request(protocol::OP_TERMINAL_RELEASE),
                &[],
                77,
            )
            .header
            .status,
        protocol::STATUS_OK
    );
    assert!(service.controlling_terminal(77).is_none());
}

#[test]
fn service_submits_open_as_one_atomic_filesystem_operation() {
    let peer = PeerIdentity {
        process_id: 111,
        effective_uid: 505,
        effective_gid: 24,
    };
    let mut service = service_for(peer);
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
    let mut service = service_for(peer);
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
    let mut service = service_for(peer);
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
    let mut service = service_for(peer);
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
    let mut service = service_for(peer);
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
    let mut service = service_for(peer);
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
    let mut service = service_for(peer);
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
    assert_eq!(
        protocol::decode_rename_at(&encoded[..length]).unwrap(),
        request
    );

    let peer = PeerIdentity {
        process_id: 121,
        effective_uid: 503,
        effective_gid: 22,
    };
    let mut service = service_for(peer);
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
fn link_wire_and_service_preserve_flags_credentials_and_two_directory_handles() {
    let request = protocol::LinkAtRequest {
        old_base: protocol::OpenBase::AttachedDirectory,
        new_base: protocol::OpenBase::AttachedDirectory,
        flags: protocol::LINK_FOLLOW_SOURCE,
        old_path: "old/source",
        new_path: "new/link",
    };
    let mut encoded = [0; protocol::LINK_AT_HEADER_LEN + protocol::MAX_PATH_LEN * 2];
    let length = protocol::encode_link_at(request, &mut encoded).unwrap();
    assert_eq!(
        protocol::decode_link_at(&encoded[..length]).unwrap(),
        request
    );
    let mut invalid = encoded[..length].to_vec();
    invalid[4..8].copy_from_slice(&(protocol::LINK_FLAGS_ALL << 1).to_le_bytes());
    assert!(protocol::decode_link_at(&invalid).is_err());

    let peer = PeerIdentity {
        process_id: 126,
        effective_uid: 0,
        effective_gid: 23,
    };
    let mut service = service_for(peer);
    service.handle(
        peer,
        protocol::Header {
            opcode: protocol::OP_SESSION_REGISTER,
            ..protocol::Header::default()
        },
        &[],
    );
    let mut groups = [0u8; protocol::GROUP_LIST_MAX_LEN];
    let groups_len = protocol::encode_group_list(&[42, 84], &mut groups).unwrap();
    assert_eq!(
        service
            .handle(
                peer,
                protocol::Header {
                    opcode: protocol::OP_GROUPS_SET,
                    ..protocol::Header::default()
                },
                &groups[..groups_len],
            )
            .header
            .status,
        protocol::STATUS_OK
    );
    let old_directory = AttachedObject {
        handle: 73,
        rights: 0x81,
    };
    let new_directory = AttachedObject {
        handle: 74,
        rights: 0x81,
    };
    let mut filesystem = RecordingFilesystem::default();
    let result = service.handle_objects(
        peer,
        protocol::Header {
            opcode: protocol::OP_LINK_AT,
            ..protocol::Header::default()
        },
        &encoded[..length],
        &[old_directory, new_directory],
        &mut filesystem,
    );

    assert_eq!(result.response.header.status, protocol::STATUS_OK);
    let prepared = filesystem.link_request.unwrap();
    assert_eq!(prepared.old_path, "old/source");
    assert_eq!(prepared.new_path, "new/link");
    assert_eq!(prepared.flags, protocol::LINK_FOLLOW_SOURCE);
    assert_eq!(prepared.effective_uid, 0);
    assert_eq!(prepared.effective_gid, 23);
    assert_eq!(prepared.supplementary_groups, vec![42, 84]);
    let paths = filesystem.link_paths.unwrap();
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
    let mut service = service_for(peer);
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
    assert_eq!(
        protocol::decode_symlink_at(&encoded[..length]).unwrap(),
        request
    );

    let peer = PeerIdentity {
        process_id: 123,
        effective_uid: 501,
        effective_gid: 20,
    };
    let mut service = service_for(peer);
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
    let mut service = service_for(peer);
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
    let mut service = service_for(peer);
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
    assert_eq!(
        protocol::decode_chown_at(&payload[..length]).unwrap(),
        request
    );

    let peer = PeerIdentity {
        process_id: 126,
        effective_uid: 498,
        effective_gid: 17,
    };
    let mut service = service_for(peer);
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
    let mut service = service_for(peer);
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
    let mut service = service_for(peer);
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
    let request = filesystem.directory_request.as_ref().unwrap();
    assert_eq!(request.path, "work");
    assert_eq!(request.flags, 0);
    assert_eq!(filesystem.directory.unwrap().handle, 101);
    assert_eq!(
        service
            .session_directories(peer.process_id)
            .unwrap()
            .cwd
            .handle,
        200
    );
    assert_eq!(
        filesystem.released,
        vec![AttachedObject {
            handle: 101,
            rights: 0x81
        }]
    );
}

#[test]
fn chroot_replaces_only_the_privileged_sessions_root_handle() {
    let peer = PeerIdentity {
        process_id: 127,
        effective_uid: 0,
        effective_gid: 28,
    };
    let mut service = service_for(peer);
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
            path: "jail",
        },
        &mut payload,
    )
    .unwrap();
    let mut filesystem = RecordingFilesystem::default();

    let result = service.handle_objects(
        peer,
        protocol::Header {
            opcode: protocol::OP_CHROOT_AT,
            request_id: 20,
            payload_len: length as u32,
            ..protocol::Header::default()
        },
        &payload[..length],
        &[],
        &mut filesystem,
    );

    assert_eq!(result.response.header.status, protocol::STATUS_OK);
    let request = filesystem.directory_request.as_ref().unwrap();
    assert_eq!(request.path, "jail");
    assert_eq!(request.flags, 0);
    assert_eq!(filesystem.root.unwrap().handle, 100);
    assert_eq!(filesystem.directory.unwrap().handle, 101);
    let directories = service.session_directories(peer.process_id).unwrap();
    assert_eq!(directories.root.handle, 200);
    assert_eq!(directories.cwd.handle, 101);
    assert_eq!(
        filesystem.released,
        vec![AttachedObject {
            handle: 100,
            rights: 0x81
        }]
    );

    let getcwd = service.handle_objects(
        peer,
        protocol::Header {
            opcode: protocol::OP_GETCWD,
            request_id: 21,
            ..protocol::Header::default()
        },
        &[],
        &[],
        &mut filesystem,
    );
    assert_eq!(getcwd.response.header.status, protocol::STATUS_OK);
    assert_eq!(
        filesystem.path_query,
        Some((
            AttachedObject {
                handle: 200,
                rights: 0x81
            },
            AttachedObject {
                handle: 101,
                rights: 0x81
            }
        ))
    );
}

#[test]
fn chroot_rejects_an_unprivileged_session_before_resolving_the_path() {
    let peer = PeerIdentity {
        process_id: 128,
        effective_uid: 501,
        effective_gid: 28,
    };
    let mut service = service_for(peer);
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
            path: "jail",
        },
        &mut payload,
    )
    .unwrap();
    let mut filesystem = RecordingFilesystem::default();

    let result = service.handle_objects(
        peer,
        protocol::Header {
            opcode: protocol::OP_CHROOT_AT,
            request_id: 22,
            payload_len: length as u32,
            ..protocol::Header::default()
        },
        &payload[..length],
        &[],
        &mut filesystem,
    );

    assert_eq!(result.response.header.status, protocol::STATUS_EPERM);
    assert!(filesystem.directory_request.is_none());
    assert_eq!(filesystem.roots_opened, 1);
    assert!(filesystem.released.is_empty());
}

#[test]
fn getcwd_resolves_the_live_root_and_cwd_handles() {
    let peer = PeerIdentity {
        process_id: 117,
        effective_uid: 511,
        effective_gid: 30,
    };
    let mut service = service_for(peer);
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
    let mut service = service_for(peer);
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
    assert_eq!(
        service
            .session_directories(peer.process_id)
            .unwrap()
            .cwd
            .handle,
        1058
    );
    assert_eq!(
        filesystem.released,
        vec![AttachedObject {
            handle: 101,
            rights: 0x81
        }]
    );

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
    assert_eq!(
        service
            .session_directories(peer.process_id)
            .unwrap()
            .cwd
            .handle,
        1058
    );
}

#[test]
fn terminal_flush_wire_format_is_fixed_and_rejects_unknown_flags() {
    let mut encoded = [0u8; protocol::TERMINAL_FLUSH_LEN];
    protocol::encode_terminal_flush(protocol::TERMINAL_FLUSH_ALL, &mut encoded).unwrap();
    assert_eq!(encoded, protocol::TERMINAL_FLUSH_ALL.to_le_bytes());
    assert_eq!(
        protocol::decode_terminal_flush(&encoded),
        Ok(protocol::TERMINAL_FLUSH_ALL)
    );
    assert_eq!(
        protocol::encode_terminal_flush(0, &mut encoded),
        Err(protocol::ProtocolError::InvalidLength)
    );
    assert_eq!(
        protocol::encode_terminal_flush(1 << 31, &mut encoded),
        Err(protocol::ProtocolError::InvalidLength)
    );
    assert_eq!(
        protocol::decode_terminal_flush(&[1, 0, 0, 0, 0]),
        Err(protocol::ProtocolError::InvalidLength)
    );
}
