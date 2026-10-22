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

#[path = "support/child_cpu_state.rs"]
mod child_cpu_state;

#[path = "support/orphan_group_transition.rs"]
mod orphan_group_transition;

#[path = "support/process_group_image.rs"]
mod process_group_image;

#[path = "support/image_credentials.rs"]
mod image_credentials;

#[path = "support/image_signal_state.rs"]
mod image_signal_state;

#[path = "support/fork_image_state.rs"]
mod fork_image_state;

#[path = "support/child_exit_image.rs"]
mod child_exit_image;

#[path = "support/child_stop_image.rs"]
mod child_stop_image;

#[path = "support/child_continue_image.rs"]
mod child_continue_image;

#[path = "support/request_image.rs"]
mod request_image;

#[path = "support/alarm.rs"]
mod alarm;

#[path = "support/wait_observation.rs"]
mod wait_observation;

#[path = "support/wait_selection.rs"]
mod wait_selection;

#[path = "support/wait_info.rs"]
mod wait_info;

#[path = "support/cpu_limit.rs"]
mod cpu_limit;

#[path = "support/cpu_timer.rs"]
mod cpu_timer;

#[path = "support/child_signal_info.rs"]
mod child_signal_info;

#[path = "support/default_ignored_signals.rs"]
mod default_ignored_signals;

#[path = "support/metadata_admission.rs"]
mod metadata_admission;

#[path = "support/fork_process_limit.rs"]
mod fork_process_limit;

#[path = "support/canonical_path_protocol.rs"]
mod canonical_path_protocol;

#[path = "support/byte_path_protocol.rs"]
mod byte_path_protocol;

#[path = "support/file_time_protocol.rs"]
mod file_time_protocol;

struct LocalTransport {
    service: RefCell<PosixService>,
    peer: PeerIdentity,
}

#[test]
fn real_effective_updates_are_atomic_and_use_stored_not_peer_credentials() {
    let client = client(PeerIdentity {
        process_id: 198,
        effective_uid: 0,
        effective_gid: 0,
    });
    client.register_session().unwrap();
    client.set_groups(&[20, 42]).unwrap();
    client.set_real_effective_gid(20, 42).unwrap();
    client.set_real_effective_uid(501, 502).unwrap();
    let unchanged = protocol::CREDENTIAL_ID_UNCHANGED;
    // The transport still reports UID zero: only stored POSIX state authorizes.
    let before = client.session_info().unwrap();
    assert_eq!(
        client.set_real_effective_uid(502, 777),
        Err(ClientError::Remote(protocol::STATUS_EPERM))
    );
    assert_eq!(client.session_info().unwrap(), before);
    assert_eq!(
        client.set_real_effective_gid(42, 777),
        Err(ClientError::Remote(protocol::STATUS_EPERM))
    );
    assert_eq!(client.session_info().unwrap(), before);
    client.set_real_effective_uid(unchanged, 501).unwrap();
    client.set_real_effective_uid(unchanged, 502).unwrap();
    client.set_real_effective_uid(502, 501).unwrap();
    let state = client.session_info().unwrap();
    assert_eq!((state.real_uid, state.effective_uid), (502, 501));
    client.set_real_effective_uid(unchanged, unchanged).unwrap();
    client.set_real_effective_gid(42, 20).unwrap();
    assert_eq!(client.session_info().unwrap().effective_gid, 20);
    let mut groups = [0; 4];
    assert_eq!(client.get_groups(&mut groups).unwrap(), 2);
    assert_eq!(&groups[..2], &[20, 42]);
    let transport = client.into_transport();
    let service = transport.service.borrow();
    let stored = service.session(198).unwrap();
    assert_eq!(
        (stored.real_uid, stored.effective_uid, stored.saved_uid),
        (502, 501, 501)
    );
    assert_eq!(
        (stored.real_gid, stored.effective_gid, stored.saved_gid),
        (42, 20, 20)
    );
}

#[test]
fn effective_id_noop_preserves_saved_ids_and_does_not_authorize_other_ids() {
    let client = client(PeerIdentity {
        process_id: 202,
        effective_uid: 0,
        effective_gid: 0,
    });
    client.register_session().unwrap();
    client.set_effective_gid(42).unwrap();
    client.set_effective_uid(501).unwrap();
    let before = client.session_info().unwrap();
    client.set_effective_uid(501).unwrap();
    client.set_effective_gid(42).unwrap();
    assert_eq!(client.session_info().unwrap(), before);
    assert_eq!(
        client.set_effective_uid(502),
        Err(ClientError::Remote(protocol::STATUS_EPERM))
    );
    assert_eq!(
        client.set_effective_gid(43),
        Err(ClientError::Remote(protocol::STATUS_EPERM))
    );
    assert_eq!(client.session_info().unwrap(), before);
    {
        let service = client.transport().service.borrow();
        let stored = service.session(202).unwrap();
        assert_eq!(stored.saved_uid, 0);
        assert_eq!(stored.saved_gid, 0);
    }
    // Temporary effective-ID changes must not destroy the restoration path.
    client.set_effective_uid(0).unwrap();
    client.set_effective_gid(0).unwrap();
    assert_eq!(client.session_info().unwrap().effective_uid, 0);
    assert_eq!(client.session_info().unwrap().effective_gid, 0);
}

#[test]
fn explicitly_setting_real_id_drops_saved_privilege_even_when_real_is_unchanged() {
    let client = client(PeerIdentity {
        process_id: 199,
        effective_uid: 0,
        effective_gid: 0,
    });
    client.register_session().unwrap();
    let unchanged = protocol::CREDENTIAL_ID_UNCHANGED;
    client.set_effective_gid(42).unwrap();
    client.set_real_effective_gid(unchanged, 42).unwrap();
    client.set_real_effective_gid(0, unchanged).unwrap();
    client.set_effective_uid(501).unwrap();
    client.set_real_effective_uid(unchanged, 501).unwrap();
    client.set_real_effective_uid(0, unchanged).unwrap();
    // Effective-only no-op is permitted even when it differs from real/saved.
    client.set_real_effective_uid(unchanged, 501).unwrap();
    let transport = client.into_transport();
    let service = transport.service.borrow();
    let stored = service.session(199).unwrap();
    assert_eq!(stored.saved_uid, 501);
    assert_eq!(stored.saved_gid, 42);
}

#[test]
fn real_id_effective_update_preserves_saved_id_until_explicit_permanent_drop() {
    let client = client(PeerIdentity {
        process_id: 201,
        effective_uid: 0,
        effective_gid: 0,
    });
    client.register_session().unwrap();
    client.set_real_effective_gid(20, 42).unwrap();
    client.set_real_effective_uid(501, 502).unwrap();
    let unchanged = protocol::CREDENTIAL_ID_UNCHANGED;
    client.set_real_effective_uid(unchanged, 501).unwrap();
    client.set_real_effective_gid(unchanged, 20).unwrap();
    client.set_real_effective_uid(unchanged, unchanged).unwrap();
    client.set_real_effective_gid(unchanged, unchanged).unwrap();
    {
        let service = client.transport().service.borrow();
        let stored = service.session(201).unwrap();
        assert_eq!(stored.saved_uid, 502);
        assert_eq!(stored.saved_gid, 42);
    }
    client.set_real_effective_uid(unchanged, 502).unwrap();
    client.set_real_effective_gid(unchanged, 42).unwrap();
    client.set_real_effective_gid(20, 20).unwrap();
    client.set_real_effective_uid(501, 501).unwrap();
    assert_eq!(
        client.set_real_effective_uid(unchanged, 502),
        Err(ClientError::Remote(protocol::STATUS_EPERM))
    );
    assert_eq!(
        client.set_real_effective_gid(unchanged, 42),
        Err(ClientError::Remote(protocol::STATUS_EPERM))
    );
}

#[test]
fn credential_pair_wire_is_exact_and_malformed_requests_do_not_change_state() {
    let mut bytes = [0; protocol::CREDENTIAL_PAIR_PAYLOAD_LEN];
    protocol::encode_credential_pair(501, u32::MAX, &mut bytes).unwrap();
    assert_eq!(bytes, [245, 1, 0, 0, 255, 255, 255, 255]);
    assert_eq!(
        protocol::decode_credential_pair(&bytes),
        Ok((501, u32::MAX))
    );
    assert!(protocol::encode_credential_pair(1, 2, &mut bytes[..7]).is_err());
    let peer = PeerIdentity {
        process_id: 200,
        effective_uid: 501,
        effective_gid: 20,
    };
    let mut service = service_for(peer);
    service.handle(
        peer,
        protocol::Header {
            opcode: protocol::OP_SESSION_REGISTER,
            ..Default::default()
        },
        &[],
    );
    let before = *service.session(200).unwrap();
    for opcode in [
        protocol::OP_SET_REAL_EFFECTIVE_UID,
        protocol::OP_SET_REAL_EFFECTIVE_GID,
    ] {
        for payload in [&bytes[..7], &[0; 9][..]] {
            assert_eq!(
                service
                    .handle(
                        peer,
                        protocol::Header {
                            opcode,
                            ..Default::default()
                        },
                        payload
                    )
                    .header
                    .status,
                STATUS_EINVAL
            );
            assert_eq!(*service.session(200).unwrap(), before);
        }
        assert_eq!(
            service
                .handle(
                    peer,
                    protocol::Header {
                        opcode,
                        flags: 1,
                        ..Default::default()
                    },
                    &bytes
                )
                .header
                .status,
            STATUS_EINVAL
        );
        assert_eq!(*service.session(200).unwrap(), before);
    }
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

fn terminal_identity(peer: PeerIdentity) -> mnu_abi::ExecutionIdentity {
    mnu_abi::ExecutionIdentity {
        process_id: peer.process_id,
        thread_id: 1,
    }
}

fn service_for(peer: PeerIdentity) -> PosixService {
    let mut service = PosixService::new();
    assert_eq!(
        service.initialize_bootstrap_process(
            AuthenticatedProcess {
                handle: u32::try_from(peer.process_id).unwrap(),
                process_id: peer.process_id,
            },
            peer.effective_uid,
            peer.effective_gid,
            &[],
        ),
        Ok(())
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
    let initialized = client.session_info().unwrap();

    client.register_session().unwrap();
    let initial = client.session_info().unwrap();
    assert_eq!(initial, initialized);
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
        privileged.get_groups(&mut groups).unwrap(),
        0
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
            path: b"child",
        },
        &mut bytes,
    )
    .unwrap();
    assert_eq!(
        protocol::decode_stat_at(&bytes[..length]).unwrap(),
        protocol::StatAtRequest {
            base: protocol::OpenBase::AttachedDirectory,
            flags: protocol::STAT_NOFOLLOW,
            path: b"child",
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
            path: b"child",
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
    assert_eq!(decoded.path, b"child");
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
            path: path.as_bytes(),
        },
        &mut payload,
    )
    .unwrap();
    assert!(protocol::HEADER_LEN + payload_len <= protocol::CONTROL_MESSAGE_LEN);

    let rename_len = protocol::encode_rename_at(
        protocol::RenameAtRequest {
            old_base: protocol::OpenBase::ProcessCwd,
            new_base: protocol::OpenBase::ProcessCwd,
            old_path: path.as_bytes(),
            new_path: path.as_bytes(),
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

    fn close_received_handle(&self, _: u32) {
        panic!("unexpected owned reply Handle in this fixture");
    }

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

    fn close_received_handle(&self, _: u32) {
        panic!("unexpected owned reply Handle in this fixture");
    }

    fn call_with_handles(
        &self,
        request: &[u8],
        response: &mut [u8],
        handles: &mut ObjectHandles<Self::Handle>,
    ) -> Result<usize, Self::Error> {
        let (header, payload) = protocol::decode(request).map_err(|_| ())?;
        if header.opcode == protocol::OP_FORK_COMMIT {
            assert_eq!(protocol::fork::decode_token(payload), Ok(77));
        } else {
            assert_eq!(header.opcode, protocol::OP_PROCESS_SPAWNED);
            let mut groups = [0; protocol::MAX_SUPPLEMENTARY_GROUPS];
            assert_eq!(
                protocol::decode_spawn_credentials(payload, &mut groups),
                Ok((505, 24, 2))
            );
            assert_eq!(&groups[..2], &[10, 20]);
        }
        assert_eq!(handles.len(), 1);
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
        .commit_fork(
            77,
            ObjectHandleAttachment {
                handle: 52,
                rights: mnu_abi::HANDLE_RIGHT_WAIT | mnu_abi::HANDLE_RIGHT_SIGNAL,
            },
        )
        .unwrap();
    Client::new(ChildRegistrationTransport)
        .register_spawned_child(
            ObjectHandleAttachment {
                handle: 52,
                rights: mnu_abi::HANDLE_RIGHT_WAIT | mnu_abi::HANDLE_RIGHT_SIGNAL,
            },
            505,
            24,
            &[10, 20],
        )
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
            path: b"child.txt",
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
    assert_eq!(decoded.path, b"child.txt");

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
            path: b"notes.txt",
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
    assert_eq!(open.path, b"notes.txt");
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
            path: b"notes.txt",
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

    fn close_received_handle(&self, _: u32) {
        panic!("unexpected owned reply Handle in this fixture");
    }

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
        assert_eq!(open.path, b"document.txt");
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

    fn close_received_handle(&self, _: u32) {
        panic!("unexpected owned reply Handle in this fixture");
    }

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
                assert_eq!(request.path, b"child");
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
    admission_calls: Vec<(u16, Option<AttachedObject<u32>>)>,
    admission_response: Option<Result<OpenedObject<u32>, i32>>,
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
    truncate_ceiling: Option<u64>,
    chmod_file: Option<(AttachedObject<u32>, u32, u32, u32)>,
    chown_file: Option<(AttachedObject<u32>, u32, u32, u32, u32)>,
    time_file: Option<(AttachedObject<u32>, protocol::file_time::Update, u32, u32, Vec<u32>)>,
    time_request: Option<posix_service::PreparedFileTimes>,
    time_error: Option<i32>,
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
    retain_failure_at: Option<usize>,
    released: Vec<AttachedObject<u32>>,
    path_query: Option<(AttachedObject<u32>, AttachedObject<u32>)>,
    directory_path: Vec<u8>,
}

impl RecordingFilesystem {
    fn admit(
        &mut self,
        opcode: u16,
        ticket: Option<AttachedObject<u32>>,
    ) -> Result<(), posix_service::MutationError<u32>> {
        self.admission_calls.push((opcode, ticket));
        match self.admission_response {
            Some(Ok(ticket)) => Err(posix_service::MutationError::Wait(ticket)),
            Some(Err(status)) => Err(posix_service::MutationError::Failed(status)),
            None => Ok(()),
        }
    }
}

#[derive(Default)]
struct RecordingProcesses {
    states: BTreeMap<u32, ProcessLifecycle>,
    images: BTreeMap<u32, Result<mnu_abi::ProcessStatus, i32>>,
    image_script: BTreeMap<u32, std::collections::VecDeque<Result<mnu_abi::ProcessStatus, i32>>>,
    identities: BTreeMap<u32, u64>,
    image_reads: Vec<u32>,
    usage: BTreeMap<u32, Result<mnu_abi::ProcessExecutionUsage, i32>>,
    suspend_error: Option<i32>,
    terminate_error: Option<i32>,
    terminate_failure: Option<(u32, i32)>,
    termination_pending: bool,
    suspended: Vec<u32>,
    terminated: Vec<(u32, u64)>,
    released: Vec<u32>,
}

impl ProcessBackend<u32> for RecordingProcesses {
    fn image_status(&mut self, process: u32) -> Result<mnu_abi::ProcessStatus, i32> {
        self.image_reads.push(process);
        if let Some(image) = self
            .image_script
            .get_mut(&process)
            .and_then(|script| script.pop_front())
        {
            return image;
        }
        self.images.get(&process).copied().unwrap_or_else(|| {
            // Policy fixtures normally assign selectors equal to their native
            // PID and keep unscripted actors alive. Nonidentity selectors and
            // observation faults are modeled explicitly, independently of the
            // lifecycle-query script in `states`.
            Ok(mnu_abi::ProcessStatus {
                process_id: self
                    .identities
                    .get(&process)
                    .copied()
                    .unwrap_or(u64::from(process)),
                state: match self.states.get(&process) {
                    Some(ProcessLifecycle::Exited { .. }) => mnu_abi::PROCESS_STATE_EXITED,
                    _ => mnu_abi::PROCESS_STATE_RUNNING,
                },
                ..Default::default()
            })
        })
    }
    fn execution_usage(&mut self, process: u32) -> Result<mnu_abi::ProcessExecutionUsage, i32> {
        if !self.states.contains_key(&process) {
            return Err(protocol::STATUS_ESRCH);
        }
        // Tests without simulated CPU execution have a zero-valued test clock.
        // Production obtains every sample from the retained native Handle.
        self.usage.get(&process).copied()
            .unwrap_or(Ok(mnu_abi::ProcessExecutionUsage {
                ticks_per_second: 500,
                ..Default::default()
            }))
    }

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
        if let Some((target, error)) = self.terminate_failure {
            if process == target {
                return Err(error);
            }
        }
        if !self.states.contains_key(&process) {
            return Err(-3);
        }
        self.terminated.push((process, exit_code));
        if !self.termination_pending {
            self.states
                .insert(process, ProcessLifecycle::Exited { exit_code });
        }
        Ok(())
    }

    fn release(&mut self, process: u32) {
        self.released.push(process);
    }
}

impl FilesystemBackend<u32> for RecordingFilesystem {
    fn open_at_admitted(
        &mut self,
        request: &PreparedOpen,
        paths: PathObjects<u32>,
        ticket: Option<AttachedObject<u32>>,
    ) -> Result<OpenedObject<u32>, posix_service::MutationError<u32>> {
        self.admit(protocol::OP_OPEN_AT, ticket)?;
        self.open_at(request, paths).map_err(Into::into)
    }

    fn ftruncate_admitted(
        &mut self,
        file: AttachedObject<u32>,
        length: u64,
        ceiling: u64,
        ticket: Option<AttachedObject<u32>>,
    ) -> Result<(), posix_service::MutationError<u32>> {
        self.admit(protocol::OP_FTRUNCATE, ticket)?;
        self.ftruncate(file, length, ceiling).map_err(Into::into)
    }

    fn truncate_at_admitted(
        &mut self,
        request: &posix_service::PreparedTruncate,
        paths: PathObjects<u32>,
        ticket: Option<AttachedObject<u32>>,
    ) -> Result<(), posix_service::MutationError<u32>> {
        self.admit(protocol::OP_TRUNCATE_AT, ticket)?;
        self.truncate_at(request, paths).map_err(Into::into)
    }

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

    fn canonical_path_at(
        &mut self,
        request: &PreparedStat,
        paths: PathObjects<u32>,
    ) -> Result<Vec<u8>, i32> {
        self.stat_request = Some(request.clone());
        self.root = Some(paths.root);
        self.directory = paths.base;
        Ok(b"/resolved/target".to_vec())
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

    fn ftruncate(
        &mut self,
        file: AttachedObject<u32>,
        length: u64,
        growth_ceiling: u64,
    ) -> Result<(), i32> {
        self.truncated = Some((file, length));
        self.truncate_ceiling = Some(growth_ceiling);
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

    fn futimens(
        &mut self,
        file: AttachedObject<u32>,
        times: protocol::file_time::Update,
        uid: u32,
        gid: u32,
        groups: &[u32],
    ) -> Result<(), i32> {
        self.time_file = Some((file, times, uid, gid, groups.to_vec()));
        self.time_error.map_or(Ok(()), Err)
    }

    fn utimens_at(
        &mut self,
        request: &posix_service::PreparedFileTimes,
        paths: PathObjects<u32>,
    ) -> Result<(), i32> {
        self.time_request = Some(request.clone());
        self.root = Some(paths.root);
        self.directory = paths.base;
        self.time_error.map_or(Ok(()), Err)
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

    fn update_status_flags(
        &mut self,
        file: AttachedObject<u32>,
        mask: u32,
        flags: u32,
    ) -> Result<(), i32> {
        self.flags_file = Some(file);
        self.status_flags = (self.status_flags & !mask) | flags;
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
        if self.retain_failure_at == Some(self.retained.len()) {
            return Err(-5);
        }
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

#[test]
fn prepared_fork_keeps_policy_and_directory_objects_from_preparation_not_commit() {
    let root = PeerIdentity {
        process_id: 401,
        effective_uid: 0,
        effective_gid: 0,
    };
    let owner = PeerIdentity {
        process_id: 402,
        ..root
    };
    let mut service = service_for(root);
    let mut filesystem = RecordingFilesystem::default();
    service
        .adopt_child(
            root,
            AuthenticatedProcess {
                process_id: 402,
                handle: 1402,
            },
            &mut filesystem,
        )
        .unwrap();
    let call = |service: &mut PosixService, opcode, flags, bytes: &[u8]| {
        let response = service.handle(
            owner,
            protocol::Header {
                opcode,
                flags,
                ..Default::default()
            },
            bytes,
        );
        assert_eq!(response.header.status, 0);
        response
    };
    // Open real independently-owned root/cwd references before preparing.
    assert_eq!(
        service
            .handle_objects(
                owner,
                protocol::Header {
                    opcode: protocol::OP_GETCWD,
                    ..Default::default()
                },
                &[],
                &[],
                &mut filesystem
            )
            .response
            .header
            .status,
        0
    );
    let before_directories = *service.session_directories(402).unwrap();
    let mut groups = [0u8; protocol::GROUP_LIST_MAX_LEN];
    let length = protocol::encode_group_list(&[7, 8], &mut groups).unwrap();
    call(&mut service, protocol::OP_GROUPS_SET, 0, &groups[..length]);
    let mut mask = [0; protocol::UMASK_PAYLOAD_LEN];
    protocol::encode_umask(0o027, &mut mask).unwrap();
    call(&mut service, protocol::OP_UMASK_SET, 0, &mask);
    let mut limit = [0; protocol::RESOURCE_LIMIT_REQUEST_LEN];
    protocol::encode_resource_limit_request(
        protocol::ResourceLimitRequest {
            process_id: 0,
            resource: protocol::RLIMIT_NOFILE,
            flags: protocol::RESOURCE_LIMIT_SET,
            limit: protocol::ResourceLimit { soft: 7, hard: 17 },
        },
        &mut limit,
    )
    .unwrap();
    call(&mut service, protocol::OP_RESOURCE_LIMIT, 0, &limit);
    let mut action = [0; protocol::SIGNAL_DISPOSITION_LEN];
    protocol::encode_signal_disposition(
        protocol::SignalDisposition {
            signal: 10,
            kind: protocol::SIGNAL_DISPOSITION_IGNORE,
            child_options: 0,
        },
        &mut action,
    )
    .unwrap();
    call(
        &mut service,
        protocol::OP_SIGNAL_DISPOSITION,
        protocol::SIGNAL_DISPOSITION_SET,
        &action,
    );
    let token = service.prepare_fork(owner, &mut filesystem).unwrap();
    // Parent updates between VM capture and ProcessCreate must not leak into
    // the child. Claims in PeerIdentity are not credential overrides.
    filesystem.stat_mode = Some(0o040755);
    assert_eq!(service.handle_objects(
        owner, protocol::Header { opcode: protocol::OP_FCHDIR, ..Default::default() },
        &[], &[AttachedObject { handle: 58, rights: 0x4000_0000_0000_0081 }], &mut filesystem,
    ).response.header.status, 0);
    assert_eq!(service.session_directories(402).unwrap().cwd.handle, 1058);
    protocol::encode_resource_limit_request(
        protocol::ResourceLimitRequest {
            process_id: 0,
            resource: protocol::RLIMIT_NOFILE,
            flags: protocol::RESOURCE_LIMIT_SET,
            limit: protocol::ResourceLimit { soft: 1, hard: 2 },
        },
        &mut limit,
    )
    .unwrap();
    call(&mut service, protocol::OP_RESOURCE_LIMIT, 0, &limit);
    protocol::encode_umask(0o077, &mut mask).unwrap();
    call(&mut service, protocol::OP_UMASK_SET, 0, &mask);
    let length = protocol::encode_group_list(&[99], &mut groups).unwrap();
    call(&mut service, protocol::OP_GROUPS_SET, 0, &groups[..length]);
    protocol::encode_signal_disposition(
        protocol::SignalDisposition {
            signal: 10,
            kind: protocol::SIGNAL_DISPOSITION_CAUGHT,
            child_options: 0,
        },
        &mut action,
    )
    .unwrap();
    call(
        &mut service,
        protocol::OP_SIGNAL_DISPOSITION,
        protocol::SIGNAL_DISPOSITION_SET,
        &action,
    );
    call(&mut service, protocol::OP_CREATE_SESSION, 0, &[]);
    let mut credential = [0; 4];
    protocol::encode_credential_id(505, &mut credential).unwrap();
    call(&mut service, protocol::OP_SET_GID, 0, &credential);
    call(&mut service, protocol::OP_SET_UID, 0, &credential);
    let child = AuthenticatedProcess {
        process_id: 403,
        handle: 1403,
    };
    let retained = filesystem.retained.len();
    service.commit_fork(owner, token, child).unwrap();
    assert_eq!(
        filesystem.retained.len(),
        retained,
        "commit must not reopen or retain live parent paths"
    );
    let session = service.session(403).unwrap();
    assert_eq!(
        (session.real_uid, session.effective_uid, session.saved_uid),
        (0, 0, 0)
    );
    assert_eq!(
        (session.real_gid, session.effective_gid, session.saved_gid),
        (0, 0, 0)
    );
    assert_eq!(session.umask, 0o027);
    assert_eq!(service.supplementary_groups(403), Some(&[7, 8][..]));
    let directories = service.session_directories(403).unwrap();
    assert_eq!(
        directories.root.handle,
        before_directories.root.handle + 1000
    );
    assert_eq!(directories.cwd.handle, before_directories.cwd.handle + 1000);
    let child_peer = PeerIdentity {
        process_id: 403,
        ..owner
    };
    let response = service.handle(
        child_peer,
        protocol::Header {
            opcode: protocol::OP_PROCESS_INFO,
            ..Default::default()
        },
        &0i64.to_le_bytes(),
    );
    let info = protocol::decode_process_info(&response.payload).unwrap();
    assert_eq!(
        (info.parent_id, info.process_group_id, info.session_id),
        (402, 401, 401)
    );
    let response = service.handle(
        child_peer,
        protocol::Header {
            opcode: protocol::OP_SIGNAL_DISPOSITION,
            ..Default::default()
        },
        &{
            protocol::encode_signal_disposition(
                protocol::SignalDisposition {
                    signal: 10,
                    kind: 0,
                    child_options: 0,
                },
                &mut action,
            )
            .unwrap();
            action
        },
    );
    assert_eq!(
        protocol::decode_signal_disposition(&response.payload)
            .unwrap()
            .kind,
        protocol::SIGNAL_DISPOSITION_IGNORE
    );
    protocol::encode_resource_limit_request(
        protocol::ResourceLimitRequest {
            process_id: 0,
            resource: protocol::RLIMIT_NOFILE,
            flags: 0,
            limit: Default::default(),
        },
        &mut limit,
    )
    .unwrap();
    let response = service.handle(
        child_peer,
        protocol::Header {
            opcode: protocol::OP_RESOURCE_LIMIT,
            ..Default::default()
        },
        &limit,
    );
    assert_eq!(
        protocol::decode_resource_limit(&response.payload).unwrap(),
        protocol::ResourceLimit { soft: 7, hard: 17 }
    );
    assert_eq!(
        service.cancel_fork(owner, token, &mut filesystem),
        Err(protocol::STATUS_ESRCH)
    );
    assert_eq!(
        service.commit_fork(owner, token, child),
        Err(protocol::STATUS_ESRCH)
    );
}

#[test]
fn fork_control_wire_rejects_self_claimed_identity_and_foreign_or_malformed_tokens() {
    let mut sentinel = [0xff; 8];
    assert!(protocol::fork::encode_token(0, &mut sentinel).is_err());
    assert!(protocol::fork::encode_token(1, &mut sentinel[..7]).is_err());
    assert_eq!(sentinel, [0xff; 8]);
    let owner = PeerIdentity {
        process_id: 701,
        effective_uid: 0,
        effective_gid: 0,
    };
    let foreign = PeerIdentity {
        process_id: 702,
        ..owner
    };
    let mut service = service_for(owner);
    let mut filesystem = RecordingFilesystem::default();
    let prepare = protocol::Header {
        opcode: protocol::OP_FORK_PREPARE,
        request_id: 71,
        ..Default::default()
    };
    for (header, payload, handles) in [
        (prepare, &701u64.to_le_bytes()[..], vec![]),
        (
            protocol::Header {
                flags: 1,
                ..prepare
            },
            &[][..],
            vec![],
        ),
        (
            protocol::Header {
                status: 1,
                ..prepare
            },
            &[][..],
            vec![],
        ),
        (
            prepare,
            &[][..],
            vec![AttachedObject {
                handle: 42,
                rights: mnu_abi::HANDLE_RIGHT_ALL,
            }],
        ),
    ] {
        assert_eq!(
            service
                .handle_objects(owner, header, payload, &handles, &mut filesystem)
                .response
                .header
                .status,
            STATUS_EINVAL
        );
    }
    let prepared = service.handle_objects(owner, prepare, &[], &[], &mut filesystem);
    assert!(prepared.handles.is_empty());
    assert_eq!(prepared.response.header.request_id, 71);
    assert_eq!(prepared.response.header.status, 0);
    let token = protocol::fork::decode_token(&prepared.response.payload).unwrap();
    let mut bytes = [0; protocol::fork::TOKEN_LEN];
    protocol::fork::encode_token(token, &mut bytes).unwrap();
    assert_eq!(
        protocol::fork::decode_token(&[0; 8]),
        Err(protocol::ProtocolError::InvalidLength)
    );
    for length in 0..8 {
        assert!(protocol::fork::decode_token(&bytes[..length]).is_err());
    }
    assert!(protocol::fork::decode_token(&[1; 9]).is_err());
    let cancel = protocol::Header {
        opcode: protocol::OP_FORK_CANCEL,
        ..prepare
    };
    assert_eq!(
        service
            .handle_objects(foreign, cancel, &bytes, &[], &mut filesystem)
            .response
            .header
            .status,
        protocol::STATUS_EPERM
    );
    assert_eq!(
        service
            .handle_objects(owner, cancel, &[0; 8], &[], &mut filesystem)
            .response
            .header
            .status,
        STATUS_EINVAL
    );
    assert_eq!(
        service
            .handle_objects(owner, cancel, &bytes, &[], &mut filesystem)
            .response
            .header
            .status,
        0
    );
    assert_eq!(
        service
            .handle_objects(owner, cancel, &bytes, &[], &mut filesystem)
            .response
            .header
            .status,
        protocol::STATUS_ESRCH
    );
}

#[test]
fn fork_commit_requires_exact_process_rights_and_live_native_status() {
    use posix_service::validate_fork_child;
    let object = AttachedObject {
        handle: 42,
        rights: mnu_abi::HANDLE_RIGHT_WAIT | mnu_abi::HANDLE_RIGHT_SIGNAL,
    };
    let status = mnu_abi::ProcessStatus {
        process_id: 705,
        state: mnu_abi::PROCESS_STATE_RUNNING,
        ..Default::default()
    };
    assert_eq!(
        validate_fork_child(object, status),
        Ok(AuthenticatedProcess {
            handle: 42,
            process_id: 705
        })
    );
    for rights in [
        0,
        mnu_abi::HANDLE_RIGHT_WAIT,
        mnu_abi::HANDLE_RIGHT_SIGNAL,
        mnu_abi::HANDLE_RIGHT_ALL,
    ] {
        assert_eq!(
            validate_fork_child(AttachedObject { rights, ..object }, status),
            Err(STATUS_EINVAL)
        );
    }
    for invalid in [
        mnu_abi::ProcessStatus {
            process_id: 0,
            ..status
        },
        mnu_abi::ProcessStatus {
            reserved: 1,
            ..status
        },
    ] {
        assert_eq!(validate_fork_child(object, invalid), Err(STATUS_EINVAL));
    }
    for state in [0, mnu_abi::PROCESS_STATE_EXITED, u32::MAX] {
        assert_eq!(
            validate_fork_child(object, mnu_abi::ProcessStatus { state, ..status }),
            Err(protocol::STATUS_ESRCH)
        );
    }
}

#[test]
fn fork_preparation_is_owned_bounded_cancelable_and_commit_failure_does_not_consume_it() {
    let owner = PeerIdentity {
        process_id: 501,
        effective_uid: 0,
        effective_gid: 0,
    };
    let foreign = PeerIdentity {
        process_id: 502,
        ..owner
    };
    let mut service = service_for(owner);
    let mut filesystem = RecordingFilesystem::default();
    assert_eq!(
        service
            .handle_objects(
                owner,
                protocol::Header {
                    opcode: protocol::OP_GETCWD,
                    ..Default::default()
                },
                &[],
                &[],
                &mut filesystem
            )
            .response
            .header
            .status,
        0
    );
    let token = service.prepare_fork(owner, &mut filesystem).unwrap();
    let child = AuthenticatedProcess {
        process_id: 503,
        handle: 1503,
    };
    assert_eq!(
        service.cancel_fork(foreign, token, &mut filesystem),
        Err(protocol::STATUS_EPERM)
    );
    assert_eq!(
        service.commit_fork(foreign, token, child),
        Err(protocol::STATUS_EPERM)
    );
    assert_eq!(
        service.commit_fork(
            owner,
            token,
            AuthenticatedProcess {
                process_id: 0,
                handle: 1503
            }
        ),
        Err(STATUS_EINVAL)
    );
    assert!(service.session(503).is_none());
    assert!(filesystem.released.is_empty());
    service.cancel_fork(owner, token, &mut filesystem).unwrap();
    assert_eq!(filesystem.released.len(), 2);
    assert_eq!(
        service.cancel_fork(owner, token, &mut filesystem),
        Err(protocol::STATUS_ESRCH)
    );
    let mut tokens = Vec::new();
    for _ in 0..64 {
        tokens.push(service.prepare_fork(owner, &mut filesystem).unwrap());
    }
    let retained = filesystem.retained.len();
    assert_eq!(
        service.prepare_fork(owner, &mut filesystem),
        Err(protocol::STATUS_EAGAIN)
    );
    assert_eq!(filesystem.retained.len(), retained);
    for token in tokens {
        service.cancel_fork(owner, token, &mut filesystem).unwrap();
    }
    let next = service.prepare_fork(owner, &mut filesystem).unwrap();
    assert!(next > token);
    service.commit_fork(owner, next, child).unwrap();
    assert!(service.is_child(501, 503));
}

#[test]
fn failed_directory_retention_rolls_back_and_dead_owner_cleanup_uses_native_status() {
    let owner = PeerIdentity {
        process_id: 601,
        effective_uid: 0,
        effective_gid: 0,
    };
    let mut service = service_for(owner);
    let mut filesystem = RecordingFilesystem::default();
    assert_eq!(
        service
            .handle_objects(
                owner,
                protocol::Header {
                    opcode: protocol::OP_GETCWD,
                    ..Default::default()
                },
                &[],
                &[],
                &mut filesystem
            )
            .response
            .header
            .status,
        0
    );
    filesystem.retain_failure_at = Some(2);
    assert_eq!(service.prepare_fork(owner, &mut filesystem), Err(-5));
    assert_eq!(
        filesystem
            .released
            .iter()
            .map(|object| object.handle)
            .collect::<Vec<_>>(),
        [1100]
    );
    filesystem.retain_failure_at = None;
    let token = service.prepare_fork(owner, &mut filesystem).unwrap();
    assert!(service.child_lifecycle_handles().contains(&601));
    let mut processes = RecordingProcesses::default();
    assert!(
        service
            .reap_abandoned_forks(&mut filesystem, &mut processes)
            .is_err()
    );
    assert_eq!(filesystem.released.len(), 1);
    processes.states.insert(601, ProcessLifecycle::Running);
    assert_eq!(
        service.reap_abandoned_forks(&mut filesystem, &mut processes),
        Ok(0)
    );
    processes
        .states
        .insert(601, ProcessLifecycle::Exited { exit_code: 0 });
    assert_eq!(
        service.reap_abandoned_forks(&mut filesystem, &mut processes),
        Ok(1)
    );
    assert_eq!(filesystem.released.len(), 3);
    assert_eq!(
        service.reap_abandoned_forks(&mut filesystem, &mut processes),
        Ok(0)
    );
    assert_eq!(
        service.cancel_fork(owner, token, &mut filesystem),
        Err(protocol::STATUS_ESRCH)
    );
}

#[test]
fn spawned_credentials_wire_is_strict_and_contains_no_process_id() {
    let mut bytes = [0; 8 + protocol::GROUP_LIST_MAX_LEN];
    let length = protocol::encode_spawn_credentials(505, 24, &[10, 20], &mut bytes).unwrap();
    let mut groups = [0; protocol::MAX_SUPPLEMENTARY_GROUPS];
    assert_eq!(
        protocol::decode_spawn_credentials(&bytes[..length], &mut groups),
        Ok((505, 24, 2))
    );
    assert_eq!(&groups[..2], &[10, 20]);
    for end in 0..length {
        assert!(protocol::decode_spawn_credentials(&bytes[..end], &mut groups).is_err());
    }
    assert!(protocol::decode_spawn_credentials(&bytes[..length + 1], &mut groups).is_err());
    assert!(protocol::encode_spawn_credentials(u32::MAX, 24, &[], &mut bytes).is_err());
    assert!(protocol::encode_spawn_credentials(505, u32::MAX, &[], &mut bytes).is_err());
}

#[test]
fn fresh_child_credentials_replace_launcher_identity_before_registration() {
    let parent = PeerIdentity {
        process_id: 301,
        effective_uid: 0,
        effective_gid: 0,
    };
    let mut service = service_for(parent);
    service.handle(
        parent,
        protocol::Header {
            opcode: protocol::OP_SESSION_REGISTER,
            ..Default::default()
        },
        &[],
    );
    let mut filesystem = RecordingFilesystem::default();
    service
        .adopt_spawned_child(
            parent,
            AuthenticatedProcess {
                handle: 302,
                process_id: 302,
            },
            505,
            24,
            &[10, 20],
            &mut filesystem,
        )
        .unwrap();
    let child = service.session(302).unwrap();
    assert_eq!(
        (child.real_uid, child.effective_uid, child.saved_uid),
        (505, 505, 505)
    );
    assert_eq!(
        (child.real_gid, child.effective_gid, child.saved_gid),
        (24, 24, 24)
    );
    assert_eq!(service.supplementary_groups(302), Some(&[10, 20][..]));
    assert_eq!(service.parent_id(302), Some(301));
    // Native credentials cannot overwrite already initialized POSIX state.
    let native_peer = PeerIdentity {
        process_id: 302,
        effective_uid: 0,
        effective_gid: 0,
    };
    service.handle(
        native_peer,
        protocol::Header {
            opcode: protocol::OP_SESSION_REGISTER,
            ..Default::default()
        },
        &[],
    );
    assert_eq!(service.session(302).unwrap().effective_uid, 505);
    assert_eq!(
        service.adopt_spawned_child(
            parent,
            AuthenticatedProcess {
                handle: 303,
                process_id: 302
            },
            0,
            0,
            &[],
            &mut filesystem
        ),
        Err(STATUS_EINVAL)
    );
    assert_eq!(service.session(302).unwrap().effective_uid, 505);
}

#[test]
fn fresh_child_initialization_cannot_elevate_nonroot_posix_authority() {
    let parent = PeerIdentity {
        process_id: 311,
        effective_uid: 505,
        effective_gid: 24,
    };
    let mut service = service_for(parent);
    service.handle(
        parent,
        protocol::Header {
            opcode: protocol::OP_SESSION_REGISTER,
            ..Default::default()
        },
        &[],
    );
    let mut filesystem = RecordingFilesystem::default();
    // Even a kernel/native UID of zero is not POSIX root after initialization.
    let native_peer = PeerIdentity {
        effective_uid: 0,
        effective_gid: 0,
        ..parent
    };
    for (uid, gid, groups) in [(0, 24, &[][..]), (505, 0, &[][..]), (505, 24, &[10][..])] {
        assert_eq!(
            service.adopt_spawned_child(
                native_peer,
                AuthenticatedProcess {
                    handle: 312,
                    process_id: 312
                },
                uid,
                gid,
                groups,
                &mut filesystem
            ),
            Err(protocol::STATUS_EPERM)
        );
        assert!(service.session(312).is_none());
        assert!(service.process_handle(312).is_none());
        assert!(filesystem.retained.is_empty());
    }
    service
        .adopt_spawned_child(
            native_peer,
            AuthenticatedProcess {
                handle: 312,
                process_id: 312,
            },
            505,
            24,
            &[],
            &mut filesystem,
        )
        .unwrap();
    assert_eq!(service.session(312).unwrap().effective_uid, 505);
}

#[test]
fn fresh_image_failure_cleanup_is_owned_by_the_authenticated_creator_not_root() {
    let creator = PeerIdentity {
        process_id: 321,
        effective_uid: 505,
        effective_gid: 24,
    };
    let mut service = service_for(creator);
    service.handle(
        creator,
        protocol::Header {
            opcode: protocol::OP_SESSION_REGISTER,
            ..Default::default()
        },
        &[],
    );
    let mut filesystem = RecordingFilesystem::default();
    let child = AuthenticatedProcess {
        process_id: 322,
        handle: 1322,
    };
    service
        .adopt_spawned_child(creator, child, 505, 24, &[], &mut filesystem)
        .unwrap();
    let mut processes = RecordingProcesses::default();
    processes.states.insert(1322, ProcessLifecycle::Running);
    let other_root = PeerIdentity {
        process_id: 323,
        effective_uid: 0,
        effective_gid: 0,
    };
    assert_eq!(
        service.abort_launched_child(other_root, child, &mut filesystem, &mut processes),
        Err(protocol::STATUS_EPERM)
    );
    assert!(processes.terminated.is_empty());
    service
        .abort_launched_child(creator, child, &mut filesystem, &mut processes)
        .unwrap();
    assert_eq!(processes.terminated, [(1322, 127)]);
    assert_eq!(processes.released, [1322]);
    assert!(service.session(322).is_none());
    assert!(!service.is_child(321, 322));
}

#[test]
fn failed_broker_launch_is_reclaimed_only_by_its_creator() {
    let broker = PeerIdentity {
        process_id: 321,
        effective_uid: 0,
        effective_gid: 0,
    };
    let mut service = service_for(broker);
    service.handle(
        broker,
        protocol::Header {
            opcode: protocol::OP_SESSION_REGISTER,
            ..Default::default()
        },
        &[],
    );
    let mut filesystem = RecordingFilesystem::default();
    service.handle_objects(
        broker,
        protocol::Header {
            opcode: protocol::OP_GETCWD,
            ..Default::default()
        },
        &[],
        &[],
        &mut filesystem,
    );
    let child = AuthenticatedProcess {
        process_id: 322,
        handle: 1322,
    };
    service
        .adopt_launched_child(
            broker,
            AuthenticatedProcess {
                process_id: 321,
                handle: 999,
            },
            child,
            &mut filesystem,
        )
        .unwrap();
    let mut processes = RecordingProcesses::default();
    processes.states.insert(1322, ProcessLifecycle::Running);
    let impostor = PeerIdentity {
        process_id: 323,
        ..broker
    };
    assert_eq!(
        service.abort_launched_child(impostor, child, &mut filesystem, &mut processes),
        Err(protocol::STATUS_EPERM)
    );
    assert!(processes.terminated.is_empty());
    assert!(service.is_child(321, 322));
    processes.terminate_error = Some(-5);
    assert_eq!(
        service.abort_launched_child(broker, child, &mut filesystem, &mut processes),
        Err(-5)
    );
    assert!(service.session(322).is_some());
    assert!(processes.released.is_empty());
    processes.terminate_error = None;
    service
        .abort_launched_child(broker, child, &mut filesystem, &mut processes)
        .unwrap();
    assert_eq!(processes.terminated, [(1322, 127)]);
    assert_eq!(processes.released, [1322]);
    assert_eq!(filesystem.released.len(), 2);
    assert!(service.session(322).is_none());
    assert!(service.session_directories(322).is_none());
    assert!(service.process_handle(322).is_none());
    assert!(service.parent_id(322).is_none());
    assert!(service.supplementary_groups(322).is_none());
    assert!(!service.is_child(321, 322));
    assert_eq!(
        service.abort_launched_child(broker, child, &mut filesystem, &mut processes),
        Err(protocol::STATUS_ESRCH)
    );
    assert_eq!(processes.released, [1322]);
}

#[test]
fn failed_fork_cleanup_requires_its_creator_and_is_retryable_after_lost_reply() {
    let parent = PeerIdentity {
        process_id: 421,
        effective_uid: 505,
        effective_gid: 24,
    };
    let mut service = service_for(parent);
    service.handle(
        parent,
        protocol::Header {
            opcode: protocol::OP_SESSION_REGISTER,
            ..Default::default()
        },
        &[],
    );
    let mut filesystem = RecordingFilesystem::default();
    let child = AuthenticatedProcess {
        process_id: 422,
        handle: 1422,
    };
    let mut processes = RecordingProcesses::default();
    // Registration may never have reached the server.
    assert_eq!(
        service.abort_launched_child(parent, child, &mut filesystem, &mut processes),
        Err(protocol::STATUS_ESRCH)
    );
    service.adopt_child(parent, child, &mut filesystem).unwrap();
    processes.states.insert(1422, ProcessLifecycle::Running);
    let other_root = PeerIdentity {
        process_id: 423,
        effective_uid: 0,
        effective_gid: 0,
    };
    assert_eq!(
        service.abort_launched_child(other_root, child, &mut filesystem, &mut processes),
        Err(protocol::STATUS_EPERM)
    );
    assert!(processes.terminated.is_empty());
    processes.terminate_error = Some(-5);
    assert_eq!(
        service.abort_launched_child(parent, child, &mut filesystem, &mut processes),
        Err(-5)
    );
    assert!(service.is_child(421, 422));
    assert!(processes.released.is_empty());
    processes.terminate_error = None;
    service
        .abort_launched_child(parent, child, &mut filesystem, &mut processes)
        .unwrap();
    assert!(!service.is_child(421, 422));
    assert!(service.session(422).is_none());
    assert_eq!(processes.terminated, [(1422, 127)]);
    assert_eq!(processes.released, [1422]);
    // A lost successful response must not make retry a new termination/reap.
    assert_eq!(
        service.abort_launched_child(parent, child, &mut filesystem, &mut processes),
        Err(protocol::STATUS_ESRCH)
    );
    assert_eq!(processes.terminated, [(1422, 127)]);
    assert_eq!(processes.released, [1422]);
}

#[test]
fn fork_inherits_dispositions_but_not_pending_signals_and_keeps_updates_independent() {
    let parent = PeerIdentity {
        process_id: 421,
        effective_uid: 505,
        effective_gid: 24,
    };
    let mut service = service_for(parent);
    let action = protocol::SignalDisposition {
        signal: 10,
        kind: protocol::SIGNAL_DISPOSITION_IGNORE,
        child_options: 0,
    };
    let mut bytes = [0; protocol::SIGNAL_DISPOSITION_LEN];
    protocol::encode_signal_disposition(action, &mut bytes).unwrap();
    let set = protocol::Header {
        opcode: protocol::OP_SIGNAL_DISPOSITION,
        flags: protocol::SIGNAL_DISPOSITION_SET,
        ..Default::default()
    };
    assert_eq!(service.handle(parent, set, &bytes).header.status, 0);
    let mut signal = [0; protocol::SIGNAL_SEND_REQUEST_LEN];
    protocol::encode_signal_send_request(
        protocol::SignalSendRequest {
            selector: 421,
            signal: 12,
        },
        &mut signal,
    )
    .unwrap();
    assert_eq!(
        service
            .handle(
                parent,
                protocol::Header {
                    opcode: protocol::OP_SIGNAL_SEND,
                    ..Default::default()
                },
                &signal
            )
            .header
            .status,
        0
    );
    service
        .adopt_child(
            parent,
            AuthenticatedProcess {
                handle: 1422,
                process_id: 422,
            },
            &mut RecordingFilesystem::default(),
        )
        .unwrap();
    assert_ne!(service.signal_state(421).unwrap().pending(), 0);
    assert_eq!(service.signal_state(422).unwrap().pending(), 0);
    let child = PeerIdentity {
        process_id: 422,
        ..parent
    };
    protocol::encode_signal_disposition(
        protocol::SignalDisposition {
            kind: protocol::SIGNAL_DISPOSITION_CAUGHT,
            ..action
        },
        &mut bytes,
    )
    .unwrap();
    let reply = service.handle(child, set, &bytes);
    assert_eq!(reply.header.status, 0);
    assert_eq!(
        protocol::decode_signal_disposition(&reply.payload).unwrap(),
        action
    );
    protocol::encode_signal_disposition(
        protocol::SignalDisposition { kind: 0, ..action },
        &mut bytes,
    )
    .unwrap();
    let get = protocol::Header { flags: 0, ..set };
    let reply = service.handle(parent, get, &bytes);
    assert_eq!(
        protocol::decode_signal_disposition(&reply.payload).unwrap(),
        action
    );
    let reply = service.handle(child, get, &bytes);
    assert_eq!(
        protocol::decode_signal_disposition(&reply.payload)
            .unwrap()
            .kind,
        protocol::SIGNAL_DISPOSITION_CAUGHT
    );
}

#[test]
fn signal_disposition_uses_object_ipc_without_accepting_attached_authority() {
    let peer = PeerIdentity {
        process_id: 421,
        effective_uid: 505,
        effective_gid: 24,
    };
    let mut service = service_for(peer);
    let mut filesystem = RecordingFilesystem::default();
    let action = protocol::SignalDisposition {
        signal: 10,
        kind: protocol::SIGNAL_DISPOSITION_IGNORE,
        child_options: 0,
    };
    let mut bytes = [0; protocol::SIGNAL_DISPOSITION_LEN];
    protocol::encode_signal_disposition(action, &mut bytes).unwrap();
    let header = protocol::Header {
        opcode: protocol::OP_SIGNAL_DISPOSITION,
        flags: protocol::SIGNAL_DISPOSITION_SET,
        ..Default::default()
    };
    let reply = service.handle_objects(peer, header, &bytes, &[], &mut filesystem);
    assert_eq!(reply.response.header.status, 0);
    assert_eq!(
        protocol::decode_signal_disposition(&reply.response.payload)
            .unwrap()
            .kind,
        0
    );
    let reply = service.handle_objects(
        peer,
        header,
        &bytes,
        &[AttachedObject {
            handle: 999,
            rights: mnu_abi::HANDLE_RIGHT_ALL,
        }],
        &mut filesystem,
    );
    assert_eq!(reply.response.header.status, -22);
    assert!(reply.handles.is_empty());
}

#[test]
fn failed_launch_that_already_exited_is_reaped_without_terminating_again() {
    let broker = PeerIdentity {
        process_id: 321,
        effective_uid: 0,
        effective_gid: 0,
    };
    let mut service = service_for(broker);
    service.handle(
        broker,
        protocol::Header {
            opcode: protocol::OP_SESSION_REGISTER,
            ..Default::default()
        },
        &[],
    );
    let mut filesystem = RecordingFilesystem::default();
    let child = AuthenticatedProcess {
        process_id: 322,
        handle: 1322,
    };
    service
        .adopt_launched_child(
            broker,
            AuthenticatedProcess {
                process_id: 321,
                handle: 999,
            },
            child,
            &mut filesystem,
        )
        .unwrap();
    let mut processes = RecordingProcesses::default();
    processes
        .states
        .insert(1322, ProcessLifecycle::Exited { exit_code: 127 });
    service
        .abort_launched_child(broker, child, &mut filesystem, &mut processes)
        .unwrap();
    assert!(processes.terminated.is_empty());
    assert_eq!(processes.released, [1322]);
    assert!(service.session(322).is_none());
}

#[test]
fn broker_launch_inherits_the_requester_not_the_broker() {
    let broker = PeerIdentity {
        process_id: 321,
        effective_uid: 0,
        effective_gid: 0,
    };
    let mut service = service_for(broker);
    assert_eq!(
        service
            .handle(
                broker,
                protocol::Header {
                    opcode: protocol::OP_SESSION_REGISTER,
                    ..Default::default()
                },
                &[]
            )
            .header
            .status,
        0
    );
    let mut filesystem = RecordingFilesystem::default();
    service
        .adopt_spawned_child(
            broker,
            AuthenticatedProcess {
                handle: 322,
                process_id: 322,
            },
            505,
            24,
            &[10, 20],
            &mut filesystem,
        )
        .unwrap();
    let requester = PeerIdentity {
        process_id: 322,
        effective_uid: 0,
        effective_gid: 0,
    };
    let mut mask = [0; protocol::UMASK_PAYLOAD_LEN];
    protocol::encode_umask(0o27, &mut mask).unwrap();
    let mut limits = [0; protocol::RESOURCE_LIMIT_REQUEST_LEN];
    let inherited_limit = protocol::ResourceLimit { soft: 7, hard: 17 };
    protocol::encode_resource_limit_request(
        protocol::ResourceLimitRequest {
            process_id: 0,
            resource: protocol::RLIMIT_NOFILE,
            flags: protocol::RESOURCE_LIMIT_SET,
            limit: inherited_limit,
        },
        &mut limits,
    )
    .unwrap();
    assert_eq!(
        service
            .handle(
                requester,
                protocol::Header {
                    opcode: protocol::OP_RESOURCE_LIMIT,
                    ..Default::default()
                },
                &limits
            )
            .header
            .status,
        0
    );
    assert_eq!(
        service
            .handle_objects(
                requester,
                protocol::Header {
                    opcode: protocol::OP_GETCWD,
                    ..Default::default()
                },
                &[],
                &[],
                &mut filesystem
            )
            .response
            .header
            .status,
        0
    );
    assert_eq!(
        service
            .handle(
                requester,
                protocol::Header {
                    opcode: protocol::OP_UMASK_SET,
                    ..Default::default()
                },
                &mask
            )
            .header
            .status,
        0
    );
    service
        .adopt_launched_child(
            broker,
            AuthenticatedProcess {
                handle: 1322,
                process_id: 322,
            },
            AuthenticatedProcess {
                handle: 323,
                process_id: 323,
            },
            &mut filesystem,
        )
        .unwrap();
    let child = service.session(323).unwrap();
    assert_eq!(
        (child.real_uid, child.effective_uid, child.saved_uid),
        (505, 505, 505)
    );
    assert_eq!(
        (child.real_gid, child.effective_gid, child.saved_gid),
        (24, 24, 24)
    );
    assert_eq!(child.umask, 0o27);
    assert_eq!(service.supplementary_groups(323), Some(&[10, 20][..]));
    assert_eq!(service.parent_id(323), Some(322));
    assert!(service.is_child(322, 323));
    assert!(!service.is_child(321, 323));
    assert_eq!(service.process_handle(323), Some(323));
    protocol::encode_resource_limit_request(
        protocol::ResourceLimitRequest {
            process_id: 0,
            resource: protocol::RLIMIT_NOFILE,
            flags: 0,
            limit: Default::default(),
        },
        &mut limits,
    )
    .unwrap();
    let child_limit = service.handle(
        PeerIdentity {
            process_id: 323,
            ..requester
        },
        protocol::Header {
            opcode: protocol::OP_RESOURCE_LIMIT,
            ..Default::default()
        },
        &limits,
    );
    assert_eq!(child_limit.header.status, 0);
    assert_eq!(
        protocol::decode_resource_limit(&child_limit.payload).unwrap(),
        inherited_limit
    );
    assert_eq!(filesystem.retained.len(), 2);
    let parent_directories = service.session_directories(322).unwrap();
    let child_directories = service.session_directories(323).unwrap();
    assert_eq!(
        child_directories.root.handle,
        parent_directories.root.handle + 1000
    );
    assert_eq!(
        child_directories.cwd.handle,
        parent_directories.cwd.handle + 1000
    );
    // The inspection-only requester attachment is not stored as its owner.
    assert_eq!(service.process_handle(322), Some(322));
    assert_eq!(
        service.adopt_launched_child(
            broker,
            AuthenticatedProcess {
                handle: 322,
                process_id: 322
            },
            AuthenticatedProcess {
                handle: 1323,
                process_id: 323
            },
            &mut filesystem
        ),
        Err(STATUS_EINVAL)
    );
    assert_eq!(service.parent_id(323), Some(322));
    assert_eq!(
        service
            .handle(
                broker,
                protocol::Header {
                    opcode: protocol::OP_PROCESS_LAUNCHED,
                    ..Default::default()
                },
                &[]
            )
            .header
            .status,
        STATUS_EINVAL
    );
}

#[test]
fn launch_registration_never_trusts_native_root_or_unknown_requester() {
    let root = PeerIdentity {
        process_id: 333,
        effective_uid: 0,
        effective_gid: 0,
    };
    let broker = PeerIdentity {
        process_id: 331,
        effective_uid: 505,
        effective_gid: 24,
    };
    let mut service = service_for(root);
    service
        .initialize_process(
            root,
            AuthenticatedProcess {
                handle: 331,
                process_id: 331,
            },
            broker.effective_uid,
            broker.effective_gid,
            &[],
        )
        .unwrap();
    service.handle(
        broker,
        protocol::Header {
            opcode: protocol::OP_SESSION_REGISTER,
            ..Default::default()
        },
        &[],
    );
    let mut filesystem = RecordingFilesystem::default();
    assert_eq!(
        service.adopt_launched_child(
            PeerIdentity {
                effective_uid: 0,
                ..broker
            },
            AuthenticatedProcess {
                handle: 331,
                process_id: 331
            },
            AuthenticatedProcess {
                handle: 332,
                process_id: 332
            },
            &mut filesystem
        ),
        Err(protocol::STATUS_EPERM)
    );
    assert!(service.session(332).is_none());
    assert!(service.process_handle(332).is_none());
    assert!(filesystem.retained.is_empty());
    service.handle(
        root,
        protocol::Header {
            opcode: protocol::OP_SESSION_REGISTER,
            ..Default::default()
        },
        &[],
    );
    assert_eq!(
        service.adopt_launched_child(
            root,
            AuthenticatedProcess {
                handle: 999,
                process_id: 999
            },
            AuthenticatedProcess {
                handle: 332,
                process_id: 332
            },
            &mut filesystem
        ),
        Err(protocol::STATUS_ESRCH)
    );
    assert!(service.process_handle(332).is_none());
}

#[test]
fn launcher_tree_uses_userspace_descendants_and_exact_creation_authority() {
    let creator = PeerIdentity {
        process_id: 10,
        effective_uid: 0,
        effective_gid: 0,
    };
    let mut service = service_for(creator);
    let process = |process_id| AuthenticatedProcess {
        process_id,
        handle: process_id as u32 + 1000,
    };
    service
        .initialize_process(creator, process(20), 501, 20, &[])
        .unwrap();
    service
        .initialize_process(creator, process(60), 0, 0, &[])
        .unwrap();
    let requester = service.registered_peer(20).unwrap();
    let unrelated_root = service.registered_peer(60).unwrap();
    let mut filesystem = RecordingFilesystem::default();
    // A broker-created root belongs to the requester's POSIX family, not the
    // launcher's. Teardown authority must still belong to the actual creator.
    service
        .adopt_launched_child(creator, process(20), process(30), &mut filesystem)
        .unwrap();
    let root_peer = service.registered_peer(30).unwrap();
    service
        .adopt_child(root_peer, process(40), &mut filesystem)
        .unwrap();
    let child_peer = service.registered_peer(40).unwrap();
    service
        .adopt_child(child_peer, process(50), &mut filesystem)
        .unwrap();
    service
        .adopt_launched_child(creator, process(20), process(70), &mut filesystem)
        .unwrap();
    assert_eq!(
        service.launched_tree_handles(creator, process(30)),
        Ok(vec![1050, 1040, 1030])
    );
    assert_eq!(service.parent_id(30), Some(20));
    assert_eq!(service.parent_id(50), Some(40));
    for unauthorized in [
        requester,
        unrelated_root,
        PeerIdentity {
            effective_uid: 0,
            ..requester
        },
    ] {
        assert_eq!(
            service.launched_tree_handles(unauthorized, process(30)),
            Err(protocol::STATUS_EPERM)
        );
    }
    // A descendant's object does not let the launcher broaden the selected
    // root, and unrelated/unknown objects cannot initiate a teardown.
    for pid in [20, 40, 60, 999] {
        assert_eq!(
            service.launched_tree_handles(creator, process(pid)),
            Err(protocol::STATUS_EPERM)
        );
    }
    assert_eq!(
        service.launched_tree_handles(
            PeerIdentity {
                process_id: 999,
                ..creator
            },
            process(30)
        ),
        Err(protocol::STATUS_ESRCH)
    );
    assert_eq!(
        service.launched_tree_handles(creator, process(70)),
        Ok(vec![1070])
    );
    assert!(filesystem.released.is_empty());
    assert!(service.session(50).is_some());
}

fn launched_tree_fixture() -> (
    PosixService,
    PeerIdentity,
    RecordingFilesystem,
    RecordingProcesses,
) {
    let creator = PeerIdentity {
        process_id: 10,
        effective_uid: 0,
        effective_gid: 0,
    };
    let mut service = service_for(creator);
    let mut filesystem = RecordingFilesystem::default();
    service.handle_objects(
        creator,
        protocol::Header {
            opcode: protocol::OP_GETCWD,
            ..Default::default()
        },
        &[],
        &[],
        &mut filesystem,
    );
    service
        .adopt_spawned_child(
            creator,
            AuthenticatedProcess {
                process_id: 30,
                handle: 1030,
            },
            501,
            20,
            &[],
            &mut filesystem,
        )
        .unwrap();
    for (parent, child) in [(30, 40), (40, 50)] {
        service
            .adopt_child(
                service.registered_peer(parent).unwrap(),
                AuthenticatedProcess {
                    process_id: child,
                    handle: child as u32 + 1000,
                },
                &mut filesystem,
            )
            .unwrap();
    }
    let mut processes = RecordingProcesses::default();
    for handle in [1030, 1040, 1050] {
        processes.states.insert(handle, ProcessLifecycle::Running);
        processes.identities.insert(handle, u64::from(handle - 1000));
    }
    (service, creator, filesystem, processes)
}

#[test]
fn lost_tree_exit_reply_can_repeat_confirmation_before_reclaim() {
    let (mut service, creator, mut filesystem, mut processes) = launched_tree_fixture();
    let root = AuthenticatedProcess {
        process_id: 30,
        handle: 1030,
    };
    service
        .begin_launched_tree_termination(creator, root, &mut processes)
        .unwrap();
    assert_eq!(processes.terminated, [(1050, 1), (1040, 1), (1030, 1)]);
    assert!(processes.released.is_empty());
    assert!(filesystem.released.is_empty());
    assert_eq!(
        service.launched_tree_handles(creator, root),
        Ok(vec![1050, 1040, 1030])
    );
    // Simulate a server operation whose successful reply never reached its
    // launcher. The same explicit root must still authenticate on retry.
    service
        .begin_launched_tree_termination(creator, root, &mut processes)
        .unwrap();
    assert_eq!(processes.terminated.len(), 3);
    let denied = service.registered_peer(40).unwrap();
    assert_eq!(
        service.reclaim_launched_tree(denied, root, &mut filesystem, &mut processes),
        Err(protocol::STATUS_EPERM)
    );
    assert!(processes.released.is_empty());
    service
        .reclaim_launched_tree(creator, root, &mut filesystem, &mut processes)
        .unwrap();
    assert_eq!(processes.released, [1050, 1040, 1030]);
    assert_eq!(filesystem.released.len(), 6);
    // A lost reclaim reply is distinguishable from an unconfirmed exit:
    // a caller may accept ESRCH only after it received exit confirmation.
    assert_eq!(
        service.reclaim_launched_tree(creator, root, &mut filesystem, &mut processes),
        Err(protocol::STATUS_ESRCH)
    );
    assert_eq!(processes.released.len(), 3);
    assert_eq!(filesystem.released.len(), 6);
}

#[test]
fn active_tree_transaction_prevents_wait_rollback_and_late_child_adoption() {
    let (mut service, creator, mut filesystem, mut processes) = launched_tree_fixture();
    let root = AuthenticatedProcess {
        process_id: 30,
        handle: 1030,
    };
    processes.terminate_failure = Some((1040, -5));
    assert_eq!(
        service.begin_launched_tree_termination(creator, root, &mut processes),
        Err(-5)
    );
    let child_parent = service.registered_peer(40).unwrap();
    assert_eq!(
        service.wait_handles(
            child_parent,
            protocol::WaitRequest {
                selector: 50,
                options: 0,
            }
        ),
        Ok(vec![])
    );
    assert_eq!(
        service.wait_child(
            child_parent,
            protocol::WaitRequest {
                selector: 50,
                options: 0,
            },
            &mut filesystem,
            &mut processes
        ),
        Err(protocol::STATUS_EAGAIN)
    );
    assert_eq!(
        service.abort_launched_child(creator, root, &mut filesystem, &mut processes),
        Err(protocol::STATUS_EAGAIN)
    );
    assert_eq!(
        service.adopt_child(
            service.registered_peer(30).unwrap(),
            AuthenticatedProcess {
                process_id: 60,
                handle: 1060
            },
            &mut filesystem
        ),
        Err(protocol::STATUS_EAGAIN)
    );
    assert_eq!(
        service.reclaim_launched_tree(creator, root, &mut filesystem, &mut processes),
        Err(protocol::STATUS_EAGAIN)
    );
    assert!(processes.released.is_empty());
    assert!(filesystem.released.is_empty());
    assert!(service.registered_peer(60).is_none());
    assert_eq!(service.parent_id(50), Some(40));
    processes.terminate_failure = None;
    service
        .begin_launched_tree_termination(creator, root, &mut processes)
        .unwrap();
    service
        .reclaim_launched_tree(creator, root, &mut filesystem, &mut processes)
        .unwrap();
    // Pins are scoped to this transaction, not a permanent ban on creation.
    service
        .adopt_spawned_child(
            creator,
            AuthenticatedProcess {
                process_id: 60,
                handle: 1060,
            },
            501,
            20,
            &[],
            &mut filesystem,
        )
        .unwrap();
    assert_eq!(service.parent_id(60), Some(10));
}

#[test]
fn overlapping_tree_transactions_do_not_steal_each_others_owned_processes() {
    let (mut service, creator, mut filesystem, mut processes) = launched_tree_fixture();
    let root = AuthenticatedProcess {
        process_id: 30,
        handle: 1030,
    };
    let nested = AuthenticatedProcess {
        process_id: 60,
        handle: 1060,
    };
    service
        .adopt_launched_child(creator, root, nested, &mut filesystem)
        .unwrap();
    processes.states.insert(1060, ProcessLifecycle::Running);
    service
        .begin_launched_tree_termination(creator, nested, &mut processes)
        .unwrap();
    assert_eq!(
        service.begin_launched_tree_termination(creator, root, &mut processes),
        Err(protocol::STATUS_EAGAIN)
    );
    assert_eq!(processes.terminated, [(1060, 1)]);
    assert!(processes.released.is_empty());
    service
        .reclaim_launched_tree(creator, nested, &mut filesystem, &mut processes)
        .unwrap();
    service
        .begin_launched_tree_termination(creator, root, &mut processes)
        .unwrap();
    service
        .reclaim_launched_tree(creator, root, &mut filesystem, &mut processes)
        .unwrap();
    assert_eq!(
        processes.terminated,
        [(1060, 1), (1050, 1), (1040, 1), (1030, 1)]
    );
    assert_eq!(processes.released, [1060, 1050, 1040, 1030]);
}

#[test]
fn tree_reclaim_never_terminates_unconfirmed_processes_or_starts_a_transaction() {
    let (mut service, creator, mut filesystem, mut processes) = launched_tree_fixture();
    let root = AuthenticatedProcess {
        process_id: 30,
        handle: 1030,
    };
    assert_eq!(
        service.reclaim_launched_tree(creator, root, &mut filesystem, &mut processes),
        Err(protocol::STATUS_EAGAIN)
    );
    assert!(processes.terminated.is_empty());
    assert!(processes.released.is_empty());
    assert!(filesystem.released.is_empty());
    assert_eq!(
        service.launched_tree_handles(creator, root),
        Ok(vec![1050, 1040, 1030])
    );
}

#[test]
fn launched_tree_is_reclaimed_only_after_confirmed_descendant_first_exit() {
    let (mut service, creator, mut filesystem, mut processes) = launched_tree_fixture();
    let root = AuthenticatedProcess {
        process_id: 30,
        handle: 1030,
    };
    let denied = service.registered_peer(30).unwrap();
    assert_eq!(
        finish_tree(&mut service, denied, root, &mut filesystem, &mut processes),
        Err(protocol::STATUS_EPERM)
    );
    assert!(processes.terminated.is_empty());
    finish_tree(&mut service, creator, root, &mut filesystem, &mut processes).unwrap();
    assert_eq!(processes.terminated, [(1050, 1), (1040, 1), (1030, 1)]);
    assert_eq!(processes.released, [1050, 1040, 1030]);
    assert_eq!(filesystem.released.len(), 6);
    for pid in [30, 40, 50] {
        assert!(service.registered_peer(pid).is_none());
        assert!(service.parent_id(pid).is_none());
    }
    assert!(service.registered_peer(10).is_some());
    assert_eq!(
        finish_tree(&mut service, creator, root, &mut filesystem, &mut processes),
        Err(protocol::STATUS_EPERM)
    );
}

fn finish_tree(
    service: &mut PosixService,
    peer: PeerIdentity,
    root: AuthenticatedProcess<u32>,
    filesystem: &mut RecordingFilesystem,
    processes: &mut RecordingProcesses,
) -> Result<(), i32> {
    service.begin_launched_tree_termination(peer, root, processes)?;
    service.reclaim_launched_tree(peer, root, filesystem, processes)
}

#[test]
fn partial_tree_termination_failure_keeps_all_objects_for_retry() {
    let (mut service, creator, mut filesystem, mut processes) = launched_tree_fixture();
    let root = AuthenticatedProcess {
        process_id: 30,
        handle: 1030,
    };
    processes.terminate_failure = Some((1040, -5));
    assert_eq!(
        finish_tree(&mut service, creator, root, &mut filesystem, &mut processes),
        Err(-5)
    );
    assert_eq!(processes.terminated, [(1050, 1)]);
    assert!(processes.released.is_empty());
    assert!(filesystem.released.is_empty());
    assert_eq!(
        service.launched_tree_handles(creator, root),
        Ok(vec![1050, 1040, 1030])
    );
    processes.terminate_failure = None;
    finish_tree(&mut service, creator, root, &mut filesystem, &mut processes).unwrap();
    assert_eq!(processes.terminated, [(1050, 1), (1040, 1), (1030, 1)]);
    assert_eq!(processes.released, [1050, 1040, 1030]);
}

#[test]
fn delayed_tree_exit_is_not_treated_as_completed_teardown() {
    let (mut service, creator, mut filesystem, mut processes) = launched_tree_fixture();
    let root = AuthenticatedProcess {
        process_id: 30,
        handle: 1030,
    };
    processes.termination_pending = true;
    assert_eq!(
        finish_tree(&mut service, creator, root, &mut filesystem, &mut processes),
        Err(protocol::STATUS_EAGAIN)
    );
    assert!(processes.released.is_empty());
    assert!(filesystem.released.is_empty());
    assert_eq!(service.parent_id(50), Some(40));
    processes.termination_pending = false;
    processes
        .states
        .insert(1050, ProcessLifecycle::Exited { exit_code: 1 });
    finish_tree(&mut service, creator, root, &mut filesystem, &mut processes).unwrap();
    assert_eq!(processes.terminated, [(1050, 1), (1040, 1), (1030, 1)]);
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

#[test]
fn child_exit_queues_sigchld_before_the_parent_waits() {
    let parent = PeerIdentity {
        process_id: 1230,
        effective_uid: 505,
        effective_gid: 24,
    };
    let child = PeerIdentity {
        process_id: 1231,
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
                handle: 631,
                process_id: child.process_id,
            },
            &mut filesystem,
        )
        .unwrap();
    let mut processes = RecordingProcesses::default();
    processes.states.insert(631, ProcessLifecycle::Running);
    assert_eq!(service.child_lifecycle_handles(), vec![631]);

    processes
        .states
        .insert(631, ProcessLifecycle::Exited { exit_code: 4 });
    assert_eq!(
        service.refresh_child_exit_notifications(&mut processes),
        Ok(1)
    );
    assert_eq!(
        service.refresh_child_exit_notifications(&mut processes),
        Ok(0)
    );
    assert!(service.child_lifecycle_handles().is_empty());
    assert_eq!(
        service.signal_state(parent.process_id).unwrap().pending(),
        1u64 << (protocol::SIGNAL_CHLD - 1)
    );

    let delivery = dequeue_signal(&mut service, parent);
    assert_eq!(delivery.signal, protocol::SIGNAL_CHLD);
    let mut encoded = [0u8; protocol::SIGNAL_DELIVERY_LEN];
    protocol::encode_signal_delivery(delivery, &mut encoded).unwrap();
    service
        .complete_signal_delivery(parent, &encoded)
        .unwrap();

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
    assert_eq!(waited.status, 4 << 8);
}

fn orphan_family() -> (
    PosixService,
    PeerIdentity,
    PeerIdentity,
    PeerIdentity,
    RecordingFilesystem,
    RecordingProcesses,
) {
    let init = PeerIdentity {
        process_id: 1400,
        effective_uid: 0,
        effective_gid: 0,
    };
    let parent = PeerIdentity {
        process_id: 1401,
        effective_uid: 505,
        effective_gid: 24,
    };
    let child = PeerIdentity {
        process_id: 1402,
        ..parent
    };
    let mut service = PosixService::new();
    service
        .initialize_bootstrap_process(
            AuthenticatedProcess {
                handle: 140,
                process_id: init.process_id,
            },
            0,
            0,
            &[],
        )
        .unwrap();
    let mut filesystem = RecordingFilesystem::default();
    service
        .adopt_spawned_child(
            init,
            AuthenticatedProcess {
                handle: 141,
                process_id: parent.process_id,
            },
            505,
            24,
            &[42],
            &mut filesystem,
        )
        .unwrap();
    assert_eq!(
        service
            .handle_objects(
                parent,
                protocol::Header {
                    opcode: protocol::OP_GETCWD,
                    ..Default::default()
                },
                &[],
                &[],
                &mut filesystem
            )
            .response
            .header
            .status,
        0
    );
    service
        .adopt_launched_child(
            init,
            AuthenticatedProcess {
                handle: 141,
                process_id: parent.process_id,
            },
            AuthenticatedProcess {
                handle: 142,
                process_id: child.process_id,
            },
            &mut filesystem,
        )
        .unwrap();
    let mut processes = RecordingProcesses::default();
    for handle in [140, 141, 142] {
        processes.states.insert(handle, ProcessLifecycle::Running);
    }
    processes.identities.extend([(140, 1400), (141, 1401), (142, 1402)]);
    (service, init, parent, child, filesystem, processes)
}

fn set_child_signal_disposition(service: &mut PosixService, parent: PeerIdentity, kind: u32) {
    set_child_signal_policy(service, parent, kind, 0);
}

fn set_child_signal_policy(
    service: &mut PosixService,
    parent: PeerIdentity,
    kind: u32,
    options: u32,
) {
    let mut bytes = [0; protocol::SIGNAL_DISPOSITION_LEN];
    protocol::encode_signal_disposition(
        protocol::SignalDisposition {
            signal: protocol::SIGNAL_CHLD,
            kind,
            child_options: options,
        },
        &mut bytes,
    )
    .unwrap();
    let response = service.handle(
        parent,
        protocol::Header {
            opcode: protocol::OP_SIGNAL_DISPOSITION,
            flags: protocol::SIGNAL_DISPOSITION_SET,
            ..Default::default()
        },
        &bytes,
    );
    assert_eq!(response.header.status, 0);
}

#[test]
fn explicit_sigchld_ignore_reaps_only_confirmed_exited_children_once() {
    let (mut service, _, parent, child, mut filesystem, mut processes) = orphan_family();
    set_child_signal_disposition(&mut service, parent, protocol::SIGNAL_DISPOSITION_IGNORE);
    assert_eq!(
        service.reap_discarded_children(&mut filesystem, &mut processes),
        Ok(0)
    );
    assert!(service.is_child(parent.process_id, child.process_id));
    processes
        .states
        .insert(142, ProcessLifecycle::Exited { exit_code: 7 });
    assert_eq!(
        service.reap_discarded_children(&mut filesystem, &mut processes),
        Ok(1)
    );
    assert_eq!(processes.released, vec![142]);
    assert!(!service.is_child(parent.process_id, child.process_id));
    assert!(service.session(child.process_id).is_none());
    assert_eq!(
        service.reap_discarded_children(&mut filesystem, &mut processes),
        Ok(0)
    );
    assert_eq!(
        service.wait_child(
            parent,
            protocol::WaitRequest {
                selector: child.process_id as i64,
                options: 0
            },
            &mut filesystem,
            &mut processes
        ),
        Err(protocol::STATUS_ECHILD)
    );
}

#[test]
fn default_sigchld_retains_status_and_direct_wait_also_honors_explicit_ignore() {
    for ignored in [false, true] {
        let (mut service, _, parent, child, mut filesystem, mut processes) = orphan_family();
        if ignored {
            set_child_signal_disposition(&mut service, parent, protocol::SIGNAL_DISPOSITION_IGNORE);
        }
        processes
            .states
            .insert(142, ProcessLifecycle::Exited { exit_code: 7 });
        let waited = service.wait_child(
            parent,
            protocol::WaitRequest {
                selector: child.process_id as i64,
                options: 0,
            },
            &mut filesystem,
            &mut processes,
        );
        if ignored {
            assert_eq!(waited, Err(protocol::STATUS_ECHILD));
        } else {
            let status = waited.unwrap();
            assert_eq!(
                (status.process_id, status.status),
                (child.process_id, 7 << 8)
            );
        }
    }
}

#[test]
fn restoring_sigchld_default_does_not_resurrect_observed_discarded_status() {
    let (mut service, _, parent, child, mut filesystem, mut processes) = orphan_family();
    set_child_signal_disposition(&mut service, parent, protocol::SIGNAL_DISPOSITION_IGNORE);
    processes
        .states
        .insert(142, ProcessLifecycle::Exited { exit_code: 7 });
    service
        .refresh_child_exit_notifications(&mut processes)
        .unwrap();
    set_child_signal_disposition(&mut service, parent, protocol::SIGNAL_DISPOSITION_DEFAULT);
    assert_eq!(
        service.reap_discarded_children(&mut filesystem, &mut processes),
        Ok(1)
    );
    assert!(!service.is_child(parent.process_id, child.process_id));
}

#[test]
fn ignoring_sigchld_also_discards_already_observed_zombie_status() {
    let (mut service, _, parent, child, mut filesystem, mut processes) = orphan_family();
    processes
        .states
        .insert(142, ProcessLifecycle::Exited { exit_code: 7 });
    service
        .refresh_child_exit_notifications(&mut processes)
        .unwrap();
    set_child_signal_disposition(&mut service, parent, protocol::SIGNAL_DISPOSITION_IGNORE);
    set_child_signal_disposition(&mut service, parent, protocol::SIGNAL_DISPOSITION_DEFAULT);
    assert_eq!(
        service.reap_discarded_children(&mut filesystem, &mut processes),
        Ok(1)
    );
    assert!(!service.is_child(parent.process_id, child.process_id));
}

#[test]
fn ignored_children_with_failed_native_status_are_not_assumed_dead() {
    let (mut service, _, parent, child, mut filesystem, mut processes) = orphan_family();
    set_child_signal_disposition(&mut service, parent, protocol::SIGNAL_DISPOSITION_IGNORE);
    processes.states.remove(&142);
    assert_eq!(
        service.reap_discarded_children(&mut filesystem, &mut processes),
        Err(protocol::STATUS_ESRCH)
    );
    assert!(service.is_child(parent.process_id, child.process_id));
    assert!(processes.released.is_empty());
}

#[test]
fn sigchld_ignore_does_not_steal_pinned_teardown_resources() {
    let (mut service, creator, mut filesystem, mut processes) = launched_tree_fixture();
    let root = AuthenticatedProcess {
        process_id: 30,
        handle: 1030,
    };
    set_child_signal_disposition(&mut service, creator, protocol::SIGNAL_DISPOSITION_IGNORE);
    service
        .begin_launched_tree_termination(creator, root, &mut processes)
        .unwrap();
    assert_eq!(
        service.reap_discarded_children(&mut filesystem, &mut processes),
        Ok(0)
    );
    assert!(processes.released.is_empty());
    set_child_signal_disposition(&mut service, creator, protocol::SIGNAL_DISPOSITION_DEFAULT);
    assert_eq!(
        service.reap_discarded_children(&mut filesystem, &mut processes),
        Ok(0)
    );
    service
        .reclaim_launched_tree(creator, root, &mut filesystem, &mut processes)
        .unwrap();
    assert_eq!(processes.released, vec![1050, 1040, 1030]);
}

#[test]
fn no_cld_wait_reaps_children_while_preserving_caught_exit_notifications() {
    let (mut service, _, parent, child, mut filesystem, mut processes) = orphan_family();
    set_child_signal_policy(
        &mut service,
        parent,
        protocol::SIGNAL_DISPOSITION_CAUGHT,
        protocol::SIGNAL_CHILD_OPTION_NOCLDWAIT | protocol::SIGNAL_CHILD_OPTION_NOCLDSTOP,
    );
    processes
        .states
        .insert(142, ProcessLifecycle::Exited { exit_code: 9 });
    assert_eq!(
        service.refresh_child_exit_notifications(&mut processes),
        Ok(1)
    );
    assert_ne!(
        service.signal_state(parent.process_id).unwrap().pending()
            & (1 << (protocol::SIGNAL_CHLD - 1)),
        0
    );
    assert_eq!(
        service.reap_discarded_children(&mut filesystem, &mut processes),
        Ok(1)
    );
    assert!(!service.is_child(parent.process_id, child.process_id));
    assert_eq!(
        service.wait_child(
            parent,
            protocol::WaitRequest {
                selector: -1,
                options: 0
            },
            &mut filesystem,
            &mut processes
        ),
        Err(protocol::STATUS_ECHILD)
    );
}

#[test]
fn clearing_no_cld_wait_after_observed_exit_does_not_restore_discarded_status() {
    let (mut service, _, parent, child, mut filesystem, mut processes) = orphan_family();
    set_child_signal_policy(
        &mut service,
        parent,
        protocol::SIGNAL_DISPOSITION_DEFAULT,
        protocol::SIGNAL_CHILD_OPTION_NOCLDWAIT,
    );
    processes
        .states
        .insert(142, ProcessLifecycle::Exited { exit_code: 9 });
    service
        .refresh_child_exit_notifications(&mut processes)
        .unwrap();
    set_child_signal_policy(
        &mut service,
        parent,
        protocol::SIGNAL_DISPOSITION_DEFAULT,
        0,
    );
    assert_eq!(
        service.reap_discarded_children(&mut filesystem, &mut processes),
        Ok(1)
    );
    assert!(!service.is_child(parent.process_id, child.process_id));
}

#[test]
fn orphan_reparenting_preserves_credentials_and_objects_then_reaps_exit_once() {
    let (mut service, init, parent, child, mut filesystem, mut processes) = orphan_family();
    let credentials = *service.session(child.process_id).unwrap();
    let directories = *service.session_directories(child.process_id).unwrap();
    let groups = service
        .supplementary_groups(child.process_id)
        .unwrap()
        .to_vec();
    let released = filesystem.released.len();
    processes
        .states
        .insert(141, ProcessLifecycle::Exited { exit_code: 4 });
    assert_eq!(
        service.refresh_child_exit_notifications(&mut processes),
        Ok(1)
    );
    assert_eq!(service.parent_id(child.process_id), Some(init.process_id));
    assert!(service.is_child(init.process_id, child.process_id));
    assert!(!service.is_child(parent.process_id, child.process_id));
    assert_eq!(service.session(child.process_id), Some(&credentials));
    assert_eq!(
        service.session_directories(child.process_id),
        Some(&directories)
    );
    assert_eq!(
        service.supplementary_groups(child.process_id),
        Some(groups.as_slice())
    );
    assert_eq!(filesystem.released.len(), released);
    assert_eq!(service.reap_orphans(&mut filesystem, &mut processes), Ok(0));
    assert!(processes.released.is_empty());
    let wait = protocol::WaitRequest {
        selector: parent.process_id as i64,
        options: 0,
    };
    assert_eq!(
        service
            .wait_child(init, wait, &mut filesystem, &mut processes)
            .unwrap()
            .process_id,
        parent.process_id
    );
    assert_eq!(processes.released, [141]);
    // A failed lifecycle query must retain both the orphan's ProcessHandle and
    // its filesystem objects, rather than treating uncertainty as exit.
    processes.states.remove(&142);
    let released = filesystem.released.len();
    assert_eq!(
        service.reap_orphans(&mut filesystem, &mut processes),
        Err(protocol::STATUS_ESRCH)
    );
    assert!(service.session(child.process_id).is_some());
    assert_eq!(filesystem.released.len(), released);
    processes
        .states
        .insert(142, ProcessLifecycle::Exited { exit_code: 7 });
    assert_eq!(service.reap_orphans(&mut filesystem, &mut processes), Ok(1));
    assert_eq!(service.reap_orphans(&mut filesystem, &mut processes), Ok(0));
    assert_eq!(processes.released, [141, 142]);
    assert!(service.session(child.process_id).is_none());
    assert_eq!(service.parent_id(child.process_id), None);
    assert!(!service.is_child(init.process_id, child.process_id));
    assert_eq!(filesystem.released.len(), released + 2);
    assert!(processes.terminated.is_empty());
}

#[test]
fn immediate_parent_wait_reparents_children_without_needing_a_refresh_first() {
    let (mut service, init, parent, child, mut filesystem, mut processes) = orphan_family();
    processes
        .states
        .insert(141, ProcessLifecycle::Exited { exit_code: 0 });
    service
        .wait_child(
            init,
            protocol::WaitRequest {
                selector: parent.process_id as i64,
                options: 0,
            },
            &mut filesystem,
            &mut processes,
        )
        .unwrap();
    assert_eq!(service.parent_id(child.process_id), Some(init.process_id));
    assert!(service.session(child.process_id).is_some());
    assert_eq!(service.reap_orphans(&mut filesystem, &mut processes), Ok(0));
    assert_eq!(processes.released, [141]);
}

#[test]
fn orphan_reparenting_does_not_change_a_frozen_tree_or_release_its_parent_early() {
    let (mut service, init, parent, child, mut filesystem, mut processes) = orphan_family();
    let root = AuthenticatedProcess {
        handle: 142,
        process_id: child.process_id,
    };
    service
        .begin_launched_tree_termination(init, root, &mut processes)
        .unwrap();
    processes
        .states
        .insert(141, ProcessLifecycle::Exited { exit_code: 0 });
    service
        .refresh_child_exit_notifications(&mut processes)
        .unwrap();
    assert_eq!(service.parent_id(child.process_id), Some(parent.process_id));
    assert_eq!(service.reap_orphans(&mut filesystem, &mut processes), Ok(0));
    let wait = protocol::WaitRequest {
        selector: parent.process_id as i64,
        options: protocol::WAIT_NOHANG,
    };
    assert_eq!(
        service
            .wait_child(init, wait, &mut filesystem, &mut processes)
            .unwrap()
            .process_id,
        0
    );
    assert!(service.wait_handles(init, wait).unwrap().is_empty());
    assert!(service.child_lifecycle_handles().is_empty());
    assert!(service.session(parent.process_id).is_some());
    assert!(processes.released.is_empty());
    service
        .reclaim_launched_tree(init, root, &mut filesystem, &mut processes)
        .unwrap();
    assert_eq!(
        service
            .wait_child(init, wait, &mut filesystem, &mut processes)
            .unwrap()
            .process_id,
        parent.process_id
    );
    assert_eq!(processes.released, [142, 141]);
}

#[test]
fn a_native_root_without_a_posix_parent_still_wakes_orphan_processing() {
    let (mut service, init, _, _, mut filesystem, mut processes) = orphan_family();
    let root = PeerIdentity {
        process_id: 1403,
        effective_uid: 505,
        effective_gid: 24,
    };
    service
        .initialize_process(
            init,
            AuthenticatedProcess {
                handle: 143,
                process_id: root.process_id,
            },
            505,
            24,
            &[52],
        )
        .unwrap();
    service
        .adopt_child(
            root,
            AuthenticatedProcess {
                handle: 144,
                process_id: 1404,
            },
            &mut filesystem,
        )
        .unwrap();
    processes.states.insert(143, ProcessLifecycle::Running);
    processes.states.insert(144, ProcessLifecycle::Running);
    assert!(service.child_lifecycle_handles().contains(&143));
    assert!(!service.child_lifecycle_handles().contains(&140));
    processes
        .states
        .insert(143, ProcessLifecycle::Exited { exit_code: 0 });
    service
        .refresh_child_exit_notifications(&mut processes)
        .unwrap();
    assert_eq!(service.parent_id(1404), Some(init.process_id));
    assert!(!service.child_lifecycle_handles().contains(&143));
    assert!(service.child_lifecycle_handles().contains(&144));
    assert_eq!(service.reap_orphans(&mut filesystem, &mut processes), Ok(0));
    assert!(processes.released.is_empty());
}

#[test]
fn asynchronous_abort_cannot_reparent_or_release_children_before_confirmed_exit() {
    let (mut service, init, parent, child, mut filesystem, mut processes) = orphan_family();
    let root = AuthenticatedProcess {
        handle: 141,
        process_id: parent.process_id,
    };
    processes.termination_pending = true;
    assert_eq!(
        service.abort_launched_child(init, root, &mut filesystem, &mut processes),
        Err(protocol::STATUS_EAGAIN)
    );
    assert_eq!(service.parent_id(child.process_id), Some(parent.process_id));
    assert!(service.session(parent.process_id).is_some());
    assert!(processes.released.is_empty());
    assert!(filesystem.released.is_empty());
    processes
        .states
        .insert(141, ProcessLifecycle::Exited { exit_code: 127 });
    service
        .abort_launched_child(init, root, &mut filesystem, &mut processes)
        .unwrap();
    assert_eq!(service.parent_id(child.process_id), Some(init.process_id));
    assert_eq!(processes.released, [141]);
    assert_eq!(processes.terminated, [(141, 127)]);
    assert_eq!(service.reap_orphans(&mut filesystem, &mut processes), Ok(0));
}

#[test]
fn nocldstop_is_inherited_and_suppresses_only_stop_continue_notifications() {
    let parent = PeerIdentity {
        process_id: 1240,
        effective_uid: 505,
        effective_gid: 24,
    };
    let child = PeerIdentity {
        process_id: 1241,
        ..parent
    };
    let grandchild = PeerIdentity {
        process_id: 1242,
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
    let mut options = [0u8; protocol::SIGNAL_CHILD_OPTIONS_LEN];
    protocol::encode_signal_child_options(
        protocol::SIGNAL_CHILD_OPTION_NOCLDSTOP,
        &mut options,
    )
    .unwrap();
    assert_eq!(
        service
            .handle(
                parent,
                protocol::Header {
                    opcode: protocol::OP_SIGNAL_CHILD_OPTIONS,
                    ..protocol::Header::default()
                },
                &options,
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
                handle: 641,
                process_id: child.process_id,
            },
            &mut filesystem,
        )
        .unwrap();
    service
        .adopt_child(
            child,
            AuthenticatedProcess {
                handle: 642,
                process_id: grandchild.process_id,
            },
            &mut filesystem,
        )
        .unwrap();
    set_own_job_group(&mut service, child);
    set_own_job_group(&mut service, grandchild);
    let mut processes = RecordingProcesses::default();
    processes.states.insert(641, ProcessLifecycle::Running);
    processes.states.insert(642, ProcessLifecycle::Running);
    processes
        .identities
        .extend([(641, child.process_id), (642, grandchild.process_id)]);

    for (sender, target, handle) in [
        (parent, child, 641),
        (child, grandchild, 642),
    ] {
        let delivery = deliver_signal(
            &mut service,
            sender,
            target,
            protocol::SIGNAL_TSTP,
        );
        let mut encoded = [0u8; protocol::SIGNAL_DELIVERY_LEN];
        protocol::encode_signal_delivery(delivery, &mut encoded).unwrap();
        service
            .report_process_stopped(target, &encoded, &mut processes)
            .unwrap();
        assert!(processes.suspended.contains(&handle));
        assert_eq!(
            service.signal_state(sender.process_id).unwrap().pending(),
            0
        );
    }

    send_signal(&mut service, parent, child, protocol::SIGNAL_CONT);
    service.refresh_child_notifications(&mut processes).unwrap();
    assert_eq!(service.signal_state(parent.process_id).unwrap().pending(), 0);

    processes
        .states
        .insert(641, ProcessLifecycle::Exited { exit_code: 0 });
    assert_eq!(
        service.refresh_child_exit_notifications(&mut processes),
        Ok(1)
    );
    assert_eq!(
        service.signal_state(parent.process_id).unwrap().pending(),
        1u64 << (protocol::SIGNAL_CHLD - 1)
    );
}

fn changed_uid_signal_family() -> (PosixService, PeerIdentity, PeerIdentity) {
    let parent = PeerIdentity {
        process_id: 1500,
        effective_uid: 0,
        effective_gid: 0,
    };
    let child = PeerIdentity {
        process_id: 1501,
        effective_uid: 502,
        effective_gid: 20,
    };
    let mut service = service_for(parent);
    service
        .adopt_spawned_child(
            parent,
            AuthenticatedProcess {
                handle: 1501,
                process_id: child.process_id,
            },
            502,
            20,
            &[],
            &mut RecordingFilesystem::default(),
        )
        .unwrap();
    let mut uid = [0u8; 4];
    uid.copy_from_slice(&501u32.to_le_bytes());
    assert_eq!(
        service
            .handle(
                parent,
                protocol::Header {
                    opcode: protocol::OP_SET_UID,
                    ..Default::default()
                },
                &uid
            )
            .header
            .status,
        protocol::STATUS_OK
    );
    // Keep the peer's stale UID zero: authorization must use stored state.
    (service, parent, child)
}

fn signal_request_status(
    service: &mut PosixService,
    sender: PeerIdentity,
    selector: i64,
    signal: u32,
) -> i32 {
    let mut payload = [0; protocol::SIGNAL_SEND_REQUEST_LEN];
    protocol::encode_signal_send_request(
        protocol::SignalSendRequest { selector, signal },
        &mut payload,
    )
    .unwrap();
    service
        .handle(
            sender,
            protocol::Header {
                opcode: protocol::OP_SIGNAL_SEND,
                ..Default::default()
            },
            &payload,
        )
        .header
        .status
}

#[test]
fn same_session_continue_ignores_uid_but_other_signals_do_not() {
    let (mut service, parent, child) = changed_uid_signal_family();
    for signal in [
        0,
        protocol::SIGNAL_HUP,
        protocol::SIGNAL_KILL,
        protocol::SIGNAL_TSTP,
    ] {
        assert_eq!(
            signal_request_status(&mut service, parent, child.process_id as i64, signal),
            protocol::STATUS_EPERM
        );
        assert_eq!(service.signal_state(child.process_id).unwrap().pending(), 0);
        assert!(
            !service
                .process_resume_notification_processes()
                .any(|id| id == child.process_id)
        );
    }
    send_signal(&mut service, parent, child, protocol::SIGNAL_CONT);
    assert_eq!(
        service.signal_state(child.process_id).unwrap().pending(),
        1u64 << (protocol::SIGNAL_CONT - 1)
    );
    assert!(
        service
            .process_resume_notification_processes()
            .any(|id| id == child.process_id)
    );
    assert_eq!(
        service.session(child.process_id).unwrap().effective_uid,
        502
    );
    assert_eq!(
        service.session(parent.process_id).unwrap().effective_uid,
        501
    );
    // The session exception also permits a job to continue its ancestor.
    send_signal(&mut service, child, parent, protocol::SIGNAL_CONT);
    assert_eq!(
        service.signal_state(parent.process_id).unwrap().pending(),
        1u64 << (protocol::SIGNAL_CONT - 1)
    );
}

#[test]
fn continue_session_exception_applies_to_groups_but_not_a_new_session() {
    for selector_kind in 0..4 {
        let (mut service, parent, child) = changed_uid_signal_family();
        let selector = match selector_kind {
            0 => child.process_id as i64,
            1 => 0,
            2 => -(parent.process_id as i64),
            _ => -1,
        };
        assert_eq!(
            signal_request_status(&mut service, parent, selector, protocol::SIGNAL_CONT),
            protocol::STATUS_OK
        );
        assert_eq!(
            service.signal_state(child.process_id).unwrap().pending(),
            1u64 << (protocol::SIGNAL_CONT - 1)
        );
    }
    let (mut service, parent, child) = changed_uid_signal_family();
    assert_eq!(
        service
            .handle(
                child,
                protocol::Header {
                    opcode: protocol::OP_CREATE_SESSION,
                    ..Default::default()
                },
                &[]
            )
            .header
            .status,
        protocol::STATUS_OK
    );
    assert_eq!(
        signal_request_status(
            &mut service,
            parent,
            child.process_id as i64,
            protocol::SIGNAL_CONT
        ),
        protocol::STATUS_EPERM
    );
    assert_eq!(
        signal_request_status(
            &mut service,
            parent,
            -(child.process_id as i64),
            protocol::SIGNAL_CONT
        ),
        protocol::STATUS_EPERM
    );
    // The broadcast succeeds for the caller itself, not the unauthorized job.
    assert_eq!(
        signal_request_status(&mut service, parent, -1, protocol::SIGNAL_CONT),
        protocol::STATUS_OK
    );
    assert_eq!(service.signal_state(child.process_id).unwrap().pending(), 0);
    assert!(
        !service
            .process_resume_notification_processes()
            .any(|id| id == child.process_id)
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
    let mut mask = [0u8; protocol::SIGNAL_THREAD_MASK_LEN];
    protocol::encode_signal_mask_request(
        protocol::SignalMaskRequest {
            operation: protocol::SIGNAL_MASK_INITIALIZE,
            mask: 0,
        },
        &mut mask,
    )
    .unwrap();
    assert_eq!(
        thread_signal_request(service, receiver, protocol::OP_SIGNAL_THREAD_MASK, &mask)
            .header
            .status,
        0
    );
    let response = thread_signal_request(service, receiver, protocol::OP_SIGNAL_THREAD_DEQUEUE, &[]);
    assert_eq!(response.header.status, protocol::STATUS_OK);
    protocol::decode_signal_delivery(&response.payload).unwrap()
}

fn thread_signal_request(
    service: &mut PosixService,
    receiver: PeerIdentity,
    opcode: u16,
    payload: &[u8],
) -> posix_service::Response {
    service.handle_thread_signal_request(
        receiver,
        mnu_abi::ExecutionIdentity {
            process_id: receiver.process_id,
            thread_id: receiver.process_id,
        },
        protocol::Header {
            opcode,
            ..protocol::Header::default()
        },
        payload,
    )
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
    set_own_job_group(&mut service, child);
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
    let child_change = dequeue_signal(&mut service, parent);
    assert_eq!(child_change.signal, protocol::SIGNAL_CHLD);
    let mut child_change_bytes = [0u8; protocol::SIGNAL_DELIVERY_LEN];
    protocol::encode_signal_delivery(child_change, &mut child_change_bytes).unwrap();
    service
        .complete_signal_delivery(parent, &child_change_bytes)
        .unwrap();

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
    service.refresh_child_notifications(&mut processes).unwrap();
    let child_change = dequeue_signal(&mut service, parent);
    assert_eq!(child_change.signal, protocol::SIGNAL_CHLD);
    protocol::encode_signal_delivery(child_change, &mut child_change_bytes).unwrap();
    service
        .complete_signal_delivery(parent, &child_change_bytes)
        .unwrap();
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
    let response = thread_signal_request(&mut service, process, protocol::OP_SIGNAL_THREAD_DEQUEUE, &[]);
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
                terminal_identity(leader),
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
                terminal_identity(member),
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
    let mut processes = RecordingProcesses::default();
    processes.states.insert(142, ProcessLifecycle::Running);
    assert_eq!(
        service
            .handle_process_group_request(
                leader,
                protocol::Header {
                    opcode: protocol::OP_SET_PROCESS_GROUP,
                    ..protocol::Header::default()
                },
                &group_request,
                &[],
                &mut processes,
            )
            .response
            .header
            .status,
        protocol::STATUS_OK
    );
    let mut foreground = [0u8; protocol::PROCESS_ID_REQUEST_LEN];
    protocol::encode_process_id_request(142, &mut foreground).unwrap();
    assert_eq!(
        service
            .handle_terminal(
                leader,
                terminal_identity(leader),
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
        terminal_identity(leader),
        terminal_request(protocol::OP_TERMINAL_GET_FOREGROUND),
        &[],
        77,
    );
    assert_eq!(response.header.status, protocol::STATUS_OK);
    assert_eq!(
        protocol::decode_process_id_request(&response.payload),
        Ok(142)
    );
    for caller in [leader, member] {
        let response = service.handle_terminal(
            caller,
            terminal_identity(caller),
            terminal_request(protocol::OP_TERMINAL_GET_SESSION),
            &[],
            77,
        );
        assert_eq!(response.header.status, protocol::STATUS_OK);
        assert_eq!(
            protocol::decode_process_id_request(&response.payload),
            Ok(141)
        );
        for (flags, payload) in [(1, &[][..]), (0, &[1][..])] {
            let response = service.handle_terminal(
                caller,
                terminal_identity(caller),
                protocol::Header {
                    flags,
                    ..terminal_request(protocol::OP_TERMINAL_GET_SESSION)
                },
                payload,
                77,
            );
            assert_eq!(response.header.status, STATUS_EINVAL);
        }
        let response = service.handle_terminal(
            caller,
            mnu_abi::ExecutionIdentity {
                process_id: 999,
                thread_id: 1,
            },
            terminal_request(protocol::OP_TERMINAL_GET_SESSION),
            &[],
            77,
        );
        assert_eq!(response.header.status, protocol::STATUS_EPERM);
    }
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
    for opcode in [protocol::OP_TERMINAL_GET_FOREGROUND, protocol::OP_TERMINAL_GET_SESSION] {
        assert_eq!(
            service
                .handle_terminal(
                    other_leader,
                    terminal_identity(other_leader),
                    terminal_request(opcode),
                    &[],
                    77,
                )
                .header
                .status,
            protocol::STATUS_ENOTTY
        );
    }
    assert_eq!(
        service
            .handle_terminal(
                other_leader,
                terminal_identity(other_leader),
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
                terminal_identity(member),
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
                terminal_identity(leader),
                terminal_request(protocol::OP_TERMINAL_RELEASE),
                &[],
                77,
            )
            .header
            .status,
        protocol::STATUS_OK
    );
    assert!(service.controlling_terminal(77).is_none());
    for (caller, terminal) in [(leader, 77), (member, 77), (leader, 999), (other_leader, 77)] {
        let response = service.handle_terminal(
            caller,
            terminal_identity(caller),
            terminal_request(protocol::OP_TERMINAL_GET_SESSION),
            &[],
            terminal,
        );
        assert_eq!(response.header.status, protocol::STATUS_ENOTTY);
    }
}

fn terminal_exit_family() -> (
    PosixService,
    [PeerIdentity; 5],
    RecordingFilesystem,
    RecordingProcesses,
) {
    let peers = [4100, 4101, 4102, 4103, 4104].map(|process_id| PeerIdentity {
        process_id,
        effective_uid: 505,
        effective_gid: 24,
    });
    let [parent, leader, first, second, background] = peers;
    let mut service = service_for(parent);
    let mut filesystem = RecordingFilesystem::default();
    service
        .adopt_child(
            parent,
            AuthenticatedProcess {
                handle: leader.process_id as u32,
                process_id: leader.process_id,
            },
            &mut filesystem,
        )
        .unwrap();
    let header = |opcode| protocol::Header {
        opcode,
        ..Default::default()
    };
    assert_eq!(
        service
            .handle(leader, header(protocol::OP_CREATE_SESSION), &[])
            .header
            .status,
        0
    );
    for child in [first, second, background] {
        service
            .adopt_child(
                leader,
                AuthenticatedProcess {
                    handle: child.process_id as u32,
                    process_id: child.process_id,
                },
                &mut filesystem,
            )
            .unwrap();
    }
    let mut processes = RecordingProcesses::default();
    for peer in peers {
        processes
            .states
            .insert(peer.process_id as u32, ProcessLifecycle::Running);
    }
    for child in [first, second] {
        let mut group = [0; protocol::PROCESS_GROUP_REQUEST_LEN];
        protocol::encode_process_group_request(
            child.process_id as i64,
            first.process_id as i64,
            &mut group,
        )
        .unwrap();
        assert_eq!(
            service
                .handle_process_group_request(
                    leader,
                    header(protocol::OP_SET_PROCESS_GROUP),
                    &group,
                    &[],
                    &mut processes,
                )
                .response
                .header
                .status,
            0
        );
    }
    assert_eq!(
        service
            .handle_terminal(leader, terminal_identity(leader), header(protocol::OP_TERMINAL_ACQUIRE), &[], 77)
            .header
            .status,
        0
    );
    let mut group = [0; protocol::PROCESS_ID_REQUEST_LEN];
    protocol::encode_process_id_request(first.process_id as i64, &mut group).unwrap();
    assert_eq!(
        service
            .handle_terminal(
                leader,
                terminal_identity(leader),
                header(protocol::OP_TERMINAL_SET_FOREGROUND),
                &group,
                77
            )
            .header
            .status,
        0
    );
    (service, peers, filesystem, processes)
}

#[test]
fn master_close_hangs_up_the_controller_before_controller_exit_hangs_up_the_job() {
    let (mut service, [_, controller, first, second, background], _, mut processes) =
        terminal_exit_family();
    let mut ptys = posix_service::pty::PtyManager::new();
    let pair = ptys.open().unwrap();
    let terminal_id = ptys.slave_terminal_id(pair.slave_object_id).unwrap();
    assert_eq!(
        service
            .handle_terminal(
                controller,
                terminal_identity(controller),
                protocol::Header {
                    opcode: protocol::OP_TERMINAL_RELEASE,
                    ..Default::default()
                },
                &[],
                77
            )
            .header
            .status,
        0
    );
    assert_eq!(
        service
            .handle_terminal(
                controller,
                terminal_identity(controller),
                protocol::Header {
                    opcode: protocol::OP_TERMINAL_ACQUIRE,
                    ..Default::default()
                },
                &[],
                terminal_id
            )
            .header
            .status,
        0
    );
    let mut group = [0; protocol::PROCESS_ID_REQUEST_LEN];
    protocol::encode_process_id_request(first.process_id as i64, &mut group).unwrap();
    assert_eq!(
        service
            .handle_terminal(
                controller,
                terminal_identity(controller),
                protocol::Header {
                    opcode: protocol::OP_TERMINAL_SET_FOREGROUND,
                    ..Default::default()
                },
                &group,
                terminal_id
            )
            .header
            .status,
        0
    );
    ptys.release(pair.master_object_id).unwrap();
    let event = ptys.take_terminal_signal().unwrap();
    assert_eq!(event.signal, protocol::SIGNAL_HUP);
    service.hangup_terminal(event.terminal_id).unwrap();
    let delivery = dequeue_signal(&mut service, controller);
    assert_eq!(delivery.signal, protocol::SIGNAL_HUP);
    for member in [first, second, background] {
        assert_eq!(
            service.signal_state(member.process_id).unwrap().pending(),
            0
        );
    }
    assert!(service.controlling_terminal(terminal_id).is_some());
    assert_eq!(service.hangup_terminal(999), Err(protocol::STATUS_ENOTTY));
    processes.states.insert(
        controller.process_id as u32,
        ProcessLifecycle::Exited { exit_code: 129 },
    );
    service
        .refresh_child_exit_notifications(&mut processes)
        .unwrap();
    assert!(service.controlling_terminal(terminal_id).is_none());
    for member in [first, second] {
        assert_eq!(
            dequeue_signal(&mut service, member).signal,
            protocol::SIGNAL_HUP
        );
    }
    assert_eq!(
        service
            .signal_state(background.process_id)
            .unwrap()
            .pending(),
        0
    );
    assert_eq!(ptys.take_terminal_signal(), None);
}

fn terminal_mask(service: &mut PosixService, caller: PeerIdentity, thread: u64, mask: u64) {
    let mut bytes = [0; protocol::SIGNAL_THREAD_MASK_LEN];
    protocol::encode_signal_mask_request(
        protocol::SignalMaskRequest {
            operation: protocol::SIGNAL_MASK_SET,
            mask,
        },
        &mut bytes,
    )
    .unwrap();
    assert_eq!(
        service
            .handle_thread_signal_request(
                caller,
                mnu_abi::ExecutionIdentity {
                    process_id: caller.process_id,
                    thread_id: thread
                },
                protocol::Header {
                    opcode: protocol::OP_SIGNAL_THREAD_MASK,
                    ..Default::default()
                },
                &bytes,
            )
            .header
            .status,
        0
    );
}

fn request_foreground(
    service: &mut PosixService,
    caller: PeerIdentity,
    sender: mnu_abi::ExecutionIdentity,
    group: u64,
) -> i32 {
    let mut bytes = [0; protocol::PROCESS_ID_REQUEST_LEN];
    protocol::encode_process_id_request(group as i64, &mut bytes).unwrap();
    service
        .handle_terminal(
            caller,
            sender,
            protocol::Header {
                opcode: protocol::OP_TERMINAL_SET_FOREGROUND,
                ..Default::default()
            },
            &bytes,
            77,
        )
        .header
        .status
}

#[test]
fn background_tcsetpgrp_signals_the_whole_group_without_changing_foreground() {
    let (mut service, [_, leader, first, second, background], _, mut processes) =
        terminal_exit_family();
    set_own_job_group(&mut service, background);
    let mut bytes = [0; protocol::PROCESS_GROUP_REQUEST_LEN];
    protocol::encode_process_group_request(
        second.process_id as i64,
        background.process_id as i64,
        &mut bytes,
    )
    .unwrap();
    assert_eq!(
        service
            .handle_process_group_request(
                leader,
                protocol::Header {
                    opcode: protocol::OP_SET_PROCESS_GROUP,
                    ..Default::default()
                },
                &bytes,
                &[],
                &mut processes,
            )
            .response
            .header
            .status,
        0
    );
    terminal_mask(&mut service, background, 1, 0);
    assert_eq!(
        request_foreground(
            &mut service,
            background,
            terminal_identity(background),
            background.process_id
        ),
        protocol::STATUS_EINTR
    );
    assert_eq!(
        service
            .controlling_terminal(77)
            .unwrap()
            .foreground_process_group,
        first.process_id
    );
    for member in [background, second] {
        assert_eq!(
            service.signal_state(member.process_id).unwrap().pending(),
            1 << (protocol::SIGNAL_TTOU - 1)
        );
    }
    assert_eq!(service.signal_state(first.process_id).unwrap().pending(), 0);
    assert_eq!(
        service.signal_state(leader.process_id).unwrap().pending(),
        0
    );
}

#[test]
fn tcsetpgrp_uses_calling_thread_mask_and_never_another_threads_exemption() {
    let (mut service, [_, _, first, _, background], _, _) = terminal_exit_family();
    set_own_job_group(&mut service, background);
    terminal_mask(
        &mut service,
        background,
        2,
        1 << (protocol::SIGNAL_TTOU - 1),
    );
    assert_eq!(
        request_foreground(
            &mut service,
            background,
            terminal_identity(background),
            background.process_id
        ),
        protocol::STATUS_ESRCH
    );
    terminal_mask(&mut service, background, 1, 0);
    assert_eq!(
        request_foreground(
            &mut service,
            background,
            terminal_identity(background),
            background.process_id
        ),
        protocol::STATUS_EINTR
    );
    assert_eq!(
        service
            .controlling_terminal(77)
            .unwrap()
            .foreground_process_group,
        first.process_id
    );
    let sender = mnu_abi::ExecutionIdentity {
        process_id: background.process_id,
        thread_id: 2,
    };
    assert_eq!(
        request_foreground(&mut service, background, sender, background.process_id),
        0
    );
    assert_eq!(
        service
            .controlling_terminal(77)
            .unwrap()
            .foreground_process_group,
        background.process_id
    );
}

#[test]
fn orphaned_background_tcsetpgrp_fails_without_sending_a_stop_signal() {
    let (mut service, [_, leader, first, _, _], _, _) = terminal_exit_family();
    terminal_mask(&mut service, leader, 1, 0);
    assert_eq!(
        request_foreground(
            &mut service,
            leader,
            terminal_identity(leader),
            leader.process_id
        ),
        protocol::STATUS_EIO
    );
    assert_eq!(
        service.signal_state(leader.process_id).unwrap().pending(),
        0
    );
    assert_eq!(
        service
            .controlling_terminal(77)
            .unwrap()
            .foreground_process_group,
        first.process_id
    );
    // Blocking SIGTTOU permits the operation even in an orphaned group.
    terminal_mask(&mut service, leader, 1, 1 << (protocol::SIGNAL_TTOU - 1));
    assert_eq!(
        request_foreground(
            &mut service,
            leader,
            terminal_identity(leader),
            leader.process_id
        ),
        0
    );
}

#[test]
fn ignoring_ttou_permits_background_tcsetpgrp_but_forged_identity_never_does() {
    let (mut service, [_, leader, first, _, _], _, _) = terminal_exit_family();
    let mut bytes = [0; protocol::SIGNAL_DISPOSITION_LEN];
    protocol::encode_signal_disposition(
        protocol::SignalDisposition {
            signal: protocol::SIGNAL_TTOU,
            kind: protocol::SIGNAL_DISPOSITION_IGNORE,
            child_options: 0,
        },
        &mut bytes,
    )
    .unwrap();
    assert_eq!(
        service
            .handle(
                leader,
                protocol::Header {
                    opcode: protocol::OP_SIGNAL_DISPOSITION,
                    flags: protocol::SIGNAL_DISPOSITION_SET,
                    ..Default::default()
                },
                &bytes
            )
            .header
            .status,
        0
    );
    assert_eq!(
        request_foreground(
            &mut service,
            leader,
            terminal_identity(first),
            leader.process_id
        ),
        protocol::STATUS_EPERM
    );
    assert_eq!(
        request_foreground(
            &mut service,
            leader,
            mnu_abi::ExecutionIdentity {
                process_id: leader.process_id,
                thread_id: 0
            },
            leader.process_id
        ),
        protocol::STATUS_EPERM
    );
    assert_eq!(
        service
            .controlling_terminal(77)
            .unwrap()
            .foreground_process_group,
        first.process_id
    );
    assert_eq!(
        request_foreground(
            &mut service,
            leader,
            terminal_identity(leader),
            leader.process_id
        ),
        0
    );
    assert_eq!(
        service.signal_state(leader.process_id).unwrap().pending(),
        0
    );
}

#[test]
fn background_terminal_read_signals_ttin_and_blocking_it_returns_eio() {
    let (mut service, [_, _, first, _, background], _, _) = terminal_exit_family();
    set_own_job_group(&mut service, background);
    terminal_mask(&mut service, background, 1, 0);
    assert_eq!(
        service.authorize_terminal_io(terminal_identity(background), 77, true, false),
        Err(protocol::STATUS_EINTR)
    );
    assert_eq!(
        service
            .signal_state(background.process_id)
            .unwrap()
            .pending(),
        1 << (protocol::SIGNAL_TTIN - 1)
    );
    terminal_mask(
        &mut service,
        background,
        2,
        1 << (protocol::SIGNAL_TTIN - 1),
    );
    assert_eq!(
        service.authorize_terminal_io(
            mnu_abi::ExecutionIdentity {
                process_id: background.process_id,
                thread_id: 2,
            },
            77,
            true,
            false
        ),
        Err(protocol::STATUS_EIO)
    );
    assert_eq!(
        service.authorize_terminal_io(terminal_identity(first), 77, true, true),
        Ok(())
    );
}

#[test]
fn terminal_write_tostop_and_orphan_exemptions_do_not_apply_to_reads() {
    let (mut service, [_, leader, _, _, background], _, _) = terminal_exit_family();
    set_own_job_group(&mut service, background);
    terminal_mask(&mut service, background, 1, 0);
    assert_eq!(
        service.authorize_terminal_io(terminal_identity(background), 77, false, false),
        Ok(())
    );
    assert_eq!(
        service
            .signal_state(background.process_id)
            .unwrap()
            .pending(),
        0
    );
    assert_eq!(
        service.authorize_terminal_io(terminal_identity(background), 77, false, true),
        Err(protocol::STATUS_EINTR)
    );
    terminal_mask(&mut service, leader, 1, 0);
    for reading in [true, false] {
        assert_eq!(
            service.authorize_terminal_io(terminal_identity(leader), 77, reading, true),
            Err(protocol::STATUS_EIO)
        );
    }
    assert_eq!(
        service.signal_state(leader.process_id).unwrap().pending(),
        0
    );
    terminal_mask(
        &mut service,
        leader,
        1,
        (1 << (protocol::SIGNAL_TTIN - 1)) | (1 << (protocol::SIGNAL_TTOU - 1)),
    );
    assert_eq!(
        service.authorize_terminal_io(terminal_identity(leader), 77, false, true),
        Ok(())
    );
    assert_eq!(
        service.authorize_terminal_io(terminal_identity(leader), 77, true, true),
        Err(protocol::STATUS_EIO)
    );
}

#[test]
fn ignored_ttin_is_eio_and_other_delegated_terminals_are_not_controlling_terminals() {
    let (mut service, [parent, leader, _, _, background], _, _) = terminal_exit_family();
    let mut bytes = [0; protocol::SIGNAL_DISPOSITION_LEN];
    protocol::encode_signal_disposition(
        protocol::SignalDisposition {
            signal: protocol::SIGNAL_TTIN,
            kind: protocol::SIGNAL_DISPOSITION_IGNORE,
            child_options: 0,
        },
        &mut bytes,
    )
    .unwrap();
    assert_eq!(
        service
            .handle(
                background,
                protocol::Header {
                    opcode: protocol::OP_SIGNAL_DISPOSITION,
                    flags: protocol::SIGNAL_DISPOSITION_SET,
                    ..Default::default()
                },
                &bytes
            )
            .header
            .status,
        0
    );
    assert_eq!(
        service.authorize_terminal_io(terminal_identity(background), 77, true, false),
        Err(protocol::STATUS_EIO)
    );
    assert_eq!(
        service
            .signal_state(background.process_id)
            .unwrap()
            .pending(),
        0
    );
    assert_eq!(
        service.authorize_terminal_io(terminal_identity(parent), 77, true, true),
        Ok(())
    );
    assert_eq!(
        service.authorize_terminal_io(terminal_identity(leader), 999, true, true),
        Ok(())
    );
    assert_eq!(
        service.authorize_terminal_io(
            mnu_abi::ExecutionIdentity {
                process_id: 0,
                thread_id: 1
            },
            77,
            true,
            true
        ),
        Err(protocol::STATUS_EPERM)
    );
}

fn orphan_job_family() -> (
    PosixService,
    [PeerIdentity; 5],
    RecordingFilesystem,
    RecordingProcesses,
) {
    let (mut service, peers, filesystem, processes) = terminal_exit_family();
    // Isolate orphan-group policy from controlling-terminal hangup policy.
    assert_eq!(
        service
            .handle_terminal(
                peers[1],
                terminal_identity(peers[1]),
                protocol::Header {
                    opcode: protocol::OP_TERMINAL_RELEASE,
                    ..Default::default()
                },
                &[],
                77
            )
            .header
            .status,
        0
    );
    (service, peers, filesystem, processes)
}

fn set_own_job_group(service: &mut PosixService, member: PeerIdentity) {
    let mut group = [0; protocol::PROCESS_GROUP_REQUEST_LEN];
    protocol::encode_process_group_request(0, 0, &mut group).unwrap();
    assert_eq!(
        service
            .handle(
                member,
                protocol::Header {
                    opcode: protocol::OP_SET_PROCESS_GROUP,
                    ..Default::default()
                },
                &group
            )
            .header
            .status,
        0
    );
}

fn stop_job_member(
    service: &mut PosixService,
    parent: PeerIdentity,
    member: PeerIdentity,
    processes: &mut RecordingProcesses,
) {
    let delivery = deliver_signal(service, parent, member, protocol::SIGNAL_STOP);
    let mut bytes = [0; protocol::SIGNAL_DELIVERY_LEN];
    protocol::encode_signal_delivery(delivery, &mut bytes).unwrap();
    service
        .report_process_stopped(member, &bytes, processes)
        .unwrap();
}

fn consume_job_hangup_and_continue(service: &mut PosixService, member: PeerIdentity) {
    for signal in [protocol::SIGNAL_HUP, protocol::SIGNAL_CONT] {
        let delivery = dequeue_signal(service, member);
        assert_eq!(delivery.signal, signal);
        let mut bytes = [0; protocol::SIGNAL_DELIVERY_LEN];
        protocol::encode_signal_delivery(delivery, &mut bytes).unwrap();
        service.complete_signal_delivery(member, &bytes).unwrap();
    }
}

#[test]
fn orphaned_groups_discard_default_terminal_stops_but_not_delivery_or_sigstop() {
    let (mut service, [_, parent, _, _, member], mut filesystem, mut processes) =
        orphan_job_family();
    for signal in [
        protocol::SIGNAL_TSTP,
        protocol::SIGNAL_TTIN,
        protocol::SIGNAL_TTOU,
    ] {
        let delivery = deliver_signal(&mut service, parent, member, signal);
        assert_eq!(delivery.signal, signal);
        let mut bytes = [0; protocol::SIGNAL_DELIVERY_LEN];
        protocol::encode_signal_delivery(delivery, &mut bytes).unwrap();
        // Handler delivery is not filtered; completing it remains legal.
        service.complete_signal_delivery(member, &bytes).unwrap();
        let delivery = deliver_signal(&mut service, parent, member, signal);
        for forged in [
            protocol::SignalDelivery {
                token: delivery.token + 1,
                ..delivery
            },
            protocol::SignalDelivery {
                signal: protocol::SIGNAL_STOP,
                ..delivery
            },
        ] {
            protocol::encode_signal_delivery(forged, &mut bytes).unwrap();
            assert_eq!(
                service.report_process_stopped(member, &bytes, &mut processes),
                Err(protocol::STATUS_EAGAIN)
            );
        }
        protocol::encode_signal_delivery(delivery, &mut bytes).unwrap();
        // Even a backend failure must be irrelevant when no stop is allowed.
        processes.suspend_error = Some(-5);
        assert_eq!(
            service.report_process_stopped(member, &bytes, &mut processes),
            Ok(())
        );
        assert_eq!(
            service.report_process_stopped(member, &bytes, &mut processes),
            Err(protocol::STATUS_EAGAIN)
        );
        assert_eq!(
            service.complete_signal_delivery(member, &bytes),
            Err(protocol::STATUS_EAGAIN)
        );
        assert!(processes.suspended.is_empty());
        assert_eq!(
            service.signal_state(parent.process_id).unwrap().pending(),
            0
        );
        assert_eq!(
            service
                .wait_child(
                    parent,
                    protocol::WaitRequest {
                        selector: member.process_id as i64,
                        options: protocol::WAIT_NOHANG | protocol::WAIT_UNTRACED,
                    },
                    &mut filesystem,
                    &mut processes
                )
                .unwrap(),
            protocol::WaitResult::default()
        );
    }
    processes.suspend_error = None;
    stop_job_member(&mut service, parent, member, &mut processes);
    assert_eq!(processes.suspended, [member.process_id as u32]);
    let stopped = service
        .wait_child(
            parent,
            protocol::WaitRequest {
                selector: member.process_id as i64,
                options: protocol::WAIT_NOHANG | protocol::WAIT_UNTRACED,
            },
            &mut filesystem,
            &mut processes,
        )
        .unwrap();
    assert_eq!(stopped.status, (protocol::SIGNAL_STOP << 8) | 0x7f);
}

#[test]
fn connected_jobs_can_stop_for_all_three_catchable_job_control_signals() {
    let (mut service, [_, parent, member, _, _], mut filesystem, mut processes) =
        orphan_job_family();
    for signal in [
        protocol::SIGNAL_TSTP,
        protocol::SIGNAL_TTIN,
        protocol::SIGNAL_TTOU,
    ] {
        let delivery = deliver_signal(&mut service, parent, member, signal);
        let mut bytes = [0; protocol::SIGNAL_DELIVERY_LEN];
        protocol::encode_signal_delivery(delivery, &mut bytes).unwrap();
        service
            .report_process_stopped(member, &bytes, &mut processes)
            .unwrap();
        let stopped = service
            .wait_child(
                parent,
                protocol::WaitRequest {
                    selector: member.process_id as i64,
                    options: protocol::WAIT_NOHANG | protocol::WAIT_UNTRACED,
                },
                &mut filesystem,
                &mut processes,
            )
            .unwrap();
        assert_eq!(stopped.status, (signal << 8) | 0x7f);
        let continued = deliver_signal(&mut service, parent, member, protocol::SIGNAL_CONT);
        protocol::encode_signal_delivery(continued, &mut bytes).unwrap();
        service.complete_signal_delivery(member, &bytes).unwrap();
    }
    assert_eq!(processes.suspended, [member.process_id as u32; 3]);
}

#[test]
fn default_stop_rechecks_group_connection_after_signal_dequeue() {
    for initially_connected in [false, true] {
        let (mut service, [_, parent, member, _, _], _, mut processes) = orphan_job_family();
        let mut group = [0; protocol::PROCESS_GROUP_REQUEST_LEN];
        if !initially_connected {
            protocol::encode_process_group_request(0, parent.process_id as i64, &mut group)
                .unwrap();
            assert_eq!(
                service
                    .handle(
                        member,
                        protocol::Header {
                            opcode: protocol::OP_SET_PROCESS_GROUP,
                            ..Default::default()
                        },
                        &group
                    )
                    .header
                    .status,
                0
            );
        }
        let delivery = deliver_signal(&mut service, parent, member, protocol::SIGNAL_TSTP);
        if initially_connected {
            protocol::encode_process_group_request(0, parent.process_id as i64, &mut group)
                .unwrap();
            assert_eq!(
                service
                    .handle(
                        member,
                        protocol::Header {
                            opcode: protocol::OP_SET_PROCESS_GROUP,
                            ..Default::default()
                        },
                        &group
                    )
                    .header
                    .status,
                0
            );
        } else {
            set_own_job_group(&mut service, member);
        }
        let mut bytes = [0; protocol::SIGNAL_DELIVERY_LEN];
        protocol::encode_signal_delivery(delivery, &mut bytes).unwrap();
        service
            .report_process_stopped(member, &bytes, &mut processes)
            .unwrap();
        assert_eq!(
            processes.suspended,
            if initially_connected {
                vec![]
            } else {
                vec![member.process_id as u32]
            }
        );
        assert_eq!(
            service.report_process_stopped(member, &bytes, &mut processes),
            Err(protocol::STATUS_EAGAIN)
        );
    }
}

#[test]
fn parent_exit_continues_the_whole_newly_orphaned_job_once_without_reaping_it() {
    let (mut service, [init, parent, first, second, background], mut filesystem, mut processes) =
        orphan_job_family();
    stop_job_member(&mut service, parent, first, &mut processes);
    assert_eq!(
        service.refresh_child_exit_notifications(&mut processes),
        Ok(0)
    );
    processes.states.remove(&(parent.process_id as u32));
    assert_eq!(
        service.refresh_child_exit_notifications(&mut processes),
        Err(-3)
    );
    assert_eq!(service.signal_state(first.process_id).unwrap().pending(), 0);
    assert!(
        service
            .process_resume_notification_processes()
            .next()
            .is_none()
    );
    processes.states.insert(
        parent.process_id as u32,
        ProcessLifecycle::Exited { exit_code: 0 },
    );
    assert_eq!(
        service.refresh_child_exit_notifications(&mut processes),
        Ok(1)
    );
    for member in [first, second] {
        assert_eq!(service.parent_id(member.process_id), Some(init.process_id));
        consume_job_hangup_and_continue(&mut service, member);
    }
    assert_eq!(
        service
            .signal_state(background.process_id)
            .unwrap()
            .pending(),
        0
    );
    assert_eq!(
        service
            .process_resume_notification_processes()
            .collect::<Vec<_>>(),
        [first.process_id, second.process_id]
    );
    assert!(processes.released.is_empty());
    assert!(processes.terminated.is_empty());
    let continued = service
        .wait_child(
            init,
            protocol::WaitRequest {
                selector: first.process_id as i64,
                options: protocol::WAIT_NOHANG | protocol::WAIT_CONTINUED,
            },
            &mut filesystem,
            &mut processes,
        )
        .unwrap();
    assert_eq!(
        (continued.process_id, continued.status),
        (first.process_id, protocol::WAIT_STATUS_CONTINUED)
    );
    assert_eq!(
        service.refresh_child_exit_notifications(&mut processes),
        Ok(0)
    );
    for member in [first, second] {
        assert_eq!(
            service.signal_state(member.process_id).unwrap().pending(),
            0
        );
    }
}

#[test]
fn immediate_wait_applies_orphan_job_policy_without_a_lifecycle_refresh() {
    let (mut service, [init, parent, first, second, _], mut filesystem, mut processes) =
        orphan_job_family();
    stop_job_member(&mut service, parent, first, &mut processes);
    processes.states.insert(
        parent.process_id as u32,
        ProcessLifecycle::Exited { exit_code: 0 },
    );
    service
        .wait_child(
            init,
            protocol::WaitRequest {
                selector: parent.process_id as i64,
                options: 0,
            },
            &mut filesystem,
            &mut processes,
        )
        .unwrap();
    for member in [first, second] {
        consume_job_hangup_and_continue(&mut service, member);
    }
    assert_eq!(processes.released, [parent.process_id as u32]);
}

#[test]
fn another_live_parent_keeps_the_job_connected_until_its_own_exit() {
    let (mut service, [_, parent, first, second, connector], mut filesystem, mut processes) =
        orphan_job_family();
    let third = PeerIdentity {
        process_id: 4105,
        ..connector
    };
    service
        .adopt_child(
            connector,
            AuthenticatedProcess {
                handle: 4105,
                process_id: third.process_id,
            },
            &mut filesystem,
        )
        .unwrap();
    let mut group = [0; protocol::PROCESS_GROUP_REQUEST_LEN];
    protocol::encode_process_group_request(
        third.process_id as i64,
        first.process_id as i64,
        &mut group,
    )
    .unwrap();
    processes.states.insert(4105, ProcessLifecycle::Running);
    assert_eq!(
        service
            .handle_process_group_request(
                connector,
                protocol::Header {
                    opcode: protocol::OP_SET_PROCESS_GROUP,
                    ..Default::default()
                },
                &group,
                &[],
                &mut processes,
            )
            .response
            .header
            .status,
        0
    );
    processes.states.insert(4105, ProcessLifecycle::Running);
    stop_job_member(&mut service, parent, first, &mut processes);
    processes.states.insert(
        parent.process_id as u32,
        ProcessLifecycle::Exited { exit_code: 0 },
    );
    service
        .refresh_child_exit_notifications(&mut processes)
        .unwrap();
    for member in [first, second, third] {
        assert_eq!(
            service.signal_state(member.process_id).unwrap().pending(),
            0
        );
    }
    assert!(
        service
            .process_resume_notification_processes()
            .next()
            .is_none()
    );
    processes.states.insert(
        connector.process_id as u32,
        ProcessLifecycle::Exited { exit_code: 0 },
    );
    service
        .refresh_child_exit_notifications(&mut processes)
        .unwrap();
    for member in [first, second, third] {
        consume_job_hangup_and_continue(&mut service, member);
    }
}

#[test]
fn running_jobs_and_groups_already_orphaned_are_not_hung_up_on_parent_exit() {
    let (mut service, [_, parent, first, second, background], _, mut processes) =
        orphan_job_family();
    // This member is already in its parent's group, so that group was already
    // orphaned. Its stop must not cause unrelated running groups to hang up.
    stop_job_member(&mut service, parent, background, &mut processes);
    processes.states.insert(
        parent.process_id as u32,
        ProcessLifecycle::Exited { exit_code: 0 },
    );
    service
        .refresh_child_exit_notifications(&mut processes)
        .unwrap();
    for member in [first, second, background] {
        assert_eq!(
            service.signal_state(member.process_id).unwrap().pending(),
            0
        );
    }
    assert!(
        service
            .process_resume_notification_processes()
            .next()
            .is_none()
    );
}

#[test]
fn an_exited_parent_is_not_a_job_control_connection_even_with_frozen_links() {
    let (mut service, init, parent, child, _, mut processes) = orphan_family();
    let mut group = [0; protocol::PROCESS_GROUP_REQUEST_LEN];
    protocol::encode_process_group_request(0, 0, &mut group).unwrap();
    assert_eq!(
        service
            .handle(
                child,
                protocol::Header {
                    opcode: protocol::OP_SET_PROCESS_GROUP,
                    ..Default::default()
                },
                &group
            )
            .header
            .status,
        0
    );
    stop_job_member(&mut service, parent, child, &mut processes);
    processes.termination_pending = true;
    assert_eq!(
        service.begin_launched_tree_termination(
            init,
            AuthenticatedProcess {
                handle: 142,
                process_id: child.process_id,
            },
            &mut processes,
        ),
        Err(protocol::STATUS_EAGAIN)
    );
    processes
        .states
        .insert(141, ProcessLifecycle::Exited { exit_code: 0 });
    service
        .refresh_child_exit_notifications(&mut processes)
        .unwrap();
    assert_eq!(service.parent_id(child.process_id), Some(parent.process_id));
    assert!(processes.released.is_empty());
    consume_job_hangup_and_continue(&mut service, child);
    assert_eq!(
        service
            .process_resume_notification_processes()
            .collect::<Vec<_>>(),
        [child.process_id]
    );
    assert_eq!(
        service.refresh_child_exit_notifications(&mut processes),
        Ok(0)
    );
    assert_eq!(service.signal_state(child.process_id).unwrap().pending(), 0);
}

#[test]
fn controlling_process_exit_hangs_up_only_foreground_members_once_before_wait() {
    let (mut service, [parent, leader, first, second, background], mut filesystem, mut processes) =
        terminal_exit_family();
    assert_eq!(
        service.refresh_child_exit_notifications(&mut processes),
        Ok(0)
    );
    assert!(service.controlling_terminal(77).is_some());
    assert_eq!(service.signal_state(first.process_id).unwrap().pending(), 0);
    processes.states.remove(&(leader.process_id as u32));
    assert_eq!(
        service.refresh_child_exit_notifications(&mut processes),
        Err(-3)
    );
    assert!(service.controlling_terminal(77).is_some());
    assert_eq!(service.signal_state(first.process_id).unwrap().pending(), 0);
    processes.states.insert(
        leader.process_id as u32,
        ProcessLifecycle::Exited { exit_code: 0 },
    );
    assert_eq!(
        service.refresh_child_exit_notifications(&mut processes),
        Ok(1)
    );
    assert!(service.controlling_terminal(77).is_none());
    assert!(processes.released.is_empty());
    for peer in [first, second] {
        assert_eq!(
            dequeue_signal(&mut service, peer).signal,
            protocol::SIGNAL_HUP
        );
    }
    for peer in [leader, background] {
        assert_eq!(service.signal_state(peer.process_id).unwrap().pending(), 0);
    }
    assert_eq!(
        service.refresh_child_exit_notifications(&mut processes),
        Ok(0)
    );
    for peer in [first, second] {
        assert_eq!(service.signal_state(peer.process_id).unwrap().pending(), 0);
    }
    assert_eq!(
        service
            .wait_child(
                parent,
                protocol::WaitRequest {
                    selector: leader.process_id as i64,
                    options: 0,
                },
                &mut filesystem,
                &mut processes
            )
            .unwrap()
            .process_id,
        leader.process_id
    );
    assert_eq!(processes.released, [leader.process_id as u32]);
    for peer in [first, second] {
        assert_eq!(service.signal_state(peer.process_id).unwrap().pending(), 0);
    }
    // The terminal is reusable immediately, without waiting for old members.
    assert_eq!(
        service
            .handle_terminal(
                parent,
                terminal_identity(parent),
                protocol::Header {
                    opcode: protocol::OP_TERMINAL_ACQUIRE,
                    ..Default::default()
                },
                &[],
                77
            )
            .header
            .status,
        0
    );
}

#[test]
fn direct_wait_also_applies_controlling_process_exit_policy() {
    let (mut service, [parent, leader, first, second, background], mut filesystem, mut processes) =
        terminal_exit_family();
    processes.states.insert(
        leader.process_id as u32,
        ProcessLifecycle::Exited { exit_code: 0 },
    );
    service
        .wait_child(
            parent,
            protocol::WaitRequest {
                selector: leader.process_id as i64,
                options: 0,
            },
            &mut filesystem,
            &mut processes,
        )
        .unwrap();
    assert!(service.controlling_terminal(77).is_none());
    for peer in [first, second] {
        assert_eq!(
            dequeue_signal(&mut service, peer).signal,
            protocol::SIGNAL_HUP
        );
    }
    assert_eq!(
        service
            .signal_state(background.process_id)
            .unwrap()
            .pending(),
        0
    );
}

#[test]
fn parentless_controlling_process_is_watched_and_terminal_release_is_idempotent() {
    let leader = PeerIdentity {
        process_id: 4200,
        effective_uid: 505,
        effective_gid: 24,
    };
    let mut service = service_for(leader);
    assert_eq!(
        service
            .handle_terminal(
                leader,
                terminal_identity(leader),
                protocol::Header {
                    opcode: protocol::OP_TERMINAL_ACQUIRE,
                    ..Default::default()
                },
                &[],
                77
            )
            .header
            .status,
        0
    );
    assert_eq!(service.child_lifecycle_handles(), [4200]);
    let mut processes = RecordingProcesses::default();
    processes
        .states
        .insert(4200, ProcessLifecycle::Exited { exit_code: 0 });
    assert_eq!(
        service.refresh_child_exit_notifications(&mut processes),
        Ok(0)
    );
    assert!(service.controlling_terminal(77).is_none());
    assert!(service.child_lifecycle_handles().is_empty());
    assert_eq!(
        dequeue_signal(&mut service, leader).signal,
        protocol::SIGNAL_HUP
    );
    assert_eq!(
        service.refresh_child_exit_notifications(&mut processes),
        Ok(0)
    );
    assert_eq!(
        service.signal_state(leader.process_id).unwrap().pending(),
        0
    );
    assert!(processes.released.is_empty());
}

#[test]
fn controlling_process_exit_releases_a_terminal_with_an_empty_foreground_group() {
    let (mut service, [_, leader, first, second, background], mut filesystem, mut processes) =
        terminal_exit_family();
    for member in [first, second] {
        processes.states.insert(
            member.process_id as u32,
            ProcessLifecycle::Exited { exit_code: 0 },
        );
        service
            .wait_child(
                leader,
                protocol::WaitRequest {
                    selector: member.process_id as i64,
                    options: 0,
                },
                &mut filesystem,
                &mut processes,
            )
            .unwrap();
    }
    assert!(service.controlling_terminal(77).is_some());
    processes.states.insert(
        leader.process_id as u32,
        ProcessLifecycle::Exited { exit_code: 0 },
    );
    assert_eq!(service.refresh_child_exit_notifications(&mut processes), Ok(1));
    assert!(service.controlling_terminal(77).is_none());
    assert_eq!(
        service.signal_state(background.process_id).unwrap().pending(),
        0
    );
    assert_eq!(service.refresh_child_exit_notifications(&mut processes), Ok(0));
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
            path: b"result.txt",
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
    assert_eq!(request.path, b"result.txt");
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
            path: b"result.txt",
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
    assert_eq!(request.path, b"result.txt");
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
        rights: mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_WRITE
            | mnu_abi::HANDLE_RIGHT_CONTROL | mnu_abi::HANDLE_RIGHT_TRANSFER,
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
fn file_mutation_capabilities_cannot_be_recovered_from_owner_or_root_credentials() {
    for uid in [0, 501] {
        let peer = PeerIdentity {
            process_id: 1000 + uid as u64,
            effective_uid: uid,
            effective_gid: 20,
        };
        let mut service = service_for(peer);
        service.handle(
            peer,
            protocol::Header {
                opcode: protocol::OP_SESSION_REGISTER,
                ..Default::default()
            },
            &[],
        );
        let file = AttachedObject {
            handle: 59,
            rights: mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_TRANSFER,
        };
        let mut filesystem = RecordingFilesystem::default();
        for (opcode, payload) in [
            (protocol::OP_FTRUNCATE, 1u64.to_le_bytes().to_vec()),
            (protocol::OP_FCHMOD, 0o777u32.to_le_bytes().to_vec()),
            (protocol::OP_FCHOWN, [0; 8].to_vec()),
        ] {
            let result = service.handle_objects(
                peer,
                protocol::Header {
                    opcode,
                    ..Default::default()
                },
                &payload,
                &[file],
                &mut filesystem,
            );
            assert_eq!(
                result.response.header.status, -13,
                "uid={uid} opcode={opcode}"
            );
            assert!(
                filesystem.truncated.is_none()
                    && filesystem.chmod_file.is_none()
                    && filesystem.chown_file.is_none()
            );
            assert_eq!(filesystem.roots_opened, 0);
        }
    }
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
        rights: mnu_abi::HANDLE_RIGHT_READ
            | mnu_abi::HANDLE_RIGHT_CONTROL
            | mnu_abi::HANDLE_RIGHT_TRANSFER,
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
    let mut update = [0; protocol::FILE_FLAGS_UPDATE_PAYLOAD_LEN];
    protocol::encode_file_flags_update(protocol::OPEN_NONBLOCK, 0, &mut update).unwrap();
    for (attachments, expected) in [(&[][..], STATUS_EINVAL), (&[file][..], protocol::STATUS_OK)] {
        let response = service.handle_objects(
            peer,
            protocol::Header {
                opcode: protocol::OP_FUPDATEFL,
                ..Default::default()
            },
            &update,
            attachments,
            &mut filesystem,
        );
        assert_eq!(response.response.header.status, expected);
    }
    assert_eq!(filesystem.status_flags, protocol::OPEN_APPEND);
    assert_eq!(filesystem.flags_file, Some(file));
    let reduced = AttachedObject {
        rights: file.rights & !mnu_abi::HANDLE_RIGHT_CONTROL,
        ..file
    };
    for opcode in [protocol::OP_FSETFL, protocol::OP_FUPDATEFL] {
        let payload = if opcode == protocol::OP_FSETFL {
            &flags[..]
        } else {
            &update[..]
        };
        let response = service.handle_objects(
            peer,
            protocol::Header {
                opcode,
                ..Default::default()
            },
            payload,
            &[reduced],
            &mut filesystem,
        );
        assert_eq!(response.response.header.status, -13);
        assert_eq!(filesystem.status_flags, protocol::OPEN_APPEND);
    }
    update[4..].copy_from_slice(&protocol::OPEN_APPEND.to_le_bytes());
    let response = service.handle_objects(
        peer,
        protocol::Header {
            opcode: protocol::OP_FUPDATEFL,
            ..Default::default()
        },
        &update,
        &[file],
        &mut filesystem,
    );
    assert_eq!(response.response.header.status, STATUS_EINVAL);
    assert_eq!(filesystem.status_flags, protocol::OPEN_APPEND);
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
            path: b"child",
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
    assert_eq!(request.path, b"child");
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
            path: b"child",
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
    assert_eq!(request.path, b"child");
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
        old_path: b"old/file",
        new_path: b"new/file",
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
    assert_eq!(prepared.old_path, b"old/file");
    assert_eq!(prepared.new_path, b"new/file");
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
        old_path: b"old/source",
        new_path: b"new/link",
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
    assert_eq!(prepared.old_path, b"old/source");
    assert_eq!(prepared.new_path, b"new/link");
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
            path: b"file",
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
    assert_eq!(prepared.path, b"file");
    assert_eq!(prepared.length, 1234);
    assert_eq!(prepared.growth_ceiling, protocol::RLIM_INFINITY);
    assert_eq!(prepared.effective_uid, 502);
    assert_eq!(prepared.effective_gid, 21);
    assert_eq!(filesystem.directory, Some(directory));
}

#[test]
fn truncate_ceiling_comes_from_authenticated_process_policy_not_request_identity() {
    let peer = PeerIdentity {
        process_id: 192,
        effective_uid: 501,
        effective_gid: 20,
    };
    let mut service = service_for(peer);
    assert_eq!(
        service
            .handle(
                peer,
                protocol::Header {
                    opcode: protocol::OP_SESSION_REGISTER,
                    ..Default::default()
                },
                &[]
            )
            .header
            .status,
        0
    );
    let mut payload = [0; protocol::RESOURCE_LIMIT_REQUEST_LEN];
    protocol::encode_resource_limit_request(
        protocol::ResourceLimitRequest {
            process_id: 0,
            resource: protocol::RLIMIT_FSIZE,
            flags: protocol::RESOURCE_LIMIT_SET,
            limit: protocol::ResourceLimit { soft: 5, hard: 10 },
        },
        &mut payload,
    )
    .unwrap();
    assert_eq!(
        service
            .handle(
                peer,
                protocol::Header {
                    opcode: protocol::OP_RESOURCE_LIMIT,
                    ..Default::default()
                },
                &payload
            )
            .header
            .status,
        0
    );
    let mut filesystem = RecordingFilesystem::default();
    let file = AttachedObject {
        handle: 70,
        rights: mnu_abi::HANDLE_RIGHT_WRITE | mnu_abi::HANDLE_RIGHT_TRANSFER,
    };
    let forged = PeerIdentity {
        effective_uid: 0,
        effective_gid: 0,
        ..peer
    };
    let mut length = [0; 8];
    protocol::encode_file_length(123, &mut length).unwrap();
    assert_eq!(
        service
            .handle_objects(
                forged,
                protocol::Header {
                    opcode: protocol::OP_FTRUNCATE,
                    ..Default::default()
                },
                &length,
                &[file],
                &mut filesystem
            )
            .response
            .header
            .status,
        0
    );
    assert_eq!(filesystem.truncated, Some((file, 123)));
    assert_eq!(filesystem.truncate_ceiling, Some(5));
    let mut path = [0; protocol::TRUNCATE_AT_HEADER_LEN + 8];
    let length = protocol::encode_truncate_at(
        protocol::TruncateAtRequest {
            base: protocol::OpenBase::ProcessCwd,
            length: 123,
            path: b"file",
        },
        &mut path,
    )
    .unwrap();
    let prepared = service
        .prepare_truncate_at(forged, &path[..length], 0)
        .unwrap();
    assert_eq!((prepared.effective_uid, prepared.growth_ceiling), (501, 5));
    assert_eq!(
        posix_service::truncate_filesystem_status(-filesystem_protocol::ERROR_GROWTH_LIMIT),
        protocol::STATUS_FILE_SIZE_LIMIT
    );
    for error in [-27, -13, -5] {
        assert_eq!(posix_service::truncate_filesystem_status(error), error);
    }
}

#[test]
fn symlink_wire_and_service_preserve_target_credentials_and_directory_handle() {
    let request = protocol::SymlinkAtRequest {
        base: protocol::OpenBase::AttachedDirectory,
        target: b"../target",
        link_path: b"links/name",
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
    assert_eq!(prepared.target, b"../target");
    assert_eq!(prepared.link_path, b"links/name");
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
            path: b"links/name",
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
    assert_eq!(prepared.path, b"links/name");
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
            path: b"file",
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
    assert_eq!(prepared.path, b"file");
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
        path: b"link",
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
    assert_eq!(prepared.path, b"link");
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
            path: b"tool",
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
    assert_eq!(request.path, b"tool");
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
            path: b"work",
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
    assert_eq!(request.path, b"work");
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
            path: b"jail",
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
    assert_eq!(request.path, b"jail");
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
            path: b"jail",
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
