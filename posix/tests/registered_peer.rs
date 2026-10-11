use mochios_posix_protocol as protocol;
use posix_service::{AuthenticatedProcess, PeerIdentity, PosixService};

#[test]
fn admission_requires_an_initialized_environment_not_only_a_process_handle() {
    let mut service = PosixService::new();
    assert_eq!(service.registered_peer(70), None);
    service
        .bind_process(
            PeerIdentity {
                process_id: 70,
                effective_uid: 0,
                effective_gid: 0,
            },
            AuthenticatedProcess {
                handle: 7,
                process_id: 70,
            },
        )
        .unwrap();
    assert_eq!(service.registered_peer(70), None);
    assert!(service.session(70).is_none());
    let reply = service.handle(
        PeerIdentity {
            process_id: 70,
            effective_uid: 0,
            effective_gid: 0,
        },
        protocol::Header {
            opcode: protocol::OP_SESSION_REGISTER,
            request_id: 11,
            ..Default::default()
        },
        &[],
    );
    assert_eq!(reply.header.status, posix_service::STATUS_EINVAL);
    assert_eq!(reply.header.request_id, 11);
    assert!(service.session(70).is_none());
    assert_eq!(service.registered_peer(70), None);
}

#[test]
fn registration_cannot_replace_initialized_credentials_groups_or_umask() {
    let mut service = PosixService::new();
    service
        .initialize_bootstrap_process(
            AuthenticatedProcess {
                handle: 7,
                process_id: 70,
            },
            501,
            20,
            &[42],
        )
        .unwrap();
    let peer = service.registered_peer(70).unwrap();
    let mut mask = [0; 4];
    protocol::encode_umask(0o77, &mut mask).unwrap();
    assert_eq!(
        service
            .handle(
                peer,
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
    let before = *service.session(70).unwrap();
    for _ in 0..2 {
        assert_eq!(
            service
                .handle(
                    PeerIdentity {
                        effective_uid: 0,
                        effective_gid: 0,
                        ..peer
                    },
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
        assert_eq!(*service.session(70).unwrap(), before);
        let response = service.handle(
            peer,
            protocol::Header {
                opcode: protocol::OP_GROUPS_GET,
                ..Default::default()
            },
            &[],
        );
        assert_eq!(response.header.status, 0);
        let mut groups = [0; 1];
        assert_eq!(
            protocol::decode_group_list(&response.payload, &mut groups),
            Ok(1)
        );
        assert_eq!(groups, [42]);
    }
    for (flags, payload) in [(1, &[][..]), (0, &[0][..])] {
        let response = service.handle(
            peer,
            protocol::Header {
                opcode: protocol::OP_SESSION_REGISTER,
                flags,
                ..Default::default()
            },
            payload,
        );
        assert_eq!(response.header.status, posix_service::STATUS_EINVAL);
        assert_eq!(*service.session(70).unwrap(), before);
    }
}

#[test]
fn admission_returns_only_userspace_credentials_including_later_updates() {
    let mut service = PosixService::new();
    service
        .initialize_bootstrap_process(
            AuthenticatedProcess {
                handle: 7,
                process_id: 70,
            },
            0,
            20,
            &[],
        )
        .unwrap();
    let peer = service.registered_peer(70).unwrap();
    assert_eq!((peer.effective_uid, peer.effective_gid), (0, 20));
    let mut payload = [0; 4];
    protocol::encode_credential_id(501, &mut payload).unwrap();
    assert_eq!(
        service
            .handle(
                peer,
                protocol::Header {
                    opcode: protocol::OP_SET_EFFECTIVE_UID,
                    ..Default::default()
                },
                &payload
            )
            .header
            .status,
        0
    );
    let changed = service.registered_peer(70).unwrap();
    assert_eq!((changed.effective_uid, changed.effective_gid), (501, 20));
    assert_eq!(service.registered_peer(71), None);
}

#[test]
fn runtime_does_not_auto_bind_senders_or_import_native_uid_gid() {
    let source = include_str!("../src/main.rs");
    assert!(source.contains("platform::ipc::endpoint_owner_process(sender).ok()"));
    assert!(source.contains("service.registered_peer(process_id)"));
    assert!(!source.contains("effective_uid: context.effective_uid"));
    assert!(!source.contains("effective_gid: context.effective_gid"));
    assert!(!source.contains("bind_sender_process"));
    assert!(!source.contains("service.bind_process("));
    // Internal PTY worker messages are authenticated native messages, not
    // requests to manufacture a POSIX session for the service itself.
    assert!(source.contains("sender_process == Some(service_process_id)"));
    // Same-thread signal registration needs only native endpoint identity.
    // Neither registration nor peer admission may query kernel credentials or
    // reinterpret endpoint numbers as native thread IDs.
    let registration = source
        .find("header.opcode == protocol::OP_SIGNAL_THREAD_REGISTER")
        .unwrap();
    let query = registration
        + source[registration..]
            .find("platform::ipc::endpoint_execution_identity(sender)")
            .unwrap();
    assert!(registration < query);
    // The mask branch also uses kernel identity, after POSIX peer admission.
    let admission = source.find("service.registered_peer(process_id)").unwrap();
    let first_query = source
        .find("platform::ipc::endpoint_execution_identity(sender)")
        .unwrap();
    assert!(admission < first_query);
    assert!(!source.contains("thread_security_context"));
}
