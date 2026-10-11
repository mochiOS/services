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
    assert!(source.contains("service.registered_peer(context.process_id)"));
    assert!(!source.contains("effective_uid: context.effective_uid"));
    assert!(!source.contains("effective_gid: context.effective_gid"));
    assert!(!source.contains("bind_sender_process"));
    assert!(!source.contains("service.bind_process("));
    // Internal PTY worker messages are authenticated native messages, not
    // requests to manufacture a POSIX session for the service itself.
    assert!(source.contains("context.process_id == service_process_id"));
}
