use mochios_posix_protocol as protocol;
use posix_service::{AuthenticatedProcess, PeerIdentity, PosixService};

#[test]
fn initial_credentials_come_from_userspace_and_reregistration_cannot_replace_them() {
    let mut service = PosixService::new();
    service
        .initialize_bootstrap_process(
            AuthenticatedProcess {
                handle: 7,
                process_id: 70,
            },
            501,
            20,
            &[42, 43],
        )
        .unwrap();
    assert_eq!(service.process_handle(70), Some(7));
    let before = *service.session(70).unwrap();
    assert_eq!(
        (before.real_uid, before.effective_uid, before.saved_uid),
        (501, 501, 501)
    );
    assert_eq!(
        (before.real_gid, before.effective_gid, before.saved_gid),
        (20, 20, 20)
    );
    let peer = PeerIdentity {
        process_id: 70,
        effective_uid: 0,
        effective_gid: 0,
    };
    let response = service.handle(
        peer,
        protocol::Header {
            opcode: protocol::OP_SESSION_REGISTER,
            ..Default::default()
        },
        &[],
    );
    assert_eq!(response.header.status, 0);
    assert_eq!(*service.session(70).unwrap(), before);
    let response = service.handle(
        peer,
        protocol::Header {
            opcode: protocol::OP_GROUPS_GET,
            ..Default::default()
        },
        &[],
    );
    let mut groups = [0; 2];
    assert_eq!(
        protocol::decode_group_list(&response.payload, &mut groups),
        Ok(2)
    );
    assert_eq!(groups, [42, 43]);
    let mut uid = [0; 4];
    protocol::encode_credential_id(0, &mut uid).unwrap();
    assert_eq!(
        service
            .handle(
                peer,
                protocol::Header {
                    opcode: protocol::OP_SET_UID,
                    ..Default::default()
                },
                &uid
            )
            .header
            .status,
        protocol::STATUS_EPERM
    );
    assert_eq!(*service.session(70).unwrap(), before);
}

#[test]
fn bootstrap_is_one_time_and_invalid_initialization_does_not_bind_a_process() {
    let process = AuthenticatedProcess {
        handle: 7,
        process_id: 70,
    };
    let mut service = PosixService::new();
    for (process, uid, gid, groups) in [
        (
            AuthenticatedProcess {
                handle: 7,
                process_id: 0,
            },
            0,
            0,
            vec![],
        ),
        (process, u32::MAX, 0, vec![]),
        (process, 0, u32::MAX, vec![]),
        (
            process,
            0,
            0,
            vec![0; protocol::MAX_SUPPLEMENTARY_GROUPS + 1],
        ),
    ] {
        assert_eq!(
            service.initialize_bootstrap_process(process, uid, gid, &groups),
            Err(posix_service::STATUS_EINVAL)
        );
        assert!(service.process_handle(70).is_none());
        assert!(service.session(70).is_none());
    }
    service
        .initialize_bootstrap_process(process, 0, 0, &[])
        .unwrap();
    assert_eq!(
        service.initialize_bootstrap_process(process, 501, 20, &[]),
        Err(protocol::STATUS_EPERM)
    );
    assert_eq!(service.session(70).unwrap().effective_uid, 0);
    assert_eq!(
        service.initialize_bootstrap_process(
            AuthenticatedProcess {
                handle: 8,
                process_id: 80
            },
            0,
            0,
            &[]
        ),
        Err(protocol::STATUS_EPERM)
    );
    assert!(service.process_handle(80).is_none());
}

#[test]
fn bootstrap_authority_is_inherited_and_initialized_before_ready_publication() {
    let launcher = include_str!("../../service-manager/src/service_launcher.rs");
    let bootstrap = launcher
        .split("if service == FixedService::Posix {")
        .nth(1)
        .unwrap()
        .split("append_posix_handle")
        .next()
        .unwrap();
    assert!(bootstrap.contains("let own_endpoint = platform::ipc::create()?"));
    assert!(!bootstrap.contains("identity.thread_id"));
    assert!(bootstrap.contains("BOOTSTRAP_PROCESS_HANDLE_KEY"));
    assert!(bootstrap.contains("HANDLE_RIGHT_TRANSFER"));
    assert!(bootstrap.contains("close(bootstrap)"));
    assert!(!bootstrap.contains("thread_security_context"));
    let runtime = include_str!("../src/main.rs");
    assert!(
        runtime.find("initialize_bootstrap_process(").unwrap()
            < runtime.find("notify_handle(ready_target").unwrap()
    );
    assert!(runtime.contains("platform::handle::rights(handle)? != required"));
    assert!(runtime.contains("platform::process::handle_status(handle)"));
}
