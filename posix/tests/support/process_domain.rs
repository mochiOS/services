use super::*;
use posix_service::process_domain::Registry;
fn actor(id: u32) -> AuthenticatedProcess<u32> {
    AuthenticatedProcess {
        handle: id,
        process_id: u64::from(id),
    }
}
fn owner(id: u64) -> PeerIdentity {
    PeerIdentity {
        process_id: id,
        effective_uid: 0,
        effective_gid: 0,
    }
}
fn child(service: &mut PosixService, parent: u64, id: u32, fs: &mut RecordingFilesystem) {
    let parent = service.registered_peer(parent).unwrap();
    service.adopt_child(parent, actor(id), fs).unwrap();
}
fn contains(registry: &Registry, service: &PosixService, id: u64, process: u32) -> bool {
    registry
        .contains(service, owner(1), id, actor(process), |a, b| Ok(a == b))
        .unwrap()
}
#[test]
fn native_domain_membership_survives_fork_exec_reparenting_and_intermediate_reap() {
    let mut service = PosixService::new();
    service
        .initialize_bootstrap_process(actor(1), 0, 0, &[])
        .unwrap();
    let mut fs = RecordingFilesystem::default();
    child(&mut service, 1, 2, &mut fs);
    child(&mut service, 2, 3, &mut fs);
    child(&mut service, 1, 4, &mut fs);
    let mut registry = Registry::default();
    let mut id = 0;
    registry
        .create(
            &mut service,
            owner(1),
            &[actor(2)],
            |a, b| Ok(a == b),
            |value| {
                id = value;
                Ok(90)
            },
        )
        .unwrap();
    assert!(contains(&registry, &service, id, 2));
    assert!(contains(&registry, &service, id, 3));
    assert!(!contains(&registry, &service, id, 1));
    assert!(!contains(&registry, &service, id, 4));
    child(&mut service, 3, 5, &mut fs);
    let mut processes = RecordingProcesses::default();
    for process in 1..=6 {
        processes.states.insert(process, ProcessLifecycle::Running);
    }
    processes
        .states
        .insert(3, ProcessLifecycle::Exited { exit_code: 0 });
    service
        .refresh_child_exit_notifications(&mut processes)
        .unwrap();
    assert_eq!(service.parent_id(5), Some(1));
    // A real wait reaps the old POSIX parent, without erasing launch membership.
    let mut payload = [0; protocol::WAIT_REQUEST_LEN];
    protocol::encode_wait_request(
        protocol::WaitRequest {
            selector: 3,
            options: 0,
        },
        &mut payload,
    )
    .unwrap();
    let result = service
        .wait_child(
            owner(2),
            protocol::decode_wait_request(&payload).unwrap(),
            &mut fs,
            &mut processes,
        )
        .unwrap();
    assert_eq!(result.process_id, 3);
    assert!(contains(&registry, &service, id, 5));
    child(&mut service, 5, 6, &mut fs);
    assert!(contains(&registry, &service, id, 6));
    processes.images.insert(
        6,
        Ok(mnu_abi::ProcessStatus {
            process_id: 6,
            state: mnu_abi::PROCESS_STATE_RUNNING,
            image_revision: 7,
            ..Default::default()
        }),
    );
    service
        .refresh_image_state(owner(6), &mut processes)
        .unwrap();
    assert!(contains(&registry, &service, id, 6));
    assert!(!contains(&registry, &service, id, 4));
}
#[test]
fn domain_capture_requires_owned_roots_and_matching_native_objects() {
    let mut service = PosixService::new();
    service
        .initialize_bootstrap_process(actor(1), 0, 0, &[])
        .unwrap();
    let mut fs = RecordingFilesystem::default();
    child(&mut service, 1, 2, &mut fs);
    child(&mut service, 1, 3, &mut fs);
    let mut registry = Registry::default();
    assert_eq!(
        registry.create(
            &mut service,
            owner(2),
            &[actor(3)],
            |_, _| Ok(true),
            |_| Ok(90)
        ),
        Err(-1)
    );
    assert_eq!(
        registry.create(
            &mut service,
            owner(1),
            &[actor(2)],
            |_, _| Ok(false),
            |_| Ok(90)
        ),
        Err(-1)
    );
    let mut id = 0;
    registry
        .create(
            &mut service,
            owner(1),
            &[actor(2)],
            |a, b| Ok(a == b),
            |value| {
                id = value;
                Ok(90)
            },
        )
        .unwrap();
    assert_eq!(
        registry.contains(&service, owner(1), id, actor(2), |_, _| Ok(false)),
        Err(-1)
    );
    assert_eq!(
        registry.contains(&service, owner(1), id, actor(2), |_, _| Err(-5)),
        Err(-5)
    );
    assert_eq!(
        registry.contains(&service, owner(1), id + 1, actor(2), |_, _| Ok(true)),
        Err(-9)
    );
}
#[test]
fn release_is_native_only_and_does_not_make_future_children_members() {
    let mut service = PosixService::new();
    service
        .initialize_bootstrap_process(actor(1), 0, 0, &[])
        .unwrap();
    let mut fs = RecordingFilesystem::default();
    child(&mut service, 1, 2, &mut fs);
    let mut registry = Registry::default();
    let mut id = 0;
    registry
        .create(
            &mut service,
            owner(1),
            &[actor(2)],
            |a, b| Ok(a == b),
            |value| {
                id = value;
                Ok(90)
            },
        )
        .unwrap();
    let mut bytes = [0; 128];
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
    assert_eq!(registry.release_native(&bytes[..length], 0, 0), Err(-1));
    assert!(contains(&registry, &service, id, 2));
    registry
        .release_native(&bytes[..length], mnu_abi::IPC_DELIVERY_NATIVE_OBJECT, 0)
        .unwrap();
    assert_eq!(
        registry.contains(&service, owner(1), id, actor(2), |_, _| Ok(true)),
        Err(-9)
    );
    child(&mut service, 2, 3, &mut fs);
    let mut next = 0;
    registry
        .create(
            &mut service,
            owner(1),
            &[actor(2)],
            |a, b| Ok(a == b),
            |value| {
                next = value;
                Ok(91)
            },
        )
        .unwrap();
    assert!(next > id);
    assert!(contains(&registry, &service, next, 3));
}

#[test]
fn empty_owner_domain_admits_fresh_roots_before_any_child_can_execute() {
    let mut service = PosixService::new();
    service
        .initialize_bootstrap_process(actor(1), 0, 0, &[])
        .unwrap();
    let mut fs = RecordingFilesystem::default();
    child(&mut service, 1, 2, &mut fs);
    let mut registry = Registry::default();
    let mut id = 0;
    registry
        .create(
            &mut service,
            owner(1),
            &[],
            |_, _| unreachable!(),
            |value| {
                id = value;
                Ok(90)
            },
        )
        .unwrap();
    assert!(!contains(&registry, &service, id, 1));
    assert_eq!(
        registry.adopt_spawned_child(&mut service, owner(2), id, actor(3), 0, 0, &[], &mut fs),
        Err(-1)
    );
    assert!(service.session(3).is_none());
    registry
        .adopt_spawned_child(&mut service, owner(1), id, actor(3), 501, 20, &[], &mut fs)
        .unwrap();
    assert!(contains(&registry, &service, id, 3));
    child(&mut service, 3, 4, &mut fs);
    assert!(contains(&registry, &service, id, 4));
    assert!(!contains(&registry, &service, id, 2));
    assert_eq!(service.session(3).unwrap().effective_uid, 501);
    assert_eq!(
        registry.adopt_spawned_child(&mut service, owner(1), id, actor(3), 0, 0, &[], &mut fs),
        Err(-22)
    );
    assert_eq!(service.session(3).unwrap().effective_uid, 501);
}

#[test]
fn domain_publication_failures_do_not_reuse_ids_or_leave_live_membership() {
    let mut service = PosixService::new();
    service
        .initialize_bootstrap_process(actor(1), 0, 0, &[])
        .unwrap();
    let mut fs = RecordingFilesystem::default();
    child(&mut service, 1, 2, &mut fs);
    let mut registry = Registry::default();
    let mut failed = 0;
    assert_eq!(
        registry.create(
            &mut service,
            owner(1),
            &[actor(2)],
            |a, b| Ok(a == b),
            |value| {
                failed = value;
                Err(-5)
            }
        ),
        Err(-5)
    );
    let mut ids = Vec::new();
    for _ in 0..16 {
        registry
            .create(
                &mut service,
                owner(1),
                &[],
                |_, _| unreachable!(),
                |value| {
                    ids.push(value);
                    Ok(90)
                },
            )
            .unwrap();
    }
    assert!(ids[0] > failed);
    assert_eq!(
        registry.create(
            &mut service,
            owner(1),
            &[],
            |_, _| unreachable!(),
            |_| panic!("budget must be enforced before creation")
        ),
        Err(-11)
    );
    for id in ids {
        assert!(!contains(&registry, &service, id, 2));
    }
}
