use super::*;

fn launch_setup() -> (
    Arc<Mutex<PosixService>>,
    PeerIdentity,
    PeerIdentity,
    RecordingFilesystem,
    Registry<u32>,
    u64,
) {
    let (state, source, mut fs, mut scopes) = setup();
    identity(&state, source, protocol::OP_SET_EFFECTIVE_UID, 0);
    state
        .lock()
        .unwrap()
        .adopt_spawned_child(
            source,
            AuthenticatedProcess {
                handle: 400,
                process_id: 400,
            },
            0,
            0,
            &[],
            &mut fs,
        )
        .unwrap();
    identity(&state, source, protocol::OP_SET_EFFECTIVE_UID, 501);
    let broker = state.lock().unwrap().registered_peer(400).unwrap();
    let id = create(&state, source, &mut fs, &mut scopes);
    (state, source, broker, fs, scopes, id)
}

fn register(
    state: &Mutex<PosixService>,
    broker: PeerIdentity,
    source: u64,
    fs: &mut RecordingFilesystem,
    scopes: &Registry<u32>,
    id: u64,
    processes: &mut RecordingProcesses,
) -> Result<(), i32> {
    scopes.register_child(
        id,
        &mut state.lock().unwrap(),
        broker,
        AuthenticatedProcess {
            handle: source as u32,
            process_id: source,
        },
        AuthenticatedProcess {
            handle: 500,
            process_id: 500,
        },
        fs,
        processes,
    )
}

#[test]
fn scoped_registration_inherits_the_requester_and_retains_only_the_child() {
    let (state, source, broker, mut fs, scopes, id) = launch_setup();
    let before = *state.lock().unwrap().session(source.process_id).unwrap();
    let roots = *state
        .lock()
        .unwrap()
        .session_directories(source.process_id)
        .unwrap();
    register(
        &state,
        broker,
        source.process_id,
        &mut fs,
        &scopes,
        id,
        &mut RecordingProcesses::default(),
    )
    .unwrap();
    let service = state.lock().unwrap();
    let child = service.session(500).unwrap();
    assert_eq!(
        (child.real_uid, child.effective_uid, child.saved_uid),
        (before.real_uid, 501, 501)
    );
    assert_eq!(
        (
            child.real_gid,
            child.effective_gid,
            child.saved_gid,
            child.umask
        ),
        (before.real_gid, 20, 20, before.umask)
    );
    assert_eq!(service.parent_id(500), Some(source.process_id));
    assert_eq!(service.process_handle(500), Some(500));
    let child_roots = service.session_directories(500).unwrap();
    assert_eq!(
        (child_roots.root.handle, child_roots.cwd.handle),
        (roots.root.handle + 1000, roots.cwd.handle + 1000)
    );
    assert_eq!(
        service
            .launched_tree_handles(
                broker,
                AuthenticatedProcess {
                    handle: 500,
                    process_id: 500
                }
            )
            .unwrap(),
        [500]
    );
}

#[test]
fn credential_group_umask_and_directory_changes_reject_before_adopting_any_child() {
    for change in 0..6 {
        let (state, source, broker, mut fs, scopes, id) = launch_setup();
        match change {
            0 => identity(&state, source, protocol::OP_SET_EFFECTIVE_UID, 0),
            1 => identity(&state, source, protocol::OP_SET_EFFECTIVE_GID, 0),
            2 => {
                let payload = 0o077u32.to_le_bytes();
                assert_eq!(
                    state
                        .lock()
                        .unwrap()
                        .handle(source, header(protocol::OP_UMASK_SET, &payload), &payload)
                        .header
                        .status,
                    0
                );
            }
            3 => {
                identity(&state, source, protocol::OP_SET_EFFECTIVE_UID, 0);
                let mut payload = [0; 32];
                let length = protocol::encode_group_list(&[20, 43], &mut payload).unwrap();
                assert_eq!(
                    state
                        .lock()
                        .unwrap()
                        .handle(
                            source,
                            header(protocol::OP_GROUPS_SET, &payload[..length]),
                            &payload[..length]
                        )
                        .header
                        .status,
                    0
                );
                identity(&state, source, protocol::OP_SET_EFFECTIVE_UID, 501);
            }
            _ => {
                identity(&state, source, protocol::OP_SET_EFFECTIVE_UID, 0);
                let mut payload = [0; 128];
                let length = protocol::encode_stat_at(
                    protocol::StatAtRequest {
                        base: protocol::OpenBase::ProcessRoot,
                        flags: 0,
                        path: b"replacement",
                    },
                    &mut payload,
                )
                .unwrap();
                let opcode = if change == 4 {
                    protocol::OP_CHDIR_AT
                } else {
                    protocol::OP_CHROOT_AT
                };
                let result = state.lock().unwrap().handle_objects(
                    source,
                    header(opcode, &payload[..length]),
                    &payload[..length],
                    &[],
                    &mut fs,
                );
                assert_eq!(result.response.header.status, 0);
                identity(&state, source, protocol::OP_SET_EFFECTIVE_UID, 501);
            }
        }
        let retained = fs.retained.len();
        assert_eq!(
            register(
                &state,
                broker,
                source.process_id,
                &mut fs,
                &scopes,
                id,
                &mut RecordingProcesses::default()
            ),
            Err(-11),
            "change {change}"
        );
        assert!(state.lock().unwrap().session(500).is_none());
        assert_eq!(fs.retained.len(), retained);
    }
}

#[test]
fn native_image_change_rejects_even_if_the_entire_credential_record_still_matches() {
    let (state, source, broker, mut fs, mut scopes, _) = launch_setup();
    identity(&state, source, protocol::OP_SET_EFFECTIVE_UID, 0);
    identity(&state, source, protocol::OP_SET_GID, 20);
    identity(&state, source, protocol::OP_SET_UID, 501);
    let id = create(&state, source, &mut fs, &mut scopes);
    let before = *state.lock().unwrap().session(source.process_id).unwrap();
    let mut processes = RecordingProcesses::default();
    processes.images.insert(
        259,
        Ok(mnu_abi::ProcessStatus {
            process_id: 259,
            state: mnu_abi::PROCESS_STATE_RUNNING,
            image_revision: 1,
            ..Default::default()
        }),
    );
    assert_eq!(
        register(
            &state,
            broker,
            source.process_id,
            &mut fs,
            &scopes,
            id,
            &mut processes
        ),
        Err(-11)
    );
    assert_eq!(
        *state.lock().unwrap().session(source.process_id).unwrap(),
        before
    );
    assert!(state.lock().unwrap().session(500).is_none());
}

#[test]
fn foreign_scope_owner_unprivileged_broker_and_failed_observations_cannot_register() {
    let (state, source, broker, mut fs, scopes, id) = launch_setup();
    for (actor, requester, token, expected) in [
        (broker, 400, id, -1),
        (source, 259, id, -1),
        (broker, 259, id + 1, -9),
    ] {
        assert_eq!(
            register(
                &state,
                actor,
                requester,
                &mut fs,
                &scopes,
                token,
                &mut RecordingProcesses::default()
            ),
            Err(expected)
        );
    }
    for status in [
        Err(-5),
        Ok(mnu_abi::ProcessStatus {
            process_id: 259,
            state: mnu_abi::PROCESS_STATE_EXITED,
            ..Default::default()
        }),
    ] {
        let mut processes = RecordingProcesses::default();
        processes.images.insert(259, status);
        let expected = if status.is_err() { -5 } else { -3 };
        assert_eq!(
            register(&state, broker, 259, &mut fs, &scopes, id, &mut processes),
            Err(expected)
        );
    }
    fs.comparison_error = Some(-5);
    assert_eq!(
        register(
            &state,
            broker,
            259,
            &mut fs,
            &scopes,
            id,
            &mut RecordingProcesses::default()
        ),
        Err(-5)
    );
    assert!(state.lock().unwrap().session(500).is_none());
}

#[test]
fn failed_child_directory_retention_rolls_back_and_keeps_scope_and_caller_ownership() {
    for step in 1..=2 {
        let (state, source, broker, mut fs, mut scopes, id) = launch_setup();
        fs.retain_failure_at = Some(fs.retained.len() + step);
        let released = fs.released.len();
        assert_eq!(
            register(
                &state,
                broker,
                source.process_id,
                &mut fs,
                &scopes,
                id,
                &mut RecordingProcesses::default()
            ),
            Err(-5)
        );
        assert!(state.lock().unwrap().session(500).is_none());
        assert_eq!(fs.released.len() - released, step - 1);
        assert!(!fs.released.iter().any(|object| object.handle == 500));
        assert_eq!(
            invoke(&state, source, &mut fs, &mut scopes, id, wire::OP_INFO, &[])
                .response
                .header
                .status,
            0
        );
    }
}

struct LaunchTransport {
    flags: u32,
    reply: Vec<ObjectHandleAttachment<u32>>,
    status: i32,
    closed: RefCell<Vec<u32>>,
}
impl Transport for LaunchTransport {
    type Error = ();
    fn call(&self, _: &[u8], _: &mut [u8]) -> Result<usize, ()> {
        panic!("requires object attachments")
    }
}
impl ObjectTransport for LaunchTransport {
    type Handle = u32;
    fn close_received_handle(&self, handle: u32) {
        self.closed.borrow_mut().push(handle);
    }
    fn call_with_handles(
        &self,
        request: &[u8],
        response: &mut [u8],
        handles: &mut ObjectHandles<u32>,
    ) -> Result<usize, ()> {
        let (header, payload) = protocol::decode(request).unwrap();
        assert_eq!(header.opcode, wire::OP_REGISTER_CHILD);
        assert!(payload.is_empty());
        assert_eq!(
            handles
                .iter()
                .map(|object| (object.handle, object.rights))
                .collect::<Vec<_>>(),
            [
                (99, wire::ATTACH_RIGHTS),
                (77, mnu_abi::HANDLE_RIGHT_WAIT),
                (
                    88,
                    mnu_abi::HANDLE_RIGHT_WAIT | mnu_abi::HANDLE_RIGHT_SIGNAL
                ),
            ]
        );
        handles.clear();
        for object in &self.reply {
            handles.push(*object).unwrap();
        }
        protocol::encode(
            protocol::Header {
                opcode: protocol::OP_STATUS,
                request_id: header.request_id,
                flags: self.flags,
                status: self.status,
                ..Default::default()
            },
            &[],
            response,
        )
        .map_err(|_| ())
    }
}
#[test]
fn client_registration_uses_three_explicit_objects_and_drains_rejected_replies() {
    for case in 0..4 {
        let client = Client::new(LaunchTransport {
            flags: u32::from(case == 1),
            status: if case == 3 { -11 } else { 0 },
            reply: if case >= 2 {
                vec![
                    ObjectHandleAttachment {
                        handle: 44,
                        rights: 0
                    };
                    2
                ]
            } else {
                vec![]
            },
            closed: RefCell::new(Vec::new()),
        });
        let object = |handle| ObjectHandleAttachment {
            handle,
            rights: mnu_abi::HANDLE_RIGHT_ALL,
        };
        let result = client.register_launched_child_in_scope(object(99), object(77), object(88));
        assert_eq!(result.is_ok(), case == 0);
        if case == 3 {
            assert_eq!(result, Err(ClientError::Remote(-11)));
        }
        assert_eq!(
            *client.transport().closed.borrow(),
            if case >= 2 { vec![44] } else { vec![] }
        );
    }
}
