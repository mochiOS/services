use super::*;

fn action(
    service: &mut PosixService,
    peer: PeerIdentity,
    request: protocol::SignalDisposition,
    setting: bool,
) -> protocol::SignalDisposition {
    let mut bytes = [0; protocol::SIGNAL_DISPOSITION_LEN];
    protocol::encode_signal_disposition(request, &mut bytes).unwrap();
    let reply = service.handle(
        peer,
        protocol::Header {
            opcode: protocol::OP_SIGNAL_DISPOSITION,
            flags: if setting {
                protocol::SIGNAL_DISPOSITION_SET
            } else {
                0
            },
            ..Default::default()
        },
        &bytes,
    );
    assert_eq!(reply.header.status, 0);
    protocol::decode_signal_disposition(&reply.payload).unwrap()
}

fn query(
    service: &mut PosixService,
    peer: PeerIdentity,
    signal: u32,
) -> protocol::SignalDisposition {
    action(
        service,
        peer,
        protocol::SignalDisposition {
            signal,
            kind: 0,
            child_options: 0,
        },
        false,
    )
}

fn install(service: &mut PosixService, peer: PeerIdentity) {
    for (signal, kind, child_options) in [
        (30, protocol::SIGNAL_DISPOSITION_CAUGHT, 0),
        (31, protocol::SIGNAL_DISPOSITION_IGNORE, 0),
        (
            protocol::SIGNAL_CHLD,
            protocol::SIGNAL_DISPOSITION_CAUGHT,
            protocol::SIGNAL_CHILD_OPTION_NOCLDSTOP,
        ),
    ] {
        action(
            service,
            peer,
            protocol::SignalDisposition {
                signal,
                kind,
                child_options,
            },
            true,
        );
    }
}

#[test]
fn fresh_executables_reset_caught_actions_but_fork_keeps_them() {
    let parent = PeerIdentity {
        process_id: 2501,
        effective_uid: 0,
        effective_gid: 0,
    };
    let mut service = service_for(parent);
    let mut filesystem = RecordingFilesystem::default();
    install(&mut service, parent);
    for kind in 0..3 {
        let child = PeerIdentity {
            process_id: 2502 + kind,
            ..parent
        };
        let process = AuthenticatedProcess {
            handle: child.process_id as u32,
            process_id: child.process_id,
        };
        match kind {
            0 => service
                .adopt_child(parent, process, &mut filesystem)
                .unwrap(),
            1 => service
                .adopt_spawned_child(parent, process, 0, 0, &[], &mut filesystem)
                .unwrap(),
            _ => service
                .adopt_launched_child(
                    parent,
                    AuthenticatedProcess {
                        handle: 2501,
                        process_id: 2501,
                    },
                    process,
                    &mut filesystem,
                )
                .unwrap(),
        }
        let expected = if kind == 0 {
            protocol::SIGNAL_DISPOSITION_CAUGHT
        } else {
            0
        };
        assert_eq!(query(&mut service, child, 30).kind, expected);
        assert_eq!(
            query(&mut service, child, 31).kind,
            protocol::SIGNAL_DISPOSITION_IGNORE
        );
        let chld = query(&mut service, child, protocol::SIGNAL_CHLD);
        assert_eq!(chld.kind, expected);
        assert_eq!(
            chld.child_options,
            if kind == 0 {
                protocol::SIGNAL_CHILD_OPTION_NOCLDSTOP
            } else {
                0
            }
        );
    }
    assert_eq!(
        query(&mut service, parent, 30).kind,
        protocol::SIGNAL_DISPOSITION_CAUGHT
    );
}

#[test]
fn failed_image_observation_preserves_actions_and_child_options() {
    let peer = PeerIdentity {
        process_id: 2501,
        effective_uid: 0,
        effective_gid: 0,
    };
    let mut service = service_for(peer);
    install(&mut service, peer);
    let mut processes = RecordingProcesses::default();
    processes.images.insert(2501, Err(protocol::STATUS_EIO));
    assert_eq!(
        service.refresh_image_state(peer, &mut processes),
        Err(protocol::STATUS_EIO)
    );
    assert_eq!(
        query(&mut service, peer, 30).kind,
        protocol::SIGNAL_DISPOSITION_CAUGHT
    );
    assert_eq!(
        query(&mut service, peer, protocol::SIGNAL_CHLD).child_options,
        protocol::SIGNAL_CHILD_OPTION_NOCLDSTOP
    );
}
