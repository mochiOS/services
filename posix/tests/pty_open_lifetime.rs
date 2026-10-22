//! Service-private open instances; native dup/fork retain one instance instead.
use mochios_posix_protocol as wire;
use posix_service::pty::{EAGAIN, EBADF, PtyManager, PtyPair};

fn raw(ptys: &mut PtyManager, slave: u64) {
    let mut attributes = wire::TerminalAttributes::sane();
    attributes.local_flags = 0;
    attributes.input_flags = 0;
    attributes.output_flags = 0;
    ptys.set_attributes(slave, attributes).unwrap();
}

#[test]
fn separately_opened_slaves_share_terminal_state_but_have_distinct_provider_lifetimes() {
    let mut ptys = PtyManager::new();
    let pair = ptys.open().unwrap();
    raw(&mut ptys, pair.slave_object_id);
    let second = ptys.reopen_slave(pair.master_object_id).unwrap();
    let third = ptys.reopen_slave(pair.master_object_id).unwrap();
    let unrelated = ptys.open().unwrap();
    let ids = [
        pair.master_object_id,
        pair.slave_object_id,
        second,
        third,
        unrelated.master_object_id,
        unrelated.slave_object_id,
    ];
    for (at, id) in ids.iter().enumerate() {
        assert!(*id != 0 && *id <= i64::MAX as u64);
        assert!(!ids[..at].contains(id));
    }
    assert_eq!(
        ptys.slave_terminal_id(second),
        ptys.slave_terminal_id(pair.slave_object_id)
    );
    assert_ne!(
        ptys.slave_terminal_id(second),
        ptys.slave_terminal_id(unrelated.slave_object_id)
    );
    // A slave's opaque open ID need not have the old "slave" low bit.
    assert_eq!(second & 1, 0);
    let settings = ptys
        .query(second, wire::PTY_QUERY_READ_SETTINGS, &[], 4)
        .unwrap();
    assert!(
        wire::decode_terminal_read_settings(&settings)
            .unwrap()
            .noncanonical
    );
    let access = ptys.job_control_access(mnu_abi::provider::RequestHeader {
        opcode: mnu_abi::provider::OP_READ,
        object_id: second,
        argument: 0,
        basis: 0,
        length: 1,
        data_length: 0,
    });
    assert_eq!(
        access,
        Some((ptys.slave_terminal_id(second).unwrap(), true, false))
    );
    ptys.write(pair.master_object_id, b"abcdef").unwrap();
    assert_eq!(ptys.read(pair.slave_object_id, 2), Ok(b"ab".to_vec()));
    assert_eq!(ptys.read(second, 2), Ok(b"cd".to_vec()));
    ptys.release(pair.slave_object_id).unwrap();
    assert_eq!(ptys.read(pair.slave_object_id, 1), Err(EBADF));
    assert_eq!(ptys.read(third, 8), Ok(b"ef".to_vec()));
    assert_eq!(ptys.read(second, 1), Err(EAGAIN));
    assert_eq!(
        ptys.signals(pair.master_object_id).unwrap() & mnu_abi::HANDLE_SIGNAL_PEER_CLOSED,
        0
    );
    ptys.release(second).unwrap();
    assert_eq!(ptys.release(second), Err(EBADF));
    ptys.write(third, b"output").unwrap();
    assert_eq!(ptys.read(pair.master_object_id, 32), Ok(b"output".to_vec()));
    ptys.release(third).unwrap();
    assert_ne!(
        ptys.signals(pair.master_object_id).unwrap() & mnu_abi::HANDLE_SIGNAL_PEER_CLOSED,
        0
    );
    assert_eq!(ptys.read(pair.master_object_id, 32), Ok(vec![]));
    // A controller can reopen after the final slave close without fabricating
    // a terminal identity or reusing a released provider object's identifier.
    let reopened = ptys.reopen_slave(pair.master_object_id).unwrap();
    assert!(!ids.contains(&reopened));
    assert_eq!(
        ptys.signals(pair.master_object_id).unwrap() & mnu_abi::HANDLE_SIGNAL_PEER_CLOSED,
        0
    );
    ptys.write(pair.master_object_id, b"new").unwrap();
    assert_eq!(ptys.read(reopened, 32), Ok(b"new".to_vec()));
    assert_eq!(ptys.reopen_slave(reopened), Err(EBADF));
    assert_eq!(ptys.reopen_slave(u64::MAX), Err(EBADF));
}

#[test]
fn nonfinal_close_does_not_resume_stopped_output_and_last_close_does() {
    let mut ptys = PtyManager::new();
    let pair = ptys.open().unwrap();
    raw(&mut ptys, pair.slave_object_id);
    let second = ptys.reopen_slave(pair.master_object_id).unwrap();
    ptys.control(
        second,
        wire::PTY_CONTROL_FLOW,
        &wire::TERMINAL_FLOW_OUTPUT_STOP.to_le_bytes(),
        0,
    )
    .unwrap();
    ptys.write(second, b"queued").unwrap();
    ptys.release(pair.slave_object_id).unwrap();
    assert_eq!(ptys.read(pair.master_object_id, 32), Err(EAGAIN));
    ptys.release(second).unwrap();
    assert_eq!(ptys.read(pair.master_object_id, 32), Ok(b"queued".to_vec()));
    assert_eq!(ptys.read(pair.master_object_id, 32), Ok(vec![]));
}

#[test]
fn last_master_release_hangs_up_all_live_slaves_once_then_each_open_retires() {
    let mut ptys = PtyManager::new();
    let pair = ptys.open().unwrap();
    raw(&mut ptys, pair.slave_object_id);
    let second = ptys.reopen_slave(pair.master_object_id).unwrap();
    ptys.write(pair.master_object_id, b"tail").unwrap();
    let terminal = ptys.slave_terminal_id(second).unwrap();
    ptys.release(pair.master_object_id).unwrap();
    assert_eq!(ptys.reopen_slave(pair.master_object_id), Err(EBADF));
    assert_eq!(
        ptys.take_terminal_signal(),
        Some(posix_service::pty::TerminalSignal {
            terminal_id: terminal,
            signal: wire::SIGNAL_HUP,
        })
    );
    assert_eq!(ptys.release(pair.master_object_id), Err(EBADF));
    assert_eq!(ptys.take_terminal_signal(), None);
    for id in [pair.slave_object_id, second] {
        assert_ne!(
            ptys.signals(id).unwrap() & mnu_abi::HANDLE_SIGNAL_PEER_CLOSED,
            0
        );
    }
    assert_eq!(ptys.read(second, 2), Ok(b"ta".to_vec()));
    ptys.release(second).unwrap();
    assert_eq!(ptys.read(pair.slave_object_id, 8), Ok(b"il".to_vec()));
    assert_eq!(ptys.read(pair.slave_object_id, 8), Ok(vec![]));
    ptys.release(pair.slave_object_id).unwrap();
    assert_eq!(ptys.slave_terminal_id(pair.slave_object_id), Err(EBADF));
}

#[test]
fn readiness_targets_cover_all_live_opens_without_signalling_unrelated_terminals() {
    let mut ptys = PtyManager::new();
    let pair = ptys.open().unwrap();
    let second = ptys.reopen_slave(pair.master_object_id).unwrap();
    let other = ptys.open().unwrap();
    let expected = vec![pair.master_object_id, pair.slave_object_id, second];
    for object in &expected {
        assert_eq!(ptys.signal_object_ids(*object), Ok(expected.clone()));
    }
    assert_eq!(
        ptys.signal_object_ids(other.master_object_id),
        Ok(vec![other.master_object_id, other.slave_object_id])
    );
    ptys.release(pair.slave_object_id).unwrap();
    assert_eq!(
        ptys.signal_object_ids(second),
        Ok(vec![pair.master_object_id, second])
    );
    assert_eq!(ptys.signal_object_ids(pair.slave_object_id), Err(EBADF));
    let runtime = include_str!("../src/main.rs");
    assert!(runtime.contains("manager.signal_object_ids(header.object_id)"));
    assert!(runtime.contains("ids.into_iter()"));
}

#[test]
fn failed_creation_cleanup_matches_the_exact_pair_even_after_native_release() {
    let mut ptys = PtyManager::new();
    let pair = ptys.open().unwrap();
    let alias = ptys.reopen_slave(pair.master_object_id).unwrap();
    let other = ptys.open().unwrap();
    ptys.discard(PtyPair {
        master_object_id: pair.master_object_id,
        slave_object_id: other.slave_object_id,
    });
    assert!(ptys.attributes(alias).is_ok());
    ptys.write(other.master_object_id, b"\x03").unwrap();
    let other_terminal = ptys.slave_terminal_id(other.slave_object_id).unwrap();
    ptys.release(pair.master_object_id).unwrap();
    ptys.discard(pair);
    assert_eq!(
        ptys.take_terminal_signal(),
        Some(posix_service::pty::TerminalSignal {
            terminal_id: other_terminal,
            signal: wire::SIGNAL_INT,
        })
    );
    assert_eq!(ptys.take_terminal_signal(), None);
    for id in [pair.master_object_id, pair.slave_object_id, alias] {
        assert_eq!(ptys.attributes(id), Err(EBADF));
        assert_eq!(ptys.read(id, 1), Err(EBADF));
        assert_eq!(ptys.release(id), Err(EBADF));
    }
    assert!(ptys.attributes(other.slave_object_id).is_ok());
    ptys.discard(pair); // Idempotent failed-publication cleanup.
}
