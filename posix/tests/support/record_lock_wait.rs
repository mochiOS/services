//! Service policy only: no IPC sleeping or libc blocking support is claimed.
use super::*;
use posix_service::record_lock::{FileKey, Kind, MAX_LOCKS_PER_PROCESS, Range};
use posix_service::record_lock_wait::{MAX_WAITERS, MAX_WAITERS_PER_PROCESS, Outcome, Token};

fn setup(count: u64) -> (PosixService, Vec<PeerIdentity>, RecordingProcesses) {
    let root = PeerIdentity {
        process_id: 1,
        effective_uid: 0,
        effective_gid: 0,
    };
    let mut service = service_for(root);
    let mut peers = vec![root];
    let mut processes = RecordingProcesses::default();
    processes.states.insert(1, ProcessLifecycle::Running);
    for id in 2..=count {
        service
            .initialize_process(
                root,
                AuthenticatedProcess {
                    process_id: id,
                    handle: id as u32,
                },
                501,
                20,
                &[],
            )
            .unwrap();
        peers.push(service.registered_peer(id).unwrap());
        processes
            .states
            .insert(id as u32, ProcessLifecycle::Running);
    }
    (service, peers, processes)
}
fn file(inode: u64) -> FileKey {
    FileKey { device: 7, inode }
}
fn range(start: i64, length: i64) -> Range {
    Range::normalize(0, start, length).unwrap()
}
fn lock(service: &mut PosixService, peer: PeerIdentity, inode: u64, kind: Kind) {
    service
        .record_locks(peer)
        .unwrap()
        .set(file(inode), kind, range(0, 0))
        .unwrap();
}
fn release(service: &mut PosixService, peer: PeerIdentity, inode: u64) {
    service
        .record_locks(peer)
        .unwrap()
        .release_file(file(inode));
}
fn begin(
    service: &mut PosixService,
    peer: PeerIdentity,
    inode: u64,
    kind: Kind,
) -> Result<Outcome, i32> {
    service.begin_record_lock_wait(peer, file(inode), kind, range(0, 0))
}
fn pending(result: Result<Outcome, i32>) -> Token {
    match result.unwrap() {
        Outcome::Pending(token) => token,
        other => panic!("{other:?}"),
    }
}
fn image(peer: PeerIdentity, revision: u64) -> mnu_abi::ProcessStatus {
    mnu_abi::ProcessStatus {
        process_id: peer.process_id,
        image_revision: revision,
        state: mnu_abi::PROCESS_STATE_RUNNING,
        ..Default::default()
    }
}

#[test]
fn uncontended_shared_and_self_owned_requests_acquire_without_waiting() {
    let (mut service, peers, _) = setup(2);
    assert_eq!(
        begin(&mut service, peers[0], 1, Kind::Read),
        Ok(Outcome::Acquired)
    );
    assert_eq!(
        begin(&mut service, peers[1], 1, Kind::Read),
        Ok(Outcome::Acquired)
    );
    release(&mut service, peers[1], 1);
    assert_eq!(
        begin(&mut service, peers[0], 1, Kind::Write),
        Ok(Outcome::Acquired)
    );
    assert_eq!(
        begin(&mut service, peers[1], 2, Kind::Write),
        Ok(Outcome::Acquired)
    );
}

#[test]
fn failed_replies_never_acquire_or_upgrade_a_range_or_keep_a_pending_token() {
    use posix_service::record_lock_wait::Completion;
    let (mut service, peers, _) = setup(2);
    lock(&mut service, peers[0], 1, Kind::Read);
    assert_eq!(
        service.begin_record_lock_wait_with_reply(
            peers[0],
            file(1),
            Kind::Write,
            range(0, 0),
            || false
        ),
        Ok(Completion::Undelivered)
    );
    assert_eq!(
        service
            .record_locks(peers[1])
            .unwrap()
            .conflict(file(1), Kind::Write, range(0, 0))
            .unwrap()
            .kind,
        Kind::Read
    );
    let token = pending(begin(&mut service, peers[1], 1, Kind::Write));
    assert_eq!(
        service.retry_record_lock_wait_with_reply(peers[1], token, || panic!(
            "blocked must not reply"
        )),
        Ok(Completion::Pending(token))
    );
    release(&mut service, peers[0], 1);
    assert_eq!(
        service.retry_record_lock_wait_with_reply(peers[1], token, || false),
        Ok(Completion::Undelivered)
    );
    assert_eq!(
        service.retry_record_lock_wait(peers[1], token),
        Err(protocol::STATUS_ESRCH)
    );
    assert_eq!(
        begin(&mut service, peers[0], 1, Kind::Write),
        Ok(Outcome::Acquired)
    );
}

#[test]
fn retry_rechecks_current_conflicts_and_consumes_token_only_at_acquisition() {
    let (mut service, peers, _) = setup(3);
    lock(&mut service, peers[0], 1, Kind::Write);
    let token = pending(begin(&mut service, peers[1], 1, Kind::Write));
    assert_eq!(
        service.retry_record_lock_wait(peers[1], token),
        Ok(Outcome::Pending(token))
    );
    release(&mut service, peers[0], 1);
    // Readiness is not a grant: an independent caller wins before retry.
    lock(&mut service, peers[2], 1, Kind::Read);
    assert_eq!(
        service.retry_record_lock_wait(peers[1], token),
        Ok(Outcome::Pending(token))
    );
    release(&mut service, peers[2], 1);
    assert_eq!(
        service.retry_record_lock_wait(peers[1], token),
        Ok(Outcome::Acquired)
    );
    assert_eq!(
        service.retry_record_lock_wait(peers[1], token),
        Err(protocol::STATUS_ESRCH)
    );
    assert_eq!(
        service.cancel_record_lock_wait(peers[1], token),
        Err(protocol::STATUS_ESRCH)
    );
    assert_eq!(
        service
            .record_locks(peers[0])
            .unwrap()
            .conflict(file(1), Kind::Read, range(0, 0))
            .unwrap()
            .owner,
        peers[1].process_id
    );
}

#[test]
fn cancellation_is_owner_bound_nonreusable_and_does_not_unlock_existing_ranges() {
    let (mut service, peers, _) = setup(3);
    lock(&mut service, peers[0], 1, Kind::Write);
    lock(&mut service, peers[1], 2, Kind::Write);
    let old = pending(begin(&mut service, peers[1], 1, Kind::Read));
    assert!(Token::from_raw(0).is_none());
    assert_eq!(Token::from_raw(old.as_raw()), Some(old));
    assert_eq!(
        service.cancel_record_lock_wait(peers[2], old),
        Err(protocol::STATUS_ESRCH)
    );
    service.cancel_record_lock_wait(peers[1], old).unwrap();
    let new = pending(begin(&mut service, peers[1], 1, Kind::Read));
    assert_ne!(old, new);
    assert_eq!(
        service.cancel_record_lock_wait(peers[1], old),
        Err(protocol::STATUS_ESRCH)
    );
    assert_eq!(
        service.retry_record_lock_wait(peers[1], new),
        Ok(Outcome::Pending(new))
    );
    assert_eq!(
        service
            .record_locks(peers[2])
            .unwrap()
            .conflict(file(2), Kind::Read, range(0, 0))
            .unwrap()
            .owner,
        2
    );
}

#[test]
fn two_owner_deadlock_rejects_new_wait_without_changing_existing_locks_or_wait() {
    let (mut service, peers, _) = setup(2);
    lock(&mut service, peers[0], 1, Kind::Write);
    lock(&mut service, peers[1], 2, Kind::Write);
    let token = pending(begin(&mut service, peers[0], 2, Kind::Write));
    assert_eq!(begin(&mut service, peers[1], 1, Kind::Read), Err(-35));
    assert_eq!(
        service.retry_record_lock_wait(peers[0], token),
        Ok(Outcome::Pending(token))
    );
    release(&mut service, peers[1], 2);
    assert_eq!(
        service.retry_record_lock_wait(peers[0], token),
        Ok(Outcome::Acquired)
    );
}

#[test]
fn long_cycle_and_cycle_through_a_nonfirst_reader_are_detected() {
    let (mut service, peers, _) = setup(4);
    lock(&mut service, peers[0], 1, Kind::Write);
    lock(&mut service, peers[1], 2, Kind::Write);
    lock(&mut service, peers[2], 3, Kind::Write);
    pending(begin(&mut service, peers[0], 2, Kind::Write));
    pending(begin(&mut service, peers[1], 3, Kind::Write));
    assert_eq!(begin(&mut service, peers[2], 1, Kind::Write), Err(-35));

    let (mut service, peers, _) = setup(4);
    lock(&mut service, peers[0], 1, Kind::Read);
    lock(&mut service, peers[1], 1, Kind::Read);
    lock(&mut service, peers[2], 2, Kind::Write);
    pending(begin(&mut service, peers[1], 2, Kind::Read));
    // The first reader (owner 1) has no pending call. Owner 2 forms the cycle.
    assert_eq!(begin(&mut service, peers[2], 1, Kind::Write), Err(-35));
}

#[test]
fn four_owner_wait_graph_matches_an_independent_transitive_closure_oracle() {
    let mut random = 0xd194_5a37u32;
    for case in 0..256 {
        let (mut service, peers, _) = setup(4);
        let mut edges = [[false; 4]; 4];
        for (index, peer) in peers.iter().enumerate() {
            lock(&mut service, *peer, index as u64 + 1, Kind::Write);
        }
        let mut tokens = Vec::new();
        for step in 0..12 {
            random = random.wrapping_mul(1664525).wrapping_add(1013904223);
            let from = (random >> 24) as usize % 4;
            let to = (from + 1 + (random >> 16) as usize % 3) % 4;
            let mut closure = edges;
            for middle in 0..4 {
                for a in 0..4 {
                    for b in 0..4 {
                        closure[a][b] |= closure[a][middle] && closure[middle][b];
                    }
                }
            }
            let result = begin(&mut service, peers[from], to as u64 + 1, Kind::Write);
            if closure[to][from] {
                assert_eq!(result, Err(-35), "case {case}, step {step}");
            } else {
                tokens.push((from, to, pending(result)));
                edges[from][to] = true;
            }
            if step % 3 == 2 && !tokens.is_empty() {
                let (from, to, token) = tokens.remove(0);
                service.cancel_record_lock_wait(peers[from], token).unwrap();
                edges[from][to] = tokens.iter().any(|(a, b, _)| *a == from && *b == to);
            }
        }
        for (from, _, token) in tokens {
            assert_eq!(
                service.retry_record_lock_wait(peers[from], token),
                Ok(Outcome::Pending(token))
            );
            service.cancel_record_lock_wait(peers[from], token).unwrap();
        }
    }
}

#[test]
fn changing_ranges_and_cancellation_remove_stale_wait_graph_edges() {
    let (mut service, peers, _) = setup(3);
    lock(&mut service, peers[0], 1, Kind::Write);
    lock(&mut service, peers[1], 2, Kind::Write);
    let first = pending(begin(&mut service, peers[0], 2, Kind::Write));
    service
        .record_locks(peers[1])
        .unwrap()
        .unlock(file(2), range(0, 0))
        .unwrap();
    // The first waiter remains registered but no longer has an outgoing edge.
    let second = pending(begin(&mut service, peers[1], 1, Kind::Read));
    service.cancel_record_lock_wait(peers[1], second).unwrap();
    assert_eq!(
        service.retry_record_lock_wait(peers[0], first),
        Ok(Outcome::Acquired)
    );
    let again = pending(begin(&mut service, peers[1], 2, Kind::Write));
    service.cancel_record_lock_wait(peers[1], again).unwrap();
    assert_eq!(
        begin(&mut service, peers[0], 3, Kind::Write),
        Ok(Outcome::Acquired)
    );
}

#[test]
fn nonoverlapping_ranges_and_distinct_devices_do_not_create_false_edges() {
    let (mut service, peers, _) = setup(2);
    lock(&mut service, peers[0], 1, Kind::Write);
    lock(&mut service, peers[1], 2, Kind::Write);
    pending(begin(&mut service, peers[0], 2, Kind::Write));
    let different = FileKey {
        device: 8,
        inode: 1,
    };
    assert_eq!(
        service.begin_record_lock_wait(peers[1], different, Kind::Write, range(0, 0)),
        Ok(Outcome::Acquired)
    );
    service
        .record_locks(peers[0])
        .unwrap()
        .unlock(file(1), range(100, 0))
        .unwrap();
    assert_eq!(
        service.begin_record_lock_wait(peers[1], file(1), Kind::Write, range(100, 10)),
        Ok(Outcome::Acquired)
    );
}

#[test]
fn per_owner_and_global_quotas_are_bounded_and_cancel_recovers_a_slot() {
    let (mut service, peers, _) = setup(10);
    lock(&mut service, peers[0], 1, Kind::Write);
    let mut tokens = Vec::new();
    for peer in &peers[1..9] {
        for _ in 0..MAX_WAITERS_PER_PROCESS {
            tokens.push((*peer, pending(begin(&mut service, *peer, 1, Kind::Read))));
        }
        assert_eq!(begin(&mut service, *peer, 1, Kind::Read), Err(-37));
    }
    assert_eq!(tokens.len(), MAX_WAITERS);
    assert_eq!(begin(&mut service, peers[9], 1, Kind::Read), Err(-37));
    // Capacity is for pending state, not an artificial limit on uncontended locks.
    assert_eq!(
        begin(&mut service, peers[9], 2, Kind::Write),
        Ok(Outcome::Acquired)
    );
    let (peer, token) = tokens.remove(0);
    service.cancel_record_lock_wait(peer, token).unwrap();
    let fresh = pending(begin(&mut service, peers[9], 1, Kind::Write));
    assert_ne!(fresh, token);
    for (peer, token) in tokens {
        service.cancel_record_lock_wait(peer, token).unwrap();
    }
    service.cancel_record_lock_wait(peers[9], fresh).unwrap();
}

#[test]
fn terminal_lock_quota_failure_consumes_wait_without_partial_acquisition() {
    let (mut service, peers, _) = setup(2);
    lock(&mut service, peers[0], 1, Kind::Write);
    let token = pending(begin(&mut service, peers[1], 1, Kind::Read));
    for inode in 10..10 + MAX_LOCKS_PER_PROCESS as u64 {
        lock(&mut service, peers[1], inode, Kind::Write);
    }
    release(&mut service, peers[0], 1);
    assert_eq!(service.retry_record_lock_wait(peers[1], token), Err(-37));
    assert_eq!(
        service.cancel_record_lock_wait(peers[1], token),
        Err(protocol::STATUS_ESRCH)
    );
    assert_eq!(
        begin(&mut service, peers[0], 1, Kind::Write),
        Ok(Outcome::Acquired)
    );
}

#[test]
fn only_observed_new_image_retires_waits_and_keeps_ordinary_held_locks() {
    let (mut service, peers, mut processes) = setup(2);
    lock(&mut service, peers[0], 1, Kind::Write);
    lock(&mut service, peers[1], 2, Kind::Write);
    let token = pending(begin(&mut service, peers[1], 1, Kind::Read));
    processes.images.insert(2, Err(-5));
    assert_eq!(
        service.refresh_image_state(peers[1], &mut processes),
        Err(-5)
    );
    assert_eq!(
        service.retry_record_lock_wait(peers[1], token),
        Ok(Outcome::Pending(token))
    );
    processes.images.insert(2, Ok(image(peers[1], 1)));
    service
        .refresh_image_state(peers[1], &mut processes)
        .unwrap();
    assert_eq!(
        service.retry_record_lock_wait(peers[1], token),
        Err(protocol::STATUS_ESRCH)
    );
    assert_eq!(
        service
            .record_locks(peers[0])
            .unwrap()
            .conflict(file(2), Kind::Read, range(0, 0))
            .unwrap()
            .owner,
        2
    );
    let new = pending(begin(&mut service, peers[1], 1, Kind::Read));
    assert_ne!(new, token);
}

#[test]
fn fork_child_cannot_consume_or_cancel_its_parents_wait() {
    let (mut service, peers, _) = setup(2);
    lock(&mut service, peers[0], 1, Kind::Write);
    let token = pending(begin(&mut service, peers[1], 1, Kind::Read));
    let mut fs = RecordingFilesystem::default();
    let fork = service.prepare_fork(peers[1], &mut fs).unwrap();
    service
        .commit_fork(
            peers[1],
            fork,
            AuthenticatedProcess {
                process_id: 3,
                handle: 3,
            },
        )
        .unwrap();
    let child = service.registered_peer(3).unwrap();
    assert_eq!(
        service.cancel_record_lock_wait(child, token),
        Err(protocol::STATUS_ESRCH)
    );
    assert_eq!(
        service.retry_record_lock_wait(child, token),
        Err(protocol::STATUS_ESRCH)
    );
    assert_eq!(
        service.retry_record_lock_wait(peers[1], token),
        Ok(Outcome::Pending(token))
    );
}

#[test]
fn root_with_only_pending_lock_is_observed_until_confirmed_exit() {
    let (mut service, peers, mut processes) = setup(2);
    // Boot registration gives this process no POSIX parent or children.
    let other = peers[1];
    assert_eq!(service.parent_id(other.process_id), None);
    assert!(!service.child_lifecycle_handles().contains(&2));
    lock(&mut service, peers[0], 1, Kind::Write);
    let token = pending(begin(&mut service, other, 1, Kind::Read));
    assert!(service.child_lifecycle_handles().contains(&2));
    service
        .refresh_child_exit_notifications(&mut processes)
        .unwrap();
    assert_eq!(
        service.retry_record_lock_wait(other, token),
        Ok(Outcome::Pending(token))
    );
    processes
        .states
        .insert(2, ProcessLifecycle::Exited { exit_code: 0 });
    service
        .refresh_child_exit_notifications(&mut processes)
        .unwrap();
    assert_eq!(
        service.retry_record_lock_wait(other, token),
        Err(protocol::STATUS_ESRCH)
    );
    assert!(!service.child_lifecycle_handles().contains(&2));
}
