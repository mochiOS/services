//! Real service-owned lock state. No file IPC or libc fcntl support is claimed.
use super::*;
use posix_service::record_lock::{
    Conflict, Error, FileKey, Kind, MAX_LOCKS, MAX_LOCKS_PER_PROCESS, Range,
};

fn root() -> PeerIdentity {
    PeerIdentity {
        process_id: 1,
        effective_uid: 0,
        effective_gid: 0,
    }
}
fn setup(count: u64) -> PosixService {
    let mut service = service_for(root());
    for pid in 2..=count {
        service
            .initialize_process(
                root(),
                AuthenticatedProcess {
                    process_id: pid,
                    handle: pid as u32,
                },
                501,
                20,
                &[],
            )
            .unwrap();
    }
    service
}
fn peer(service: &PosixService, pid: u64) -> PeerIdentity {
    service.registered_peer(pid).unwrap()
}
fn file(inode: u64) -> FileKey {
    FileKey { device: 7, inode }
}
fn range(start: i64, length: i64) -> Range {
    Range::normalize(0, start, length).unwrap()
}
fn set(
    service: &mut PosixService,
    owner: u64,
    file: FileKey,
    kind: Kind,
    range: Range,
) -> Result<(), Error> {
    let peer = peer(service, owner);
    service.record_locks(peer).unwrap().set(file, kind, range)
}
fn conflict(
    service: &mut PosixService,
    owner: u64,
    file: FileKey,
    kind: Kind,
    range: Range,
) -> Option<Conflict> {
    let peer = peer(service, owner);
    service
        .record_locks(peer)
        .unwrap()
        .conflict(file, kind, range)
}

#[test]
fn normalization_preserves_negative_lengths_future_growth_and_full_off_t_domain() {
    assert_eq!(
        Range::normalize(100, -10, -20).unwrap().offset_length(),
        (70, 20)
    );
    assert_eq!(
        Range::normalize(100, -10, 0).unwrap().offset_length(),
        (90, 0)
    );
    assert_eq!(range(i64::MAX, 1).offset_length(), (i64::MAX, 0));
    assert_eq!(range(0, i64::MAX).offset_length(), (0, i64::MAX));
    for (base, offset, length, error) in [
        (-1, 0, 1, Error::InvalidRange),
        (0, -1, 0, Error::InvalidRange),
        (0, 10, -11, Error::InvalidRange),
        (0, i64::MAX, i64::MIN, Error::InvalidRange),
        (i64::MAX, 1, -1, Error::Overflow),
        (i64::MAX, 0, 2, Error::Overflow),
    ] {
        assert_eq!(Range::normalize(base, offset, length), Err(error));
    }
}

#[test]
fn shared_readers_and_exclusive_writers_are_isolated_by_file_and_process() {
    let mut service = setup(3);
    set(&mut service, 1, file(1), Kind::Read, range(10, 20)).unwrap();
    set(&mut service, 2, file(1), Kind::Read, range(10, 20)).unwrap();
    assert!(conflict(&mut service, 3, file(1), Kind::Read, range(10, 20)).is_none());
    let old = conflict(&mut service, 3, file(1), Kind::Write, range(10, 20)).unwrap();
    assert_eq!(
        (old.owner, old.kind, old.range.offset_length()),
        (1, Kind::Read, (10, 20))
    );
    assert_eq!(
        set(&mut service, 1, file(1), Kind::Write, range(10, 20)),
        Err(Error::WouldBlock(Conflict {
            owner: 2,
            kind: Kind::Read,
            range: range(10, 20)
        }))
    );
    assert_eq!(
        conflict(&mut service, 3, file(1), Kind::Write, range(10, 20)),
        Some(old)
    );
    assert!(conflict(&mut service, 3, file(1), Kind::Write, range(30, 1)).is_none());
    for different in [
        file(2),
        FileKey {
            device: 8,
            inode: 1,
        },
    ] {
        set(&mut service, 3, different, Kind::Write, range(10, 20)).unwrap();
    }
}

#[test]
fn replacing_own_ranges_splits_changes_mode_merges_and_unlocks_without_touching_others() {
    let mut service = setup(2);
    let root = root();
    set(&mut service, 1, file(1), Kind::Write, range(0, 100)).unwrap();
    set(&mut service, 1, file(1), Kind::Read, range(20, 20)).unwrap();
    assert!(conflict(&mut service, 2, file(1), Kind::Read, range(25, 1)).is_none());
    assert_eq!(
        conflict(&mut service, 2, file(1), Kind::Write, range(25, 1))
            .unwrap()
            .range,
        range(20, 20)
    );
    set(&mut service, 1, file(1), Kind::Write, range(0, 100)).unwrap();
    service
        .record_locks(root)
        .unwrap()
        .unlock(file(1), range(40, 20))
        .unwrap();
    assert_eq!(
        conflict(&mut service, 2, file(1), Kind::Read, range(25, 1))
            .unwrap()
            .range,
        range(0, 40)
    );
    assert!(conflict(&mut service, 2, file(1), Kind::Read, range(50, 1)).is_none());
    assert_eq!(
        conflict(&mut service, 2, file(1), Kind::Read, range(75, 1))
            .unwrap()
            .range,
        range(60, 40)
    );
    set(&mut service, 1, file(1), Kind::Write, range(40, 20)).unwrap();
    set(&mut service, 1, file(1), Kind::Write, range(100, 0)).unwrap();
    assert_eq!(
        conflict(&mut service, 2, file(1), Kind::Read, range(i64::MAX, 1))
            .unwrap()
            .range
            .offset_length(),
        (0, 0)
    );
    service
        .record_locks(root)
        .unwrap()
        .unlock(file(1), range(0, 0))
        .unwrap();
    assert!(conflict(&mut service, 2, file(1), Kind::Write, range(0, 0)).is_none());
}

#[test]
fn closing_any_description_releases_only_that_process_and_file_even_with_fake_root_uid() {
    let mut service = setup(3);
    for owner in [1, 2] {
        set(&mut service, owner, file(1), Kind::Read, range(0, 10)).unwrap();
    }
    set(&mut service, 1, file(2), Kind::Write, range(0, 10)).unwrap();
    let forged_uid = PeerIdentity {
        effective_uid: 0,
        ..peer(&service, 3)
    };
    service
        .record_locks(forged_uid)
        .unwrap()
        .release_file(file(1));
    assert_eq!(
        conflict(&mut service, 3, file(1), Kind::Write, range(0, 10))
            .unwrap()
            .owner,
        1
    );
    service.record_locks(root()).unwrap().release_file(file(1));
    assert_eq!(
        conflict(&mut service, 3, file(1), Kind::Write, range(0, 10))
            .unwrap()
            .owner,
        2
    );
    assert_eq!(
        conflict(&mut service, 3, file(2), Kind::Read, range(0, 10))
            .unwrap()
            .owner,
        1
    );
}

#[test]
fn image_replacement_preserves_process_locks_and_native_exit_releases_unparented_owners() {
    let mut service = setup(2);
    let mut processes = RecordingProcesses::default();
    set(&mut service, 1, file(1), Kind::Write, range(0, 0)).unwrap();
    assert!(service.child_lifecycle_handles().contains(&1));
    processes.images.insert(
        1,
        Ok(mnu_abi::ProcessStatus {
            process_id: 1,
            state: mnu_abi::PROCESS_STATE_RUNNING,
            image_revision: 1,
            ..Default::default()
        }),
    );
    service.refresh_image_state(root(), &mut processes).unwrap();
    assert_eq!(
        conflict(&mut service, 2, file(1), Kind::Read, range(0, 1))
            .unwrap()
            .owner,
        1
    );
    processes
        .states
        .insert(1, ProcessLifecycle::Exited { exit_code: 0 });
    processes.images.insert(
        1,
        Ok(mnu_abi::ProcessStatus {
            process_id: 1,
            state: mnu_abi::PROCESS_STATE_EXITED,
            image_revision: 1,
            ..Default::default()
        }),
    );
    service
        .refresh_child_exit_notifications(&mut processes)
        .unwrap();
    assert!(conflict(&mut service, 2, file(1), Kind::Read, range(0, 1)).is_none());
    assert_eq!(
        service.record_locks(root()).err(),
        Some(protocol::STATUS_ESRCH)
    );
    assert!(!service.child_lifecycle_handles().contains(&1));
}

#[test]
fn process_quota_failure_is_atomic_but_merging_and_full_unlock_can_recover_space() {
    let mut service = setup(2);
    for index in 0..MAX_LOCKS_PER_PROCESS {
        set(
            &mut service,
            1,
            file(1),
            Kind::Read,
            range(index as i64 * 4, 3),
        )
        .unwrap();
    }
    assert_eq!(
        set(&mut service, 1, file(2), Kind::Read, range(0, 1)),
        Err(Error::NoLocks)
    );
    assert_eq!(
        service
            .record_locks(root())
            .unwrap()
            .unlock(file(1), range(1, 1)),
        Err(Error::NoLocks)
    );
    assert_eq!(
        conflict(&mut service, 2, file(1), Kind::Write, range(1, 1))
            .unwrap()
            .range,
        range(0, 3)
    );
    set(&mut service, 1, file(1), Kind::Read, range(3, 1)).unwrap();
    assert_eq!(
        conflict(&mut service, 2, file(1), Kind::Write, range(1, 1))
            .unwrap()
            .range,
        range(0, 7)
    );
    set(&mut service, 1, file(2), Kind::Read, range(0, 1)).unwrap();
    service.record_locks(root()).unwrap().release_file(file(1));
    set(&mut service, 1, file(3), Kind::Write, range(0, 0)).unwrap();
}

#[test]
fn global_quota_cannot_be_bypassed_with_new_owners_or_duplicate_normalized_requests() {
    let owners = MAX_LOCKS / MAX_LOCKS_PER_PROCESS;
    let mut service = setup(owners as u64 + 1);
    for owner in 1..=owners as u64 {
        for index in 0..MAX_LOCKS_PER_PROCESS {
            set(
                &mut service,
                owner,
                file(1),
                Kind::Read,
                range(index as i64 * 2, 1),
            )
            .unwrap();
        }
    }
    set(&mut service, 1, file(1), Kind::Read, range(0, 1)).unwrap();
    assert_eq!(
        set(
            &mut service,
            owners as u64 + 1,
            file(2),
            Kind::Read,
            range(0, 1)
        ),
        Err(Error::NoLocks)
    );
    service.record_locks(root()).unwrap().release_file(file(1));
    set(
        &mut service,
        owners as u64 + 1,
        file(2),
        Kind::Read,
        range(0, 1),
    )
    .unwrap();
}

#[test]
fn range_operations_match_a_bytewise_multi_owner_oracle() {
    let mut service = setup(4);
    let mut oracle = [[[None; 8]; 2]; 4];
    let mut seed = 0x6a09e667f3bcc909u64;
    for _ in 0..4000 {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let owner = seed as usize % 4;
        let which = (seed >> 8) as usize % 2;
        let start = (seed >> 16) as usize % 8;
        let length = 1 + (seed >> 24) as usize % (8 - start);
        let kind = match (seed >> 32) % 3 {
            0 => None,
            1 => Some(Kind::Read),
            _ => Some(Kind::Write),
        };
        let blocked = kind.is_some_and(|kind| {
            (0..4).any(|other| {
                other != owner
                    && (start..start + length).any(|byte| {
                        oracle[other][which][byte]
                            .is_some_and(|old| kind == Kind::Write || old == Kind::Write)
                    })
            })
        });
        let peer = peer(&service, owner as u64 + 1);
        let mut locks = service.record_locks(peer).unwrap();
        let result = match kind {
            Some(kind) => locks.set(
                file(which as u64 + 1),
                kind,
                range(start as i64, length as i64),
            ),
            None => locks.unlock(file(which as u64 + 1), range(start as i64, length as i64)),
        };
        assert_eq!(matches!(result, Err(Error::WouldBlock(_))), blocked);
        if !blocked {
            result.unwrap();
            oracle[owner][which][start..start + length].fill(kind);
        }
        for actor in 0..4 {
            for which in 0..2 {
                for byte in 0..8 {
                    for kind in [Kind::Read, Kind::Write] {
                        let expected = (0..4).any(|other| {
                            other != actor
                                && oracle[other][which][byte]
                                    .is_some_and(|old| kind == Kind::Write || old == Kind::Write)
                        });
                        let found = conflict(
                            &mut service,
                            actor as u64 + 1,
                            file(which as u64 + 1),
                            kind,
                            range(byte as i64, 1),
                        );
                        assert_eq!(found.is_some(), expected);
                        if let Some(found) = found {
                            assert_ne!(found.owner, actor as u64 + 1);
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn verified_exit_releases_locks_even_if_parent_notification_fails_but_unknown_exit_does_not() {
    let mut service = service_for(root());
    assert_eq!(
        service
            .handle(
                root(),
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
        .adopt_child(
            root(),
            AuthenticatedProcess {
                process_id: 2,
                handle: 2,
            },
            &mut filesystem,
        )
        .unwrap();
    service
        .initialize_process(
            root(),
            AuthenticatedProcess {
                process_id: 3,
                handle: 3,
            },
            501,
            20,
            &[],
        )
        .unwrap();
    set(&mut service, 2, file(1), Kind::Write, range(0, 0)).unwrap();
    let mut processes = RecordingProcesses::default();
    assert_eq!(
        service.refresh_child_exit_notifications(&mut processes),
        Err(protocol::STATUS_ESRCH)
    );
    assert_eq!(
        conflict(&mut service, 3, file(1), Kind::Read, range(0, 1))
            .unwrap()
            .owner,
        2
    );
    processes
        .states
        .insert(2, ProcessLifecycle::Exited { exit_code: 0 });
    processes.images.insert(1, Err(protocol::STATUS_EIO));
    assert_eq!(
        service.refresh_child_exit_notifications(&mut processes),
        Err(protocol::STATUS_EIO)
    );
    assert!(conflict(&mut service, 3, file(1), Kind::Read, range(0, 1)).is_none());
}
