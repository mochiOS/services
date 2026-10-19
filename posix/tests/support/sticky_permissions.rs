//! Exercise sticky-directory policy at the serialized, authenticated provider
//! boundary, including byte-for-byte non-mutation before any clock access.
use super::*;
use ext4plus::inode::InodeMode;

fn attributes(disk: &Ext4, path: &str, uid: u32, mode: u16) {
    let mut inode = disk
        .path_to_inode(
            path.try_into().unwrap(),
            FollowSymlinks::ExcludeFinalComponent,
        )
        .unwrap();
    let kind = inode.mode().bits() & 0o170000;
    inode.set_uid(uid);
    inode.set_gid(77);
    inode
        .set_mode(InodeMode::from_bits_truncate(kind | mode))
        .unwrap();
    inode.write(disk).unwrap();
}

fn remove(
    service: &mut FilesystemService,
    path: &[u8],
    directory: bool,
    uid: u32,
) -> Result<(), i32> {
    service
        .unlink_at(
            request(
                wire::OP_UNLINK_AT,
                if directory {
                    wire::UNLINK_AT_REMOVE_DIRECTORY
                } else {
                    0
                },
            ),
            path,
            PathAnchors::default(),
            credentials(uid, 77, &[88]),
        )
        .map(|_| ())
}

fn rename(service: &mut FilesystemService, old: &[u8], new: &[u8], uid: u32) -> Result<(), i32> {
    let mut payload = old.to_vec();
    payload.extend_from_slice(new);
    service
        .rename_at(
            wire::Header {
                mode: old.len() as u32,
                request_id: 93,
                ..request(wire::OP_RENAME_AT, 0)
            },
            &payload,
            RenameAnchors::default(),
            credentials(uid, 77, &[88]),
        )
        .map(|_| ())
}

fn assert_denied(fixture: &Fixture, before: &[u8], result: Result<(), i32>) {
    assert_eq!(result, Err(1));
    assert_eq!(calls(), 0);
    assert_eq!(fixture.image.0.lock().unwrap().as_slice(), before);
}

#[test]
fn unlink_rmdir_and_symlink_removal_require_entry_or_directory_owner_not_group_membership() {
    for kind in 0..3 {
        for (uid, allowed) in [
            (1001, true),
            (1002, true),
            (1003, false),
            (0, true),
            (65538, false),
        ] {
            let (fixture, disk, mut service) = metadata_fixture();
            let path = match kind {
                0 => "/work/target",
                1 => "/work/link",
                _ => {
                    service
                        .mkdir_at(
                            mode_request(wire::OP_MKDIR_AT, 0, 0o777),
                            b"/work/dir",
                            PathAnchors::default(),
                            credentials(1001, 77, &[]),
                        )
                        .unwrap();
                    "/work/dir"
                }
            };
            attributes(&disk, "/work", 1001, 0o1777);
            attributes(&disk, path, 1002, 0o777);
            let before = fixture.image.0.lock().unwrap().clone();
            set_clock(if allowed { Ok(time(101, 202)) } else { Err(5) });
            let result = remove(&mut service, path.as_bytes(), kind == 2, uid);
            if allowed {
                result.unwrap();
                assert_eq!(calls(), 1);
                assert!(
                    disk.path_to_inode(
                        path.try_into().unwrap(),
                        FollowSymlinks::ExcludeFinalComponent
                    )
                    .is_err()
                );
            } else {
                assert_denied(&fixture, &before, result);
            }
        }
    }
}

#[test]
fn rename_checks_source_sticky_directory_even_when_new_name_is_absent() {
    for (uid, allowed) in [(1001, true), (1002, true), (1003, false), (0, true)] {
        let (fixture, disk, mut service) = metadata_fixture();
        attributes(&disk, "/work", 1001, 0o1777);
        attributes(&disk, "/hidden", 1004, 0o777);
        attributes(&disk, "/work/target", 1002, 0o777);
        let before = fixture.image.0.lock().unwrap().clone();
        set_clock(if allowed { Ok(time(101, 202)) } else { Err(5) });
        let result = rename(&mut service, b"/work/target", b"/hidden/new", uid);
        if allowed {
            result.unwrap();
            assert_eq!(calls(), 1);
        } else {
            assert_denied(&fixture, &before, result);
        }
    }
}

#[test]
fn replacement_checks_destination_owner_independently_of_source_owner() {
    for (uid, allowed) in [(1001, true), (1002, true), (1003, false), (0, true)] {
        let (fixture, disk, mut service) = metadata_fixture();
        attributes(&disk, "/work", 1004, 0o777);
        attributes(&disk, "/hidden", 1001, 0o1777);
        attributes(&disk, "/work/target", uid, 0o777);
        attributes(&disk, "/hidden/target", 1002, 0o777);
        let held = open(&mut service, b"/hidden/target", false);
        let before = fixture.image.0.lock().unwrap().clone();
        set_clock(if allowed { Ok(time(101, 202)) } else { Err(5) });
        let result = rename(&mut service, b"/work/target", b"/hidden/target", uid);
        if allowed {
            result.unwrap();
            assert_eq!(calls(), 1);
            assert_eq!(status(&mut service, held).link_count, 0);
        } else {
            assert_denied(&fixture, &before, result);
            assert_eq!(status(&mut service, held).link_count, 1);
        }
    }
}

#[test]
fn symlink_owner_is_checked_without_following_its_target_and_uid_is_not_truncated() {
    for (uid, allowed) in [(65538, true), (2, false), (1002, false)] {
        let (fixture, disk, mut service) = metadata_fixture();
        attributes(&disk, "/work", 1001, 0o1777);
        attributes(&disk, "/work/target", 1002, 0o777);
        attributes(&disk, "/work/link", 65538, 0o777);
        let before = fixture.image.0.lock().unwrap().clone();
        set_clock(if allowed { Ok(time(101, 202)) } else { Err(5) });
        let result = rename(&mut service, b"/work/link", b"/work/new-link", uid);
        if allowed {
            result.unwrap();
            assert_eq!(calls(), 1);
            assert!(
                disk.path_to_inode("/work/target".try_into().unwrap(), FollowSymlinks::All)
                    .is_ok()
            );
        } else {
            assert_denied(&fixture, &before, result);
        }
    }
}

#[test]
fn directory_replacement_enforces_sticky_before_retaining_or_unlinking_destination() {
    for (uid, allowed) in [(1001, true), (1002, true), (1003, false), (0, true)] {
        let (fixture, disk, mut service) = metadata_fixture();
        for path in [b"/work/from".as_slice(), b"/hidden/to".as_slice()] {
            service
                .mkdir_at(
                    mode_request(wire::OP_MKDIR_AT, 0, 0o777),
                    path,
                    PathAnchors::default(),
                    credentials(0, 0, &[]),
                )
                .unwrap();
        }
        attributes(&disk, "/work", 1004, 0o777);
        attributes(&disk, "/hidden", 1001, 0o1777);
        attributes(&disk, "/work/from", uid, 0o777);
        attributes(&disk, "/hidden/to", 1002, 0o777);
        let held = open(&mut service, b"/hidden/to", true);
        let before = fixture.image.0.lock().unwrap().clone();
        set_clock(if allowed { Ok(time(101, 202)) } else { Err(5) });
        let result = rename(&mut service, b"/work/from", b"/hidden/to", uid);
        if allowed {
            result.unwrap();
            assert_eq!(calls(), 1);
            assert_eq!(status(&mut service, held).link_count, 0);
        } else {
            assert_denied(&fixture, &before, result);
        }
    }
}

#[test]
fn replacing_a_symlink_checks_link_owner_not_referent_owner() {
    let (fixture, disk, mut service) = metadata_fixture();
    attributes(&disk, "/hidden", 1004, 0o777);
    attributes(&disk, "/work", 1001, 0o1777);
    attributes(&disk, "/hidden/target", 1003, 0o777);
    attributes(&disk, "/work/target", 1003, 0o777);
    attributes(&disk, "/work/link", 1002, 0o777);
    let before = fixture.image.0.lock().unwrap().clone();
    set_clock(Err(5));
    assert_denied(
        &fixture,
        &before,
        rename(&mut service, b"/hidden/target", b"/work/link", 1003),
    );
}

#[test]
fn retained_directory_anchor_uses_current_sticky_mode_and_ownership_not_open_snapshot() {
    let (fixture, disk, mut service) = metadata_fixture();
    let directory = open(&mut service, b"/work", true);
    let file = open(&mut service, b"/work/target", false);
    attributes(&disk, "/work", 1002, 0o1777);
    attributes(&disk, "/work/target", 1003, 0o777);
    let before = fixture.image.0.lock().unwrap().clone();
    set_clock(Err(5));
    let result = service
        .unlink_at(
            request(wire::OP_UNLINK_AT, wire::UNLINK_AT_BASE_ATTACHED),
            b"target",
            PathAnchors {
                root_open_id: None,
                base_open_id: Some(directory),
            },
            credentials(1001, 77, &[]),
        )
        .map(|_| ());
    assert_denied(&fixture, &before, result);
    assert_eq!(status(&mut service, file).link_count, 1);
    let result = service
        .rename_at(
            wire::Header {
                mode: 6,
                ..request(
                    wire::OP_RENAME_AT,
                    wire::RENAME_AT_OLD_BASE_ATTACHED | wire::RENAME_AT_NEW_BASE_ATTACHED,
                )
            },
            b"targetnew",
            RenameAnchors {
                root_open_id: None,
                old_base_open_id: Some(directory),
                new_base_open_id: Some(directory),
            },
            credentials(1001, 77, &[]),
        )
        .map(|_| ());
    assert_denied(&fixture, &before, result);
    // Removing sticky protection restores normal directory write semantics;
    // the entry itself need not be writable or owned by the caller.
    attributes(&disk, "/work", 1002, 0o777);
    attributes(&disk, "/work/target", 1003, 0);
    set_clock(Ok(time(102, 203)));
    remove(&mut service, b"/work/target", false, 1001).unwrap();
}

#[test]
fn sticky_owner_still_needs_parent_write_and_search_permissions() {
    for mode in [0o1555, 0o1666] {
        let (fixture, disk, mut service) = metadata_fixture();
        attributes(&disk, "/work", 1001, mode);
        attributes(&disk, "/work/target", 1001, 0o777);
        let before = fixture.image.0.lock().unwrap().clone();
        set_clock(Err(5));
        assert_eq!(remove(&mut service, b"/work/target", false, 1001), Err(13));
        assert_eq!(
            rename(&mut service, b"/work/target", b"/work/new", 1001),
            Err(13)
        );
        assert_eq!(calls(), 0);
        assert_eq!(*fixture.image.0.lock().unwrap(), before);
    }
}
