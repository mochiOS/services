#[path = "../../../user/crates/newlib-runtime/src/library_identity.rs"]
mod identity;

#[test]
fn aliases_and_changed_bytes_of_one_inode_cannot_create_another_dependency_owner() {
    let mut first = identity::Files::default();
    assert!(first.insert((7, 31)));
    assert!(first.insert((7, 32)));
    assert!(!first.insert((7, 31))); // hard link or dependency cycle
    let mut next = identity::Files::default();
    assert!(next.insert((7, 99)));
    assert!(!next.intersects(&first));
    assert!(next.insert((7, 32))); // same opened inode, even after an update
    assert!(next.intersects(&first));
    assert!(first.intersects(&next));
    let mut other_mount = identity::Files::default();
    assert!(other_mount.insert((8, 32)));
    assert!(!other_mount.intersects(&first));
}

#[test]
fn unknown_or_excessive_file_identities_are_rejected_without_losing_the_retained_set() {
    let mut files = identity::Files::default();
    assert!(!files.insert((0, 0)));
    for inode in 1..=identity::MAX_FILES {
        assert!(files.insert((1, inode as u64)));
    }
    assert!(!files.insert((1, 999)));
    let mut retained = identity::Files::default();
    assert!(retained.insert((1, 1)));
    assert!(files.intersects(&retained));
}
