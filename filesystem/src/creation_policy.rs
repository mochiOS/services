//! Creation identity selected while the resolved parent is serialized.
//! This does not grant access: the caller must first check parent permissions
//! using the authenticated credentials and the actual target filesystem.
use ext4plus::Metadata;

pub(super) fn identity(
    parent: Metadata,
    directory: bool,
    requested_mode: u32,
    uid: u32,
    effective_gid: u32,
    groups: &[u32],
) -> (u16, u32) {
    let inherit_group = parent.mode() & 0o2000 != 0;
    let gid = if inherit_group {
        parent.gid()
    } else {
        effective_gid
    };
    let mut mode = (requested_mode & 0o7777) as u16;
    if directory && inherit_group {
        mode |= 0o2000;
    } else if uid != 0 && gid != effective_gid && !groups.contains(&gid) {
        // Inheriting a directory's group is not permission to create a
        // setgid executable for a group the caller does not belong to.
        mode &= !0o2000;
    }
    (mode, gid)
}
