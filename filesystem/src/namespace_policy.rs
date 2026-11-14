//! Check the resolved object while the provider owns the serialized namespace.
//! This policy never runs in the kernel, libc, or an application wrapper.
use super::*;
use protocol::namespace_policy as policy;

fn within(path: &[u8], base: &[u8]) -> bool {
    path == base
        || path
            .strip_prefix(base)
            .is_some_and(|rest| rest.first() == Some(&b'/'))
}
impl FilesystemService {
    fn owns_home_name(&self, name: &[u8], credentials: protocol::Credentials) -> bool {
        if name.is_empty() || name == b"." || name == b".." || name.contains(&b'/') { return false; }
        let mut home = b"/home/".to_vec();
        home.extend_from_slice(name);
        matches!(self.resolve_operation_target(&home, PathAnchors::default(), FollowSymlinks::All, credentials),
            Ok(OperationTarget::Disk(inode, _, _)) if inode.file_type().is_dir() && inode.metadata().uid() == credentials.effective_uid)
    }
    fn authority_path(
        &self,
        path: &[u8],
        anchors: PathAnchors,
        follow: FollowSymlinks,
        credentials: protocol::Credentials,
    ) -> Result<Vec<u8>, i32> {
        let uid = credentials.effective_uid;
        let gid = credentials.effective_gid;
        let groups = credentials.supplementary_groups();
        let (mut result, name) = if let Some(resolution) =
            self.resolve_namespace_path(path, anchors, follow, uid, gid, groups)?
        {
            let namespace = self.namespace.as_ref().ok_or(EIO)?;
            match resolution {
                path_walk::Resolution::Found { inode, parent } => {
                    if path_walk::Backend::is_directory(namespace, &inode) {
                        (namespace.directory_path(namespace.root(), inode)?, None)
                    } else {
                        let (parent, name) = parent.ok_or(EIO)?;
                        (
                            namespace.directory_path(namespace.root(), parent)?,
                            Some(name),
                        )
                    }
                }
                path_walk::Resolution::Missing { parent, name } => (
                    namespace.directory_path(namespace.root(), parent)?,
                    Some(name),
                ),
            }
        } else {
            let (root, base) = self.resolve_anchors(path, anchors)?;
            let global_root = self.fs.read_root_inode().map_err(errno)?;
            match self.resolve_path_at(root, base, path, follow, uid, gid, groups)? {
                Resolution::Found { inode, parent } => {
                    if inode.file_type().is_dir() {
                        (
                            Self::inode_directory_path(&self.fs, global_root, inode)?,
                            None,
                        )
                    } else {
                        let (parent, name) = parent.ok_or(EIO)?;
                        (
                            Self::inode_directory_path(&self.fs, global_root, parent)?,
                            Some(name),
                        )
                    }
                }
                Resolution::Missing { parent, name } => (
                    Self::inode_directory_path(&self.fs, global_root, parent)?,
                    Some(name),
                ),
            }
        };
        if let Some(name) = name {
            if result.len() != 1 {
                result.push(b'/');
            }
            result.extend_from_slice(&name);
        }
        if result.len() > protocol::MAX_PATH_LEN {
            return Err(ENAMETOOLONG);
        }
        Ok(result)
    }

    /// `access`: 0 metadata/search; 1 read/new readable reference; 2 mutation;
    /// 3 read and mutation. `base_slot` selects old/new explicit attachments.
    pub(super) fn authorize_path(
        &self,
        path: &[u8],
        anchors: PathAnchors,
        follow: FollowSymlinks,
        credentials: protocol::Credentials,
        access: u8,
        base_slot: u32,
    ) -> Result<(), i32> {
        if anchors.base_open_id.is_some_and(|id| self.snapshot_opens.contains_key(&id)) {
            self.authorize_snapshot(anchors, credentials, path)?;
            if access & 2 != 0 { return Err(EROFS); }
            return Ok(());
        }
        let scope = credentials.namespace;
        let read = access & 1 != 0;
        let write = access & 2 != 0;
        if (!read || scope.read & policy::ALL != 0)
            && (!write || scope.write & policy::ALL != 0)
            && (access != 0 || scope.read & policy::ALL != 0)
        {
            return Ok(());
        }
        let target = self.authority_path(path, anchors, follow, credentials)?;
        if path.first() != Some(&b'/') && scope.explicit_read_bases & base_slot != 0
            && (!write || scope.explicit_write_bases & base_slot != 0) {
            if let Some(base) = anchors.base_open_id {
                let base = self.authority_path(
                    b".",
                    PathAnchors {
                        root_open_id: anchors.root_open_id,
                        base_open_id: Some(base),
                    },
                    FollowSymlinks::All,
                    credentials,
                )?;
                if within(&target, &base) || base == b"/" {
                    return Ok(());
                }
            }
        }
        // Search-only references stay private to POSIX. Metadata on these
        // public anchors must not become a readable directory authority.
        if access == 0
            && [
                b"/".as_slice(),
                b"/home",
                b"/tmp",
                b"/applications",
                b"/dev",
                b"/volumes",
            ]
            .contains(&target.as_slice())
        {
            return Ok(());
        }
        let mut required = 0;
        if within(&target, b"/tmp") || within(&target, b"/var/tmp") {
            required |= policy::TMP;
        }
        if within(&target, b"/applications") {
            required |= policy::APPLICATIONS;
        }
        if within(&target, b"/volumes") {
            required |= policy::REMOVABLE;
        }
        // Existing per-user application stores are outside /home. Bind their
        // user component to authoritative home ownership, not the USER env.
        let store_user = target.strip_prefix(b"/libraries/users/")
            .or_else(|| {
                let store = target.strip_prefix(b"/libraries/applications/")
                    .or_else(|| target.strip_prefix(b"/var/config/applications/"))?;
                let end = store.iter().position(|byte| *byte == b'/')?;
                store[end..].strip_prefix(b"/users/")
            });
        if let Some(user) = store_user {
            let end = user.iter().position(|byte| *byte == b'/').unwrap_or(user.len());
            // Reserved private stores are reached through owner-issued
            // directory authority, even for apps with broad home access.
            let private = within(&user[end..], b"/private");
            if !private && self.owns_home_name(&user[..end], credentials) { required |= policy::USER; }
        }
        if let Some(rest) = target.strip_prefix(b"/home/") {
            let name_len = rest
                .iter()
                .position(|byte| *byte == b'/')
                .unwrap_or(rest.len());
            let home = &target[..6 + name_len];
            // Home ownership is provider metadata under /home, never HOME,
            // an application-supplied name, or a second pathname RPC.
            if let Ok(OperationTarget::Disk(inode, _, _)) = self.resolve_operation_target(
                home,
                PathAnchors::default(),
                FollowSymlinks::All,
                credentials,
            ) {
                if inode.file_type().is_dir() && inode.metadata().uid() == credentials.effective_uid
                {
                    required |= policy::USER;
                    let tail = &rest[name_len..];
                    for (name, bit) in [
                        (b"/Documents".as_slice(), policy::DOCUMENTS),
                        (b"/Downloads", policy::DOWNLOADS),
                        (b"/Desktop", policy::DESKTOP),
                        (b"/Pictures", policy::PICTURES),
                        (b"/Music", policy::MUSIC),
                        (b"/Videos", policy::VIDEOS),
                        (b"/Movies", policy::VIDEOS),
                    ] {
                        if within(tail, name) {
                            required |= bit;
                        }
                    }
                }
            }
        }
        let public_read = within(&target, b"/system")
            || target == b"/dev/null"
            || target == b"/dev/zero"
            || target == b"/dev/random"
            || target == b"/dev/urandom";
        let public_write = target == b"/dev/null" || target == b"/dev/zero";
        let can_read = scope.read & policy::ALL != 0 || scope.read & required != 0 || public_read;
        let can_write =
            scope.write & policy::ALL != 0 || scope.write & required != 0 || public_write;
        if (read || access == 0) && !can_read || write && !can_write {
            return Err(EACCES);
        }
        Ok(())
    }
}
