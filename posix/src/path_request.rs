//! Owned pathname anchors across filesystem RPC, without holding POSIX state.
use super::*;
use std::sync::Mutex;

struct References<'a, H: Copy, F: FilesystemBackend<H>> {
    filesystem: &'a mut F,
    owned: Vec<AttachedObject<H>>,
}

impl<H: Copy, F: FilesystemBackend<H>> References<'_, H, F> {
    fn retain(&mut self, source: AttachedObject<H>) -> Result<AttachedObject<H>, i32> {
        // Local native reference management only, never a peer RPC.
        let retained = self.filesystem.retain_object(source)?;
        self.owned.push(retained);
        if retained.rights != source.rights {
            return Err(protocol::STATUS_EIO);
        }
        Ok(retained)
    }
}

impl<H: Copy, F: FilesystemBackend<H>> Drop for References<'_, H, F> {
    fn drop(&mut self) {
        for object in self.owned.drain(..) {
            self.filesystem.release_object(object);
        }
    }
}

#[derive(PartialEq, Eq)]
struct RootCredentials {
    uid: u32,
    gid: u32,
    groups: Vec<u32>,
}

impl RootCredentials {
    fn capture<H: Copy>(service: &PosixService<H>, peer: PeerIdentity) -> Result<Self, i32> {
        let session = service
            .sessions
            .get(&peer.process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        Ok(Self {
            uid: session.effective_uid,
            gid: session.effective_gid,
            groups: service
                .supplementary_groups
                .get(&peer.process_id)
                .cloned()
                .unwrap_or_default(),
        })
    }
}

/// `prepare` only reads POSIX policy under the lock. The operation receives a
/// matching policy/anchor snapshot outside it. Explicit incoming directories
/// stay borrowed from the receive; service-owned root/cwd are locally retained.
pub(crate) fn with_paths<H: Copy, F: FilesystemBackend<H>, P: PartialEq, R>(
    state: &Mutex<PosixService<H>>,
    peer: PeerIdentity,
    handles: &[AttachedObject<H>],
    filesystem: &mut F,
    prepare: impl Fn(&PosixService<H>) -> Result<(P, protocol::OpenBase), i32>,
    operation: impl FnOnce(&P, PathObjects<H>, &mut F) -> R,
) -> Result<R, i32> {
    let mut references = References {
        filesystem,
        owned: Vec::new(),
    };
    references.owned.try_reserve_exact(4).map_err(|_| -12)?;
    let initial = {
        let service = state.lock().map_err(|_| protocol::STATUS_EIO)?;
        let prepared = prepare(&service)?;
        if service.directories.contains_key(&peer.process_id) {
            None
        } else {
            Some((prepared, RootCredentials::capture(&service, peer)?))
        }
    };
    if let Some((initial, credentials)) = initial {
        // Root authorization always uses effective credentials, even when the
        // actual operation (access without EACCESS) uses real credentials.
        let roots = references.filesystem.open_session_root(
            credentials.uid,
            credentials.gid,
            &credentials.groups,
        )?;
        references.owned.extend([roots.root, roots.cwd]);
        let mut service = state.lock().map_err(|_| protocol::STATUS_EIO)?;
        if prepare(&service)? != initial || RootCredentials::capture(&service, peer)? != credentials
        {
            return Err(protocol::STATUS_EAGAIN);
        }
        if let std::collections::btree_map::Entry::Vacant(entry) =
            service.directories.entry(peer.process_id)
        {
            entry.insert(roots);
            references.owned.clear(); // session now owns both references
        }
    }
    let (prepared, paths) = {
        let service = state.lock().map_err(|_| protocol::STATUS_EIO)?;
        let (prepared, base) = prepare(&service)?;
        let mut paths = service.path_objects(peer.process_id, base, handles)?;
        paths.root = references.retain(paths.root)?;
        if base == protocol::OpenBase::ProcessCwd {
            paths.base = Some(references.retain(paths.base.ok_or(protocol::STATUS_EIO)?)?);
        }
        (prepared, paths)
    };
    Ok(operation(&prepared, paths, references.filesystem))
}
