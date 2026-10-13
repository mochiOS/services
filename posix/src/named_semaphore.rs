//! POSIX-owned names and permissions for shared semaphore MemoryObjects.
//! The kernel sees only backing objects and explicitly transferred Handles.

use super::{PeerIdentity, PosixService, Session};
use std::collections::BTreeMap;

pub const MAX_NAME_BYTES: usize = 255;
pub const MAX_NAMES: usize = 1024;

#[derive(Clone, Copy, Debug)]
pub struct Create {
    pub mode: u32,
    pub value: u32,
    pub exclusive: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Opened<H> {
    /// Borrowed service-local backing Handle. The transport must explicitly
    /// delegate MAP rights; this number is never a client FD/global object ID.
    pub handle: H,
    pub created: bool,
}

#[derive(Debug)]
struct Entry<H> {
    handle: H,
    owner: u32,
    group: u32,
    mode: u32,
}

#[derive(Debug)]
pub(super) struct Namespace<H> {
    names: BTreeMap<Vec<u8>, Entry<H>>,
}

impl<H: Copy> Namespace<H> {
    pub(super) const fn new() -> Self {
        Self {
            names: BTreeMap::new(),
        }
    }

    fn open(
        &mut self,
        name: &[u8],
        session: Session,
        groups: &[u32],
        create: Option<Create>,
        allocate: impl FnOnce(u32) -> Result<H, i32>,
    ) -> Result<Opened<H>, i32> {
        validate_name(name)?;
        if let Some(entry) = self.names.get(name) {
            if create.is_some_and(|create| create.exclusive) {
                return Err(-17); // EEXIST; do not allocate or mutate existing state.
            }
            if !can_open(entry, session, groups) {
                return Err(-13);
            }
            // Existing objects ignore the requested initial value and mode.
            return Ok(Opened {
                handle: entry.handle,
                created: false,
            });
        }
        let create = create.ok_or(-2)?;
        if create.value > i32::MAX as u32 {
            return Err(-22);
        }
        if self.names.len() >= MAX_NAMES {
            return Err(-28);
        }
        // Caller holds the service's namespace lock through initialization.
        // Publish only after allocation and initialization succeed; no stat /
        // create split and no visible zero/uninitialized semaphore on failure.
        let handle = allocate(create.value)?;
        self.names.insert(
            name.to_vec(),
            Entry {
                handle,
                owner: session.effective_uid,
                group: session.effective_gid,
                mode: (create.mode & 0o777) & !(session.umask & 0o777),
            },
        );
        Ok(Opened {
            handle,
            created: true,
        })
    }

    fn unlink(&mut self, name: &[u8], session: Session) -> Result<H, i32> {
        validate_name(name)?;
        let entry = self.names.get(name).ok_or(-2)?;
        // Userspace shared-namespace policy: sticky ownership, like a shared
        // temporary directory. Writable mode alone grants no unlink authority.
        if session.effective_uid != 0 && session.effective_uid != entry.owner {
            return Err(-13);
        }
        Ok(self.names.remove(name).unwrap().handle)
    }
}

fn validate_name(name: &[u8]) -> Result<(), i32> {
    if name.first() != Some(&b'/')
        || name.len() < 2
        || name[1..].iter().any(|byte| matches!(byte, b'/' | 0))
    {
        return Err(-22);
    }
    if name.len() - 1 > MAX_NAME_BYTES {
        return Err(-36);
    }
    Ok(())
}

fn can_open<H>(entry: &Entry<H>, session: Session, groups: &[u32]) -> bool {
    if session.effective_uid == 0 {
        return true;
    }
    let shift = if session.effective_uid == entry.owner {
        6
    } else if session.effective_gid == entry.group || groups.contains(&entry.group) {
        3
    } else {
        0
    };
    // sem_open maps mutable counting state: require read AND write permission.
    ((entry.mode >> shift) & 0o6) == 0o6
}

impl<H: Copy> PosixService<H> {
    /// `peer.process_id` must come from authenticated IPC metadata. UID/GID in
    /// the request/PeerIdentity are not trusted: consult registered state only.
    /// `allocate` returns an owned, initialized shared backing Handle; failure
    /// must release any temporary backing/mapping before returning an error.
    pub fn open_named_semaphore(
        &mut self,
        peer: PeerIdentity,
        name: &[u8],
        create: Option<Create>,
        allocate: impl FnOnce(u32) -> Result<H, i32>,
    ) -> Result<Opened<H>, i32> {
        let session = self.sessions.get(&peer.process_id).copied().ok_or(-3)?;
        if !self.processes.contains_key(&peer.process_id) {
            return Err(-3);
        }
        let groups = self
            .supplementary_groups
            .get(&peer.process_id)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        self.named_semaphores
            .open(name, session, groups, create, allocate)
    }

    /// Removes only the name and returns service ownership of its backing
    /// Handle for close. Already delegated Handles/mappings remain valid;
    /// creating the same name again must allocate a distinct MemoryObject.
    pub fn unlink_named_semaphore(&mut self, peer: PeerIdentity, name: &[u8]) -> Result<H, i32> {
        let session = self.sessions.get(&peer.process_id).copied().ok_or(-3)?;
        if !self.processes.contains_key(&peer.process_id) {
            return Err(-3);
        }
        self.named_semaphores.unlink(name, session)
    }
}
