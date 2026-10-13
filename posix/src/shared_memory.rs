//! Shared-memory names and POSIX permissions belong to the userspace service.
//! Backing references, not paths or client FD numbers, identify resources.

use super::{PeerIdentity, PosixService, Session};
use std::collections::BTreeMap;

pub const MAX_NAME_BYTES: usize = 255;
pub const MAX_NAMES: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    ReadOnly,
    ReadWrite,
}

#[derive(Clone, Copy, Debug)]
pub struct Open {
    pub access: Access,
    pub create: bool,
    pub exclusive: bool,
    pub truncate: bool,
    pub mode: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Opened<H> {
    /// Borrowed namespace reference. The adapter creates a new descriptor
    /// reference with these rights; it must never transfer the owning reference.
    pub backing: H,
    pub rights: u64,
    pub created: bool,
}

#[derive(Debug)]
struct Entry<H> {
    backing: H,
    owner: u32,
    group: u32,
    mode: u32,
}

#[derive(Debug)]
pub(super) struct Namespace<H> {
    names: BTreeMap<Vec<u8>, Entry<H>>,
}

impl<H> Namespace<H> {
    pub(super) const fn new() -> Self {
        Self {
            names: BTreeMap::new(),
        }
    }
}

/// Owns native resources. Failed creation must release its temporary resources.
/// Truncation affects the same object, never replaces backing under its name.
pub trait Backing<H> {
    fn create_zero_length(&mut self) -> Result<H, i32>;
    fn truncate_zero(&mut self, backing: H) -> Result<(), i32>;
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

fn rights(access: Access) -> u64 {
    let common = mnu_abi::HANDLE_RIGHT_READ
        | mnu_abi::HANDLE_RIGHT_MAP
        | mnu_abi::HANDLE_RIGHT_DUPLICATE
        | mnu_abi::HANDLE_RIGHT_TRANSFER;
    common
        | if access == Access::ReadWrite {
            mnu_abi::HANDLE_RIGHT_WRITE
        } else {
            0
        }
}

impl<H: Copy> PosixService<H> {
    pub fn open_shared_memory<B: Backing<H>>(
        &mut self,
        peer: PeerIdentity,
        name: &[u8],
        options: Open,
        backend: &mut B,
    ) -> Result<Opened<H>, i32> {
        let session = self.shared_memory_session(peer)?;
        validate_name(name)?;
        // O_WRONLY is not a shm access mode. The wire adapter must decode only
        // O_RDONLY/O_RDWR. Reject unspecified EXCL and read-only truncation.
        if options.exclusive && !options.create
            || options.truncate && options.access != Access::ReadWrite
        {
            return Err(-22);
        }
        if let Some(entry) = self.shared_memory.names.get(name) {
            if options.create && options.exclusive {
                return Err(-17);
            }
            let groups = self
                .supplementary_groups
                .get(&peer.process_id)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            let shift = if session.effective_uid == entry.owner {
                6
            } else if session.effective_gid == entry.group || groups.contains(&entry.group) {
                3
            } else {
                0
            };
            let required = if options.access == Access::ReadWrite {
                6
            } else {
                4
            };
            if session.effective_uid != 0 && (entry.mode >> shift) & required != required {
                return Err(-13);
            }
            // Serialize permission checks and truncate under the namespace
            // lock. An error keeps the name and original resource reference.
            if options.truncate {
                backend.truncate_zero(entry.backing)?;
            }
            return Ok(Opened {
                backing: entry.backing,
                rights: rights(options.access),
                created: false,
            });
        }
        if !options.create {
            return Err(-2);
        }
        if self.shared_memory.names.len() >= MAX_NAMES {
            return Err(-28);
        }
        let backing = backend.create_zero_length()?;
        // POSIX-created shm starts at length zero, even for read-only opens.
        // Publish only after successful allocation; no stat/create TOCTOU.
        self.shared_memory.names.insert(
            name.to_vec(),
            Entry {
                backing,
                owner: session.effective_uid,
                group: session.effective_gid,
                mode: (options.mode & 0o777) & !(session.umask & 0o777),
            },
        );
        Ok(Opened {
            backing,
            rights: rights(options.access),
            created: true,
        })
    }

    pub fn unlink_shared_memory(&mut self, peer: PeerIdentity, name: &[u8]) -> Result<H, i32> {
        let session = self.shared_memory_session(peer)?;
        validate_name(name)?;
        let entry = self.shared_memory.names.get(name).ok_or(-2)?;
        // Sticky shared-namespace policy. Mode bits never authorize deleting
        // somebody else's name. UID/GID here are registered service state.
        if session.effective_uid != 0 && session.effective_uid != entry.owner {
            return Err(-13);
        }
        // Caller closes only this namespace reference. Previously delegated
        // references and mappings keep the old object alive independently.
        Ok(self.shared_memory.names.remove(name).unwrap().backing)
    }

    fn shared_memory_session(&self, peer: PeerIdentity) -> Result<Session, i32> {
        if !self.processes.contains_key(&peer.process_id) {
            return Err(-3);
        }
        self.sessions.get(&peer.process_id).copied().ok_or(-3)
    }
}
