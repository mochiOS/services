//! Shared-memory names and POSIX permissions belong to the userspace service.
//! Backing references, not paths or client FD numbers, identify resources.

use super::{PeerIdentity, PosixService, Session};
use std::collections::BTreeMap;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU32, Ordering},
};

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

#[derive(Clone, Debug)]
pub struct Opened<H> {
    /// Borrowed namespace reference. The adapter creates a new descriptor
    /// reference with these rights; it must never transfer the owning reference.
    pub backing: H,
    pub rights: u64,
    pub created: bool,
    pub metadata: Arc<Metadata>,
}

impl<H: PartialEq> PartialEq for Opened<H> {
    fn eq(&self, other: &Self) -> bool {
        self.backing == other.backing
            && self.rights == other.rights
            && self.created == other.created
            && Arc::ptr_eq(&self.metadata, &other.metadata)
    }
}
impl<H: Eq> Eq for Opened<H> {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attributes {
    pub owner: u32,
    pub group: u32,
    pub mode: u32,
}

/// Namespace identity survives unlink through open-description references.
/// Attributes are shared, not snapshots copied into each descriptor.
#[derive(Debug)]
pub struct Metadata {
    pub inode: u64,
    pub attributes: Mutex<Attributes>,
    links: AtomicU32,
}
impl Metadata {
    pub fn links(&self) -> u32 {
        self.links.load(Ordering::Acquire)
    }
}

#[derive(Debug)]
struct Entry<H> {
    backing: H,
    metadata: Arc<Metadata>,
}

#[derive(Debug)]
pub(super) struct Namespace<H> {
    names: BTreeMap<Vec<u8>, Entry<H>>,
    next_inode: u64,
}

impl<H> Namespace<H> {
    pub(super) const fn new() -> Self {
        Self {
            names: BTreeMap::new(),
            next_inode: 1,
        }
    }

    fn detach(&mut self, name: &[u8]) -> Option<Entry<H>> {
        let entry = self.names.remove(name)?;
        entry.metadata.links.store(0, Ordering::Release);
        Some(entry)
    }
}

/// Owns native resources. Failed creation must release its temporary resources.
/// Truncation affects the same object, never replaces backing under its name.
pub trait Backing<H> {
    fn create_zero_length(&mut self) -> Result<H, i32>;
    fn truncate_zero(&mut self, backing: H) -> Result<(), i32>;
}

/// Creates independent reply descriptions backed by the namespace resource.
/// A namespace Handle must never be handed out as a temporary attachment.
pub trait Delegation<H>: Backing<H> {
    fn open_description(
        &mut self,
        backing: H,
        rights: u64,
        metadata: Arc<Metadata>,
    ) -> Result<H, i32>;
    fn close(&mut self, backing: H) -> Result<(), i32>;
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
    mochios_posix_protocol::shared_memory::descriptor_rights(access == Access::ReadWrite)
}

impl<H: Copy> PosixService<H> {
    /// Atomically resolve/create a name and retain an independent open
    /// description. The caller serializes this with unlink and Provider IO.
    /// Native Provider creation subsequently binds the returned ID; client FD
    /// numbers and client-supplied object IDs never enter this operation.
    pub fn open_shared_memory_description<B>(
        &mut self,
        peer: PeerIdentity,
        name: &[u8],
        options: Open,
        descriptions: &mut super::shared_memory_file::Descriptions<H>,
        backend: &mut B,
    ) -> Result<u64, i32>
    where
        B: Delegation<H> + super::shared_memory_file::Backing<H>,
    {
        let opened = self.open_shared_memory(peer, name, options, backend)?;
        match descriptions.open_with_metadata(
            opened.backing,
            options.access == Access::ReadWrite,
            opened.metadata,
            backend,
        ) {
            Ok(id) => Ok(id),
            Err(error) => {
                if opened.created {
                    // Do not discard ownership if closing the original fails.
                    <B as Delegation<H>>::close(backend, opened.backing)?;
                    self.shared_memory.detach(name);
                }
                Err(error)
            }
        }
    }

    pub fn handle_shared_memory<B: Delegation<H>>(
        &mut self,
        peer: PeerIdentity,
        header: mochios_posix_protocol::Header,
        payload: &[u8],
        attachments: &[super::AttachedObject<H>],
        backend: &mut B,
    ) -> super::ObjectResponse<H> {
        use mochios_posix_protocol::{self as protocol, shared_memory as wire};
        let outcome = (|| {
            if header.flags != 0
                || header.status != 0
                || header.payload_len as usize != payload.len()
                || !attachments.is_empty()
            {
                return Err(-22);
            }
            match header.opcode {
                protocol::OP_SHARED_MEMORY_OPEN => {
                    let request = wire::decode_open(payload).map_err(|_| -22)?;
                    let opened = self.open_shared_memory(
                        peer,
                        request.name,
                        Open {
                            access: if request.options & wire::READ_WRITE != 0 {
                                Access::ReadWrite
                            } else {
                                Access::ReadOnly
                            },
                            create: request.options & wire::CREATE != 0,
                            exclusive: request.options & wire::EXCLUSIVE != 0,
                            truncate: request.options & wire::TRUNCATE != 0,
                            mode: request.mode,
                        },
                        backend,
                    )?;
                    let handle = match backend.open_description(
                        opened.backing,
                        opened.rights,
                        opened.metadata,
                    ) {
                        Ok(handle) => handle,
                        Err(error) => {
                            if opened.created {
                                // If release fails, keep the owning namespace
                                // reference rather than losing a live resource.
                                backend.close(opened.backing)?;
                                self.shared_memory.detach(request.name);
                            }
                            return Err(error);
                        }
                    };
                    Ok(vec![super::OpenedObject {
                        handle,
                        rights: opened.rights,
                    }])
                }
                protocol::OP_SHARED_MEMORY_UNLINK => {
                    let name = wire::decode_name(payload).map_err(|_| -22)?;
                    // Check permission before releasing the owning reference.
                    // Serialize through the same service lock as open/truncate.
                    let backing = self.shared_memory_unlink_target(peer, name)?;
                    backend.close(backing)?;
                    self.shared_memory.detach(name);
                    Ok(Vec::new())
                }
                _ => Err(protocol::STATUS_ENOSYS),
            }
        })();
        match outcome {
            Ok(handles) => super::ObjectResponse {
                response: super::status_response(header.request_id, 0),
                handles,
            },
            Err(error) => super::ObjectResponse {
                response: super::status_response(header.request_id, error),
                handles: Vec::new(),
            },
        }
    }

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
            let attributes = *entry.metadata.attributes.lock().map_err(|_| -5)?;
            let shift = if session.effective_uid == attributes.owner {
                6
            } else if session.effective_gid == attributes.group
                || groups.contains(&attributes.group)
            {
                3
            } else {
                0
            };
            let required = if options.access == Access::ReadWrite {
                6
            } else {
                4
            };
            if session.effective_uid != 0 && (attributes.mode >> shift) & required != required {
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
                metadata: Arc::clone(&entry.metadata),
            });
        }
        if !options.create {
            return Err(-2);
        }
        if self.shared_memory.names.len() >= MAX_NAMES {
            return Err(-28);
        }
        let next_inode = self.shared_memory.next_inode.checked_add(1).ok_or(-28)?;
        let backing = backend.create_zero_length()?;
        let metadata = Arc::new(Metadata {
            inode: self.shared_memory.next_inode,
            attributes: Mutex::new(Attributes {
                owner: session.effective_uid,
                group: session.effective_gid,
                mode: (options.mode & 0o777) & !(session.umask & 0o777),
            }),
            links: AtomicU32::new(1),
        });
        // POSIX-created shm starts at length zero, even for read-only opens.
        // Publish only after successful allocation; no stat/create TOCTOU.
        self.shared_memory.names.insert(
            name.to_vec(),
            Entry {
                backing,
                metadata: Arc::clone(&metadata),
            },
        );
        self.shared_memory.next_inode = next_inode;
        Ok(Opened {
            backing,
            rights: rights(options.access),
            created: true,
            metadata,
        })
    }

    pub fn unlink_shared_memory(&mut self, peer: PeerIdentity, name: &[u8]) -> Result<H, i32> {
        self.shared_memory_unlink_target(peer, name)?;
        // Caller closes only this namespace reference. Previously delegated
        // references and mappings keep the old object alive independently.
        Ok(self.shared_memory.detach(name).unwrap().backing)
    }

    fn shared_memory_unlink_target(&self, peer: PeerIdentity, name: &[u8]) -> Result<H, i32> {
        let session = self.shared_memory_session(peer)?;
        validate_name(name)?;
        let entry = self.shared_memory.names.get(name).ok_or(-2)?;
        // Sticky shared-namespace policy. Mode bits never authorize deleting
        // somebody else's name. UID/GID here are registered service state.
        let attributes = *entry.metadata.attributes.lock().map_err(|_| -5)?;
        if session.effective_uid != 0 && session.effective_uid != attributes.owner {
            return Err(-13);
        }
        Ok(entry.backing)
    }

    fn shared_memory_session(&self, peer: PeerIdentity) -> Result<Session, i32> {
        if !self.processes.contains_key(&peer.process_id) {
            return Err(-3);
        }
        self.sessions.get(&peer.process_id).copied().ok_or(-3)
    }
}
