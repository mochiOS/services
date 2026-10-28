//! Self-captured read-only authority, carried by explicit native objects.
use super::*;
use protocol::read_scope as wire;
use std::sync::Mutex;

const MAX_SCOPES: usize = 256;
const MAX_PER_SOURCE: usize = 16;

#[derive(PartialEq, Eq)]
struct Credentials {
    session: Session,
    groups: Vec<u32>,
}

pub struct Scope<H> {
    credentials: Credentials,
    directories: SessionDirectories<H>,
}

impl<H: Copy> Scope<H> {
    fn release(self, filesystem: &mut impl FilesystemBackend<H>) {
        filesystem.release_object(self.directories.root);
        filesystem.release_object(self.directories.cwd);
    }

    fn info(&self) -> protocol::SessionInfo {
        let session = self.credentials.session;
        protocol::SessionInfo {
            real_uid: session.real_uid,
            effective_uid: session.effective_uid,
            real_gid: session.real_gid,
            effective_gid: session.effective_gid,
            umask: session.umask,
        }
    }

    fn open(
        &self,
        payload: &[u8],
        filesystem: &mut impl FilesystemBackend<H>,
    ) -> Result<OpenedObject<H>, i32> {
        let request = wire::decode_open(payload).map_err(|_| STATUS_EINVAL)?;
        let prepared = PreparedOpen {
            base: request.base,
            options: request.options,
            mode: 0,
            path: request.path.to_owned(),
            effective_uid: self.credentials.session.effective_uid,
            effective_gid: self.credentials.session.effective_gid,
            supplementary_groups: self.credentials.groups.clone(),
        };
        let opened = filesystem.open_at(
            &prepared,
            PathObjects {
                root: self.directories.root,
                base: (request.base == protocol::OpenBase::ProcessCwd)
                    .then_some(self.directories.cwd),
            },
        )?;
        let source = AttachedObject {
            handle: opened.handle,
            rights: opened.rights,
        };
        let result = if opened.rights & wire::FILE_RIGHTS == wire::FILE_RIGHTS {
            filesystem.retain_object(AttachedObject {
                rights: wire::FILE_RIGHTS,
                ..source
            })
        } else {
            Err(protocol::STATUS_EIO)
        };
        filesystem.release_object(source);
        let retained = result?;
        if retained.rights != wire::FILE_RIGHTS {
            filesystem.release_object(retained);
            return Err(protocol::STATUS_EIO);
        }
        Ok(OpenedObject {
            handle: retained.handle,
            rights: retained.rights,
        })
    }
}

fn capture<H: Copy>(
    state: &Mutex<PosixService<H>>,
    peer: PeerIdentity,
    filesystem: &mut impl FilesystemBackend<H>,
) -> Result<Scope<H>, i32> {
    path_request::with_paths(
        state,
        peer,
        &[],
        filesystem,
        |service| {
            let session = *service
                .session(peer.process_id)
                .ok_or(protocol::STATUS_ESRCH)?;
            let groups = service
                .supplementary_groups
                .get(&peer.process_id)
                .cloned()
                .unwrap_or_default();
            Ok((
                Credentials { session, groups },
                protocol::OpenBase::ProcessCwd,
            ))
        },
        |credentials, paths, filesystem| {
            // The path helper owns temporary references. Acquire independent scope
            // references, rolling back either duplication failure before returning.
            let base = paths.base.ok_or(protocol::STATUS_EIO)?;
            let root = filesystem.retain_object(paths.root)?;
            if root.rights != paths.root.rights {
                filesystem.release_object(root);
                return Err(protocol::STATUS_EIO);
            }
            let cwd = match filesystem.retain_object(base) {
                Ok(cwd) => cwd,
                Err(error) => {
                    filesystem.release_object(root);
                    return Err(error);
                }
            };
            if cwd.rights != base.rights {
                filesystem.release_object(cwd);
                filesystem.release_object(root);
                return Err(protocol::STATUS_EIO);
            }
            Ok(Scope {
                credentials: Credentials {
                    session: credentials.session,
                    groups: credentials.groups.clone(),
                },
                directories: SessionDirectories { root, cwd },
            })
        },
    )?
}

/// Owned only by the control endpoint's serving thread. Native provider identity
/// and final-release delivery authenticate lookup and removal; wire integers
/// never select entries. IDs are never reused, including failed publications.
pub struct Registry<H> {
    next_id: u64,
    entries: Vec<(u64, Scope<H>)>,
}

impl<H> Default for Registry<H> {
    fn default() -> Self {
        Self {
            next_id: 1,
            entries: Vec::new(),
        }
    }
}

pub fn supports(opcode: u16) -> bool {
    matches!(opcode, wire::OP_CREATE | wire::OP_INFO | wire::OP_OPEN)
}

impl<H: Copy> Registry<H> {
    pub fn release_native(
        &mut self,
        bytes: &[u8],
        delivery_flags: u32,
        attachments: usize,
        filesystem: &mut impl FilesystemBackend<H>,
    ) -> Result<(), i32> {
        let (header, _) =
            mnu_abi::provider::RequestHeader::decode(bytes).map_err(|_| STATUS_EINVAL)?;
        if delivery_flags != mnu_abi::IPC_DELIVERY_NATIVE_OBJECT
            || attachments != 0
            || header.opcode != mnu_abi::provider::OP_RELEASE
        {
            return Err(protocol::STATUS_EPERM);
        }
        if let Some(index) = self
            .entries
            .iter()
            .position(|(id, _)| *id == header.object_id)
        {
            self.entries.swap_remove(index).1.release(filesystem);
        }
        Ok(())
    }

    /// `create` and `identify` are the existing native Provider APIs. The latter
    /// accepts only objects owned by this exact endpoint thread.
    pub fn execute(
        &mut self,
        state: &Mutex<PosixService<H>>,
        peer: PeerIdentity,
        header: protocol::Header,
        payload: &[u8],
        handles: &[AttachedObject<H>],
        filesystem: &mut impl FilesystemBackend<H>,
        create: impl FnOnce(u64) -> Result<H, i32>,
        identify: impl FnOnce(H) -> Result<u64, i32>,
    ) -> ObjectResponse<H> {
        let result = (|| {
            if header.flags != 0
                || header.status != 0
                || header.payload_len as usize != payload.len()
            {
                return Err(STATUS_EINVAL);
            }
            if header.opcode == wire::OP_CREATE {
                if !payload.is_empty() || !handles.is_empty() {
                    return Err(STATUS_EINVAL);
                }
                if self.entries.len() >= MAX_SCOPES
                    || self
                        .entries
                        .iter()
                        .filter(|(_, scope)| {
                            scope.credentials.session.process_id == peer.process_id
                        })
                        .count()
                        >= MAX_PER_SOURCE
                {
                    return Err(protocol::STATUS_EAGAIN);
                }
                if self.next_id > i64::MAX as u64 {
                    return Err(STATUS_EOVERFLOW);
                }
                self.entries.try_reserve(1).map_err(|_| -12)?;
                let scope = capture(state, peer, filesystem)?;
                let id = self.next_id;
                self.next_id += 1;
                let handle = match create(id) {
                    Ok(handle) => handle,
                    Err(error) => {
                        scope.release(filesystem);
                        return Err(error);
                    }
                };
                self.entries.push((id, scope));
                return Ok(ObjectResponse {
                    response: status_response(header.request_id, 0),
                    handles: vec![OpenedObject {
                        handle,
                        rights: wire::TOKEN_RIGHTS,
                    }],
                });
            }
            if !matches!(header.opcode, wire::OP_INFO | wire::OP_OPEN)
                || handles.len() != 1
                || handles[0].rights != wire::ATTACH_RIGHTS
            {
                return Err(STATUS_EINVAL);
            }
            let id = identify(handles[0].handle)?;
            let scope = &self
                .entries
                .iter()
                .find(|(key, _)| *key == id)
                .ok_or(-9)?
                .1;
            let mut response = status_response(header.request_id, 0);
            let mut opened = Vec::new();
            if header.opcode == wire::OP_INFO {
                if !payload.is_empty() {
                    return Err(STATUS_EINVAL);
                }
                response.payload.resize(protocol::SESSION_INFO_LEN, 0);
                protocol::encode_session_info(scope.info(), &mut response.payload)
                    .map_err(|_| STATUS_EINVAL)?;
                response.header.payload_len = response.payload.len() as u32;
            } else {
                opened.push(scope.open(payload, filesystem)?);
            }
            Ok(ObjectResponse {
                response,
                handles: opened,
            })
        })();
        result.unwrap_or_else(|error| object_error(header.request_id, error))
    }
}
