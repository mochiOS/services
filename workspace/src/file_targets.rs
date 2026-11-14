//! Exact destination authority. Only native Handle attachments select a target;
//! the retained directory and one basename never come from a later request.
use super::{OwnedObjectHandle, PosixClient, SyscallEndpointTransport, error, platform, protocol};
use mochios_posix_client::{ObjectHandleAttachment, OpenAtBase, StatAtBase};
use mochios_posix_protocol as p;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};
use workspace_service::save_transaction::{Backend, Transaction};

type Client = PosixClient<SyscallEndpointTransport>;
const TAG: u64 = 9 << 60;
const LIMIT: usize = 256;
pub const RIGHTS: u64 = mnu_abi::HANDLE_RIGHT_CONTROL
    | mnu_abi::HANDLE_RIGHT_DUPLICATE
    | mnu_abi::HANDLE_RIGHT_TRANSFER;
pub const FILE_RIGHTS: u64 = mnu_abi::HANDLE_RIGHT_READ
    | mnu_abi::HANDLE_RIGHT_WRITE
    | mnu_abi::HANDLE_RIGHT_SEEK
    | mnu_abi::HANDLE_RIGHT_DUPLICATE
    | mnu_abi::HANDLE_RIGHT_TRANSFER;

struct Stage {
    file: ObjectHandleAttachment<u32>,
    _owned: OwnedObjectHandle,
}
struct Target {
    parent: ObjectHandleAttachment<u32>,
    _owned: OwnedObjectHandle,
    save: Transaction<Stage>,
}

struct DirectoryBackend<'a> {
    client: &'a Client,
    parent: ObjectHandleAttachment<u32>,
}
impl Backend for DirectoryBackend<'_> {
    type File = Stage;
    type Error = u64;
    fn create(&mut self, name: &str, mode: u32) -> Result<Stage, u64> {
        let file = self
            .client
            .open_at(
                OpenAtBase::Directory(self.parent),
                p::OPEN_READ
                    | p::OPEN_WRITE
                    | p::OPEN_CREATE
                    | p::OPEN_EXCLUSIVE
                    | p::OPEN_NOFOLLOW
                    | p::OPEN_BENEATH,
                mode,
                name,
            )
            .map_err(error::posix_errno)?;
        Ok(Stage {
            file,
            _owned: OwnedObjectHandle(file.handle),
        })
    }
    fn sync_file(&mut self, file: &Stage) -> Result<(), u64> {
        self.client.fsync(file.file).map_err(error::posix_errno)
    }
    fn rename(&mut self, from: &str, to: &str) -> Result<(), u64> {
        self.client
            .rename_at(
                StatAtBase::Directory(self.parent),
                from,
                StatAtBase::Directory(self.parent),
                to,
            )
            .map_err(error::posix_errno)
    }
    fn remove(&mut self, name: &str) -> Result<(), u64> {
        match self
            .client
            .unlink_at(StatAtBase::Directory(self.parent), 0, name)
        {
            Ok(()) | Err(mochios_posix_client::ClientError::Remote(-2)) => Ok(()),
            Err(error) => Err(error::posix_errno(error)),
        }
    }
    fn sync_directory(&mut self) -> Result<(), u64> {
        self.client.fsync(self.parent).map_err(error::posix_errno)
    }
}

pub struct Targets {
    endpoint: Option<u32>,
    next: u64,
    targets: BTreeMap<u64, Target>,
}

impl Targets {
    pub fn new() -> Self {
        Self {
            endpoint: platform::ipc::create_handle().ok(),
            next: 1,
            targets: BTreeMap::new(),
        }
    }

    fn begin(target: &mut Target, client: &Client) -> Result<ObjectHandleAttachment<u32>, u64> {
        let mut random = [0; 16];
        platform::random::fill(&mut random).map_err(error::native_errno)?;
        let name = format!(".mochios-save-{}", super::hex_encode(&random));
        let mut backend = DirectoryBackend {
            client,
            parent: target.parent,
        };
        let file = target.save.begin(&mut backend, name)?.file;
        let handle = match platform::handle::duplicate(file.handle, file.rights & FILE_RIGHTS) {
            Ok(handle) => handle,
            Err(error) => {
                let _ = target.save.abort(&mut backend);
                return Err(error::native_errno(error));
            }
        };
        let delivered = ObjectHandleAttachment {
            handle,
            rights: file.rights & FILE_RIGHTS,
        };
        Ok(delivered)
    }

    fn abort(target: &mut Target, client: &Client) -> Result<(), u64> {
        target.save.abort(&mut DirectoryBackend {
            client,
            parent: target.parent,
        })
    }

    fn commit(target: &mut Target, client: &Client) -> Result<(), u64> {
        if target.save.commit(&mut DirectoryBackend {
            client,
            parent: target.parent,
        })? {
            Ok(())
        } else {
            Err(22)
        }
    }

    /// Opens the selection under a retained home root, then pins its parent.
    /// A writable destination is a separate native object, never a directory
    /// Handle or a process-wide capability lent to the application.
    pub fn select(
        &mut self,
        client: &Client,
        path: &str,
        mode: u16,
    ) -> Result<
        (
            ObjectHandleAttachment<u32>,
            Option<ObjectHandleAttachment<u32>>,
        ),
        u64,
    > {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .and_then(|p| fs::canonicalize(p).ok())
            .ok_or(13u64)?;
        let relative = Path::new(path).strip_prefix(&home).map_err(|_| 13u64)?;
        let name = relative
            .file_name()
            .and_then(|s| s.to_str())
            .filter(|s| !s.is_empty() && !matches!(*s, "." | ".."))
            .ok_or(22u64)?
            .to_owned();
        let root = client
            .open_at(
                OpenAtBase::ProcessRoot,
                p::OPEN_READ | p::OPEN_DIRECTORY | p::OPEN_NOFOLLOW,
                0,
                home.as_os_str().as_encoded_bytes(),
            )
            .map_err(error::posix_errno)?;
        let _root = OwnedObjectHandle(root.handle);
        let parent_path = relative
            .parent()
            .filter(|s| !s.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let parent = client
            .open_at(
                OpenAtBase::Directory(root),
                p::OPEN_READ | p::OPEN_DIRECTORY | p::OPEN_BENEATH,
                0,
                parent_path.as_os_str().as_encoded_bytes(),
            )
            .map_err(error::posix_errno)?;
        let owned = OwnedObjectHandle(parent.handle);
        let flags = p::OPEN_READ | p::OPEN_NOFOLLOW | p::OPEN_NONBLOCK | p::OPEN_BENEATH;
        let opened = if mode == protocol::FILE_PANEL_MODE_SAVE {
            None
        } else {
            let file = if mode == protocol::FILE_PANEL_MODE_EDIT {
                match client.open_at(
                    OpenAtBase::Directory(parent),
                    flags | p::OPEN_WRITE,
                    0,
                    &name,
                ) {
                    Err(mochios_posix_client::ClientError::Remote(-13 | -30)) => {
                        client.open_at(OpenAtBase::Directory(parent), flags, 0, &name)
                    }
                    result => result,
                }
            } else {
                client.open_at(OpenAtBase::Directory(parent), flags, 0, &name)
            }
            .map_err(error::posix_errno)?;
            let owner = OwnedObjectHandle(file.handle);
            let metadata = client.fstat(file).map_err(error::posix_errno)?;
            if metadata.mode & 0o170000 != 0o100000 {
                return Err(13);
            }
            Some((file, owner))
        };
        let writable = mode == protocol::FILE_PANEL_MODE_SAVE
            || opened
                .as_ref()
                .is_some_and(|(file, _)| file.rights & mnu_abi::HANDLE_RIGHT_WRITE != 0);
        if !writable {
            let (file, owner) = opened.ok_or(22u64)?;
            std::mem::forget(owner);
            return Ok((
                ObjectHandleAttachment {
                    handle: file.handle,
                    rights: file.rights & (FILE_RIGHTS & !mnu_abi::HANDLE_RIGHT_WRITE),
                },
                None,
            ));
        }
        if self.targets.len() >= LIMIT || self.next >= 1 << 60 {
            return Err(28);
        }
        let id = TAG | self.next;
        self.next += 1;
        let native =
            platform::handle::create_provider_object(self.endpoint.ok_or(11u64)?, id, RIGHTS)
                .map_err(error::native_errno)?;
        let native_owner = OwnedObjectHandle(native);
        let mode = if let Some((file, _)) = opened.as_ref() {
            client.fstat(*file).map_err(error::posix_errno)?.mode & 0o777
        } else {
            match client.stat_at(StatAtBase::Directory(parent), p::STAT_NOFOLLOW, &name) {
                Ok(status) if status.mode & 0o170000 == 0o100000 => status.mode & 0o777,
                Err(mochios_posix_client::ClientError::Remote(-2)) => 0o600,
                Ok(_) => return Err(13),
                Err(error) => return Err(error::posix_errno(error)),
            }
        };
        let mut target = Target {
            parent,
            _owned: owned,
            save: Transaction::new(name, mode),
        };
        let file = match opened {
            Some((file, owner)) => {
                std::mem::forget(owner);
                Ok(ObjectHandleAttachment {
                    handle: file.handle,
                    rights: file.rights & (FILE_RIGHTS & !mnu_abi::HANDLE_RIGHT_WRITE),
                })
            }
            None => Self::begin(&mut target, client),
        };
        let file = match file {
            Ok(file) => file,
            Err(error) => return Err(error),
        };
        self.targets.insert(id, target);
        std::mem::forget(native_owner);
        Ok((
            file,
            Some(ObjectHandleAttachment {
                handle: native,
                rights: RIGHTS,
            }),
        ))
    }

    pub fn release(
        &mut self,
        bytes: &[u8],
        objects: &platform::ipc::IpcObjectHandles,
        client: &Client,
    ) -> bool {
        if objects.delivery_flags != mnu_abi::IPC_DELIVERY_NATIVE_OBJECT || objects.count != 0 {
            return false;
        }
        let Ok((header, payload)) = mnu_abi::provider::RequestHeader::decode(bytes) else {
            return false;
        };
        if header.object_id & (15 << 60) != TAG {
            return false;
        }
        if header.opcode == mnu_abi::provider::OP_RELEASE && payload.is_empty() {
            if let Some(mut target) = self.targets.remove(&header.object_id) {
                let _ = Self::abort(&mut target, client);
            }
        }
        true
    }

    pub fn execute(
        &mut self,
        opcode: u16,
        payload: &[u8],
        objects: &platform::ipc::IpcObjectHandles,
        client: &Client,
    ) -> Result<Option<ObjectHandleAttachment<u32>>, u64> {
        if !payload.is_empty() || !objects.is_user_delivery() || objects.count != 1 {
            return Err(22);
        }
        let object = objects.handles[0];
        if object.handle == 0
            || object.reserved != 0
            || object.rights != mnu_abi::HANDLE_RIGHT_CONTROL
        {
            return Err(13);
        }
        let id = platform::handle::identify_provider_object(object.handle)
            .map_err(error::native_errno)?;
        let target = self.targets.get_mut(&id).ok_or(13u64)?;
        match opcode {
            protocol::OP_FILE_TARGET_BEGIN => Self::begin(target, client).map(Some),
            protocol::OP_FILE_TARGET_COMMIT => Self::commit(target, client).map(|_| None),
            protocol::OP_FILE_TARGET_ABORT => Self::abort(target, client).map(|_| None),
            _ => Err(22),
        }
    }
}
