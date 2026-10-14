//! Pathname binding records for one explicitly delegated filesystem authority.
//! A record owns a retained inode Handle, never a client FD or pathname lookup
//! capability. The native adapter must authenticate the socket description ID.

use crate::{OpenedObject, socket::Streams};
use mochios_filesystem_protocol as filesystem;
use mochios_posix_protocol::socket::MAX_UNIX_NAME_BYTES;

pub const NODE_RIGHTS: u64 = mnu_abi::HANDLE_RIGHT_DUPLICATE | mnu_abi::HANDLE_RIGHT_TRANSFER;

/// Implementations resolve/create through the delegated filesystem controller,
/// with authenticated credentials and retained process root/cwd anchors.
/// Creation is one atomic filesystem request, not a stat-then-create sequence.
pub trait Filesystem<H> {
    fn create_socket(
        &mut self,
        path: &[u8],
    ) -> Result<(OpenedObject<H>, filesystem::NodeStatus), i32>;
    fn open_socket(
        &mut self,
        path: &[u8],
    ) -> Result<(OpenedObject<H>, filesystem::NodeStatus), i32>;
    /// Consumes one owned local reference, like FilesystemBackend::release_object.
    fn close(&mut self, handle: H);
}

struct Record<H> {
    socket: u64,
    file: H,
    identity: (u64, u64),
    name: [u8; MAX_UNIX_NAME_BYTES],
    length: usize,
}

/// Serialize with socket operations in the Provider worker. Dup/fork retain
/// that same socket object and do not add binding records. Release a record
/// only on final native Provider release, not on individual descriptor closes.
pub struct Bindings<H> {
    records: Vec<Record<H>>,
}

impl<H: Copy + Default + Eq> Default for Bindings<H> {
    fn default() -> Self {
        Self::new()
    }
}

impl<H: Copy + Default + Eq> Bindings<H> {
    pub const fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    /// The backend returns an owned Handle. Publish only after validating that
    /// it identifies the newly-created socket inode with no excess authority.
    pub fn bind_path<B: Filesystem<H>>(
        &mut self,
        streams: &Streams,
        socket: u64,
        path: &[u8],
        backend: &mut B,
    ) -> Result<(), i32> {
        streams.options(socket)?;
        if self.records.iter().any(|record| record.socket == socket) {
            return Err(-22);
        }
        if path.is_empty() || path.len() > MAX_UNIX_NAME_BYTES || path.contains(&0) {
            return Err(-22);
        }
        // No allocation failure after the filesystem publishes the new name.
        self.records.try_reserve(1).map_err(|_| -12)?;
        let (file, status) = backend
            .create_socket(path)
            .map_err(|error| if error == -17 { -98 } else { error })?;
        let valid = file.handle != H::default()
            && file.rights == NODE_RIGHTS
            && status.kind == filesystem::NODE_TYPE_SOCKET
            && status.node_id != 0
            && status.link_count == 1;
        if !valid {
            if file.handle != H::default() {
                backend.close(file.handle);
            }
            return Err(-5);
        }
        let identity = (status.device, status.node_id);
        if self
            .records
            .iter()
            .any(|record| record.identity == identity)
        {
            backend.close(file.handle);
            return Err(-5);
        }
        let mut name = [0; MAX_UNIX_NAME_BYTES];
        name[..path.len()].copy_from_slice(path);
        self.records.push(Record {
            socket,
            file: file.handle,
            identity,
            name,
            length: path.len(),
        });
        Ok(())
    }

    /// Authorize and retain the lookup result before matching an identity. The
    /// temporary Handle is closed on every outcome, while the registered inode
    /// stays pinned by its independent binding reference.
    pub fn connect_path<B: Filesystem<H>>(
        &self,
        streams: &mut Streams,
        client: u64,
        path: &[u8],
        backend: &mut B,
    ) -> Result<(u64, u64), i32> {
        streams.check_connect(client)?;
        if path.is_empty() || path.len() > MAX_UNIX_NAME_BYTES || path.contains(&0) {
            return Err(-22);
        }
        let (file, status) = backend
            .open_socket(path)
            .map_err(|error| if error == -88 { -111 } else { error })?;
        let result = (|| {
            if file.handle == H::default() || file.rights != NODE_RIGHTS || status.node_id == 0 {
                return Err(-5);
            }
            if status.kind != filesystem::NODE_TYPE_SOCKET {
                return Err(-111);
            }
            let identity = (status.device, status.node_id);
            let listener = self
                .records
                .iter()
                .find(|record| record.identity == identity)
                .ok_or(-111)?;
            let listener_path = &listener.name[..listener.length];
            let accepted = streams.connect_named(
                client,
                listener.socket,
                self.address(client),
                listener_path,
            )?;
            Ok((listener.socket, accepted))
        })();
        if file.handle != H::default() {
            backend.close(file.handle);
        }
        result
    }

    /// The original spelling is reported by getsockname, even after unlink or
    /// rename. It is not used to resolve another socket's identity.
    pub fn address(&self, socket: u64) -> Option<&[u8]> {
        self.records
            .iter()
            .find(|record| record.socket == socket)
            .map(|record| &record.name[..record.length])
    }

    /// Borrowed service-owned reference for future metadata/identity queries.
    /// The adapter must not close it or transfer it as a temporary owned reply.
    pub fn retained_file(&self, socket: u64) -> Option<H> {
        self.records
            .iter()
            .find(|record| record.socket == socket)
            .map(|record| record.file)
    }

    pub fn release<B: Filesystem<H>>(&mut self, socket: u64, backend: &mut B) {
        self.release_with(socket, |handle| backend.close(handle));
    }

    pub fn release_with(&mut self, socket: u64, mut close: impl FnMut(H)) {
        let Some(index) = self
            .records
            .iter()
            .position(|record| record.socket == socket)
        else {
            return;
        };
        close(self.records[index].file);
        self.records.swap_remove(index);
    }
}
