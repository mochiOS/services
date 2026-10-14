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

/// One authorized lookup retained across backlog waits. Not cloneable: the
/// owner must release its inode reference once on completion or cancellation.
#[must_use = "release the retained target after connecting or cancelling"]
pub struct ConnectTarget<H> {
    file: H,
    identity: (u64, u64),
    client: u64,
    listener: u64,
    client_name: Option<SavedName>,
    listener_name: SavedName,
}

/// One sendto destination, resolved once under authenticated FS authority.
/// The retained inode prevents namespace reuse; the socket identity prevents
/// redirection to a new endpoint after final close. Neither ID is wire authority.
#[must_use = "release the retained destination inode exactly once"]
pub struct DatagramTarget<H> {
    file: H,
    client: u64,
    socket: u64,
    source: crate::socket_record::SourceAddress,
}
impl<H> DatagramTarget<H> {
    pub fn client(&self) -> u64 {
        self.client
    }
    pub fn socket(&self) -> u64 {
        self.socket
    }
    pub fn source(&self) -> crate::socket_record::SourceAddress {
        self.source
    }
    pub fn release_with(self, close: impl FnOnce(H)) {
        close(self.file);
    }
}

struct SavedName {
    bytes: [u8; MAX_UNIX_NAME_BYTES],
    length: usize,
}

impl SavedName {
    fn new(name: &[u8]) -> Self {
        let mut bytes = [0; MAX_UNIX_NAME_BYTES];
        bytes[..name.len()].copy_from_slice(name);
        Self {
            bytes,
            length: name.len(),
        }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
}

impl<H> ConnectTarget<H> {
    pub fn client(&self) -> u64 {
        self.client
    }

    pub fn listener(&self) -> u64 {
        self.listener
    }

    /// Consume the sole owned lookup reference, including on cancellation.
    pub fn release_with(self, close: impl FnOnce(H)) {
        close(self.file);
    }
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

    /// Immediate attempt; blocking adapters use prepare_connect/try_connect
    /// instead so a backlog retry never reopens a mutable pathname.
    pub fn connect_path<B: Filesystem<H>>(
        &self,
        streams: &mut Streams,
        client: u64,
        path: &[u8],
        backend: &mut B,
    ) -> Result<(u64, u64), i32> {
        let target = self.prepare_connect(streams, client, path, backend)?;
        let result = self.try_connect(streams, &target);
        target.release_with(|handle| backend.close(handle));
        result
    }

    /// Datagram connect is an immediate one-way selection, not a listener or
    /// accept transaction. Authorize through one atomic inode lookup, retain
    /// that reference through publication, and close it on every result.
    pub fn connect_datagram_path<B: Filesystem<H>>(
        &self,
        streams: &mut Streams,
        client: u64,
        path: &[u8],
        backend: &mut B,
    ) -> Result<u64, i32> {
        if streams.kind(client)? != mochios_posix_protocol::socket::Kind::Datagram {
            return Err(-91);
        }
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
            let target = self
                .records
                .iter()
                .find(|record| record.identity == (status.device, status.node_id))
                .ok_or(-111)?;
            streams.connect_datagram_named(
                client,
                target.socket,
                self.address(client),
                &target.name[..target.length],
            )?;
            Ok(target.socket)
        })();
        if file.handle != H::default() {
            backend.close(file.handle);
        }
        result
    }

    pub fn prepare_datagram_target<B: Filesystem<H>>(
        &self,
        streams: &Streams,
        client: u64,
        path: &[u8],
        backend: &mut B,
    ) -> Result<DatagramTarget<H>, i32> {
        use mochios_posix_protocol::socket::{Address, Kind};
        if streams.kind(client)? != Kind::Datagram {
            return Err(-91);
        }
        if path.is_empty() || path.len() > MAX_UNIX_NAME_BYTES || path.contains(&0) {
            return Err(-22);
        }
        let source = crate::socket_record::SourceAddress::new(
            self.address(client)
                .map_or(Address::UnixUnnamed, Address::UnixPath),
        )?;
        let (file, status) =
            backend
                .open_socket(path)
                .map_err(|error| if error == -88 { -111 } else { error })?;
        let result = (|| {
            if file.handle == H::default() || file.rights != NODE_RIGHTS || status.node_id == 0 {
                return Err(-5);
            }
            if status.kind != filesystem::NODE_TYPE_SOCKET {
                return Err(-111);
            }
            let target = self
                .records
                .iter()
                .find(|record| record.identity == (status.device, status.node_id))
                .ok_or(-111)?;
            if streams.kind(target.socket).map_err(|_| -111)? != Kind::Datagram {
                return Err(-91);
            }
            Ok(DatagramTarget {
                file: file.handle,
                client,
                socket: target.socket,
                source,
            })
        })();
        if result.is_err() && file.handle != H::default() {
            backend.close(file.handle);
        }
        result
    }

    /// Authorize exactly once and retain the resolved inode while waiting.
    /// Both socket IDs are service-private, monotonic description identities.
    pub fn prepare_connect<B: Filesystem<H>>(
        &self,
        streams: &Streams,
        client: u64,
        path: &[u8],
        backend: &mut B,
    ) -> Result<ConnectTarget<H>, i32> {
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
            if streams
                .listening_backlog(listener.socket)
                .ok()
                .flatten()
                .is_none()
            {
                return Err(-111);
            }
            Ok(ConnectTarget {
                file: file.handle,
                identity,
                client,
                listener: listener.socket,
                client_name: self.address(client).map(SavedName::new),
                listener_name: SavedName::new(&listener.name[..listener.length]),
            })
        })();
        if result.is_err() && file.handle != H::default() {
            backend.close(file.handle);
        }
        result
    }

    /// Retry only the retained target. EAGAIN preserves ownership and leaves
    /// both endpoints unchanged; listener retirement is connection refusal,
    /// even if a new listener now occupies the old pathname/inode number.
    pub fn try_connect(
        &self,
        streams: &mut Streams,
        target: &ConnectTarget<H>,
    ) -> Result<(u64, u64), i32> {
        streams.check_connect(target.client)?;
        if !self
            .records
            .iter()
            .any(|record| record.socket == target.listener && record.identity == target.identity)
            || streams
                .listening_backlog(target.listener)
                .ok()
                .flatten()
                .is_none()
        {
            return Err(-111);
        }
        let accepted = streams.connect_named(
            target.client,
            target.listener,
            target.client_name.as_ref().map(SavedName::as_bytes),
            target.listener_name.as_bytes(),
        )?;
        Ok((target.listener, accepted))
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
