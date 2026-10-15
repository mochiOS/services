//! Service-owned open descriptions for RAM backing. Provider object IDs select
//! these descriptions only after native transport authentication; they are not
//! client FD numbers. Dup/fork aliases retain one description and cursor.

use std::collections::BTreeMap;
use std::sync::Arc;

pub trait Backing<H> {
    fn retain(&mut self, backing: H) -> Result<H, i32>;
    fn close(&mut self, backing: H) -> Result<(), i32>;
    fn length(&mut self, backing: H) -> Result<u64, i32>;
    fn resize(&mut self, backing: H, length: u64) -> Result<(), i32>;
    fn read_at(&mut self, backing: H, offset: u64, output: &mut [u8]) -> Result<usize, i32>;
    fn write_at(&mut self, backing: H, offset: u64, input: &[u8]) -> Result<usize, i32>;
}

struct Description<H> {
    backing: H,
    writable: bool,
    cursor: u64,
    status_flags: u32,
    metadata: Option<Arc<super::shared_memory::Metadata>>,
}

/// Serialize this manager externally through operation completion. Separate
/// opens get separate IDs; only last native Provider release closes an ID.
pub struct Descriptions<H> {
    next: u64,
    entries: BTreeMap<u64, Description<H>>,
}

impl<H: Copy> Descriptions<H> {
    pub const fn new() -> Self {
        Self {
            next: 1,
            entries: BTreeMap::new(),
        }
    }

    pub fn open<B: Backing<H>>(
        &mut self,
        backing: H,
        writable: bool,
        backend: &mut B,
    ) -> Result<u64, i32> {
        self.open_internal(backing, writable, None, backend)
    }

    pub fn open_with_metadata<B: Backing<H>>(
        &mut self,
        backing: H,
        writable: bool,
        metadata: Arc<super::shared_memory::Metadata>,
        backend: &mut B,
    ) -> Result<u64, i32> {
        self.open_internal(backing, writable, Some(metadata), backend)
    }

    fn open_internal<B: Backing<H>>(
        &mut self,
        backing: H,
        writable: bool,
        metadata: Option<Arc<super::shared_memory::Metadata>>,
        backend: &mut B,
    ) -> Result<u64, i32> {
        let next = self.next.checked_add(1).ok_or(-23)?;
        let retained = backend.retain(backing)?;
        let id = self.next;
        self.entries.insert(
            id,
            Description {
                backing: retained,
                writable,
                cursor: 0,
                status_flags: 0,
                metadata,
            },
        );
        self.next = next;
        Ok(id)
    }

    pub fn metadata(&self, id: u64) -> Result<Arc<super::shared_memory::Metadata>, i32> {
        self.entries
            .get(&id)
            .ok_or(-9)?
            .metadata
            .as_ref()
            .map(Arc::clone)
            .ok_or(-9)
    }

    pub fn status<B: Backing<H>>(
        &self,
        id: u64,
        backend: &mut B,
    ) -> Result<mochios_posix_protocol::FileStatus, i32> {
        let metadata = self.metadata(id)?;
        let attributes = *metadata.attributes.lock().map_err(|_| -5)?;
        let size = i64::try_from(self.length(id, backend)?).map_err(|_| -75)?;
        Ok(mochios_posix_protocol::FileStatus {
            // A service-owned virtual namespace, not a kernel device or path.
            device: 0x534d,
            inode: metadata.inode,
            mode: 0o100000 | attributes.mode,
            link_count: metadata.links(),
            uid: attributes.owner,
            gid: attributes.group,
            size,
            block_size: 4096,
            // POSIX shared-memory fstat requires uid/gid/size/permission bits.
            // No resident-page accounting or timestamp tracking is exposed:
            // do not invent allocated blocks from the sparse logical extent.
            ..Default::default()
        })
    }

    pub fn release<B: Backing<H>>(&mut self, id: u64, backend: &mut B) -> Result<(), i32> {
        let entry = self.entries.get(&id).ok_or(-9)?;
        backend.close(entry.backing)?;
        self.entries.remove(&id);
        Ok(())
    }

    pub fn length<B: Backing<H>>(&self, id: u64, backend: &mut B) -> Result<u64, i32> {
        backend.length(self.entries.get(&id).ok_or(-9)?.backing)
    }

    /// Borrow only for an immediately attenuated mapping delegation under the
    /// manager lock. The owning backing reference is never transferred.
    pub fn mapping_backing(&self, id: u64, writable: bool) -> Result<H, i32> {
        let entry = self.entries.get(&id).ok_or(-9)?;
        if writable && !entry.writable {
            return Err(-13);
        }
        Ok(entry.backing)
    }

    pub fn resize<B: Backing<H>>(&self, id: u64, length: u64, backend: &mut B) -> Result<(), i32> {
        self.resize_bounded(id, length, u64::MAX, backend)
    }

    /// All extent changes, including other descriptions and namespace
    /// truncation, hold the same manager lock through native resize. Mapping
    /// delegations never grant CONTROL over the service-owned RAM backing.
    pub fn resize_bounded<B: Backing<H>>(
        &self,
        id: u64,
        length: u64,
        ceiling: u64,
        backend: &mut B,
    ) -> Result<(), i32> {
        let entry = self.entries.get(&id).ok_or(-9)?;
        if !entry.writable {
            return Err(-9);
        }
        if length > i64::MAX as u64 {
            return Err(-22);
        }
        if ceiling != u64::MAX && length > ceiling && length > backend.length(entry.backing)? {
            return Err(mnu_abi::provider::STATUS_BOUND_REACHED as i32);
        }
        // ftruncate does not change an open description's file position.
        backend.resize(entry.backing, length)
    }

    pub fn set_append(&mut self, id: u64, append: bool) -> Result<(), i32> {
        let entry = self.entries.get_mut(&id).ok_or(-9)?;
        if append {
            entry.status_flags |= mochios_posix_protocol::OPEN_APPEND;
        } else {
            entry.status_flags &= !mochios_posix_protocol::OPEN_APPEND;
        }
        Ok(())
    }

    pub fn append(&self, id: u64) -> Result<bool, i32> {
        Ok(self.status_flags(id)? & mochios_posix_protocol::OPEN_APPEND != 0)
    }

    pub fn status_flags(&self, id: u64) -> Result<u32, i32> {
        Ok(self.entries.get(&id).ok_or(-9)?.status_flags)
    }

    pub fn set_status_flags(&mut self, id: u64, flags: u32) -> Result<(), i32> {
        self.update_status_flags(id, mochios_posix_protocol::MUTABLE_STATUS_FLAGS, flags)
    }

    pub fn update_status_flags(&mut self, id: u64, mask: u32, flags: u32) -> Result<(), i32> {
        let entry = self.entries.get_mut(&id).ok_or(-9)?;
        if mask & !mochios_posix_protocol::MUTABLE_STATUS_FLAGS != 0 || flags & !mask != 0 {
            return Err(-22);
        }
        // RAM IO never waits for data, so NONBLOCK requires no alternate IO
        // path. Both flags are shared by all aliases of this description.
        entry.status_flags = (entry.status_flags & !mask) | flags;
        Ok(())
    }

    pub fn read<B: Backing<H>>(
        &mut self,
        id: u64,
        output: &mut [u8],
        backend: &mut B,
    ) -> Result<(u64, usize), i32> {
        let entry = self.entries.get_mut(&id).ok_or(-9)?;
        let position = entry.cursor;
        let maximum = usize::try_from((i64::MAX as u64) - position)
            .unwrap_or(usize::MAX)
            .min(output.len());
        let read = backend.read_at(entry.backing, position, &mut output[..maximum])?;
        if read > maximum {
            return Err(-5);
        }
        entry.cursor = position + read as u64;
        Ok((position, read))
    }

    pub fn read_at<B: Backing<H>>(
        &self,
        id: u64,
        offset: u64,
        output: &mut [u8],
        backend: &mut B,
    ) -> Result<usize, i32> {
        let entry = self.entries.get(&id).ok_or(-9)?;
        if offset > i64::MAX as u64 {
            return Err(-22);
        }
        let read = backend.read_at(entry.backing, offset, output)?;
        if read > output.len() {
            return Err(-5);
        }
        Ok(read)
    }

    pub fn write<B: Backing<H>>(
        &mut self,
        id: u64,
        input: &[u8],
        backend: &mut B,
    ) -> Result<usize, i32> {
        self.write_bounded(id, input, u64::MAX, backend)
            .map(|(_, written)| written)
    }

    /// Select append/current position, permitted prefix and extent mutation
    /// under the manager lock. No client-side cursor/size query may race this.
    pub fn write_bounded<B: Backing<H>>(
        &mut self,
        id: u64,
        input: &[u8],
        byte_end: u64,
        backend: &mut B,
    ) -> Result<(u64, usize), i32> {
        let entry = self.entries.get_mut(&id).ok_or(-9)?;
        if !entry.writable {
            return Err(-9);
        }
        if input.is_empty() {
            return Ok((entry.cursor, 0));
        }
        let position = if entry.status_flags & mochios_posix_protocol::OPEN_APPEND != 0 {
            backend.length(entry.backing)?
        } else {
            entry.cursor
        };
        let available = byte_end
            .checked_sub(position)
            .filter(|&bytes| bytes != 0)
            .ok_or(mnu_abi::provider::STATUS_BOUND_REACHED as i32)?;
        let permitted = usize::try_from(available)
            .unwrap_or(usize::MAX)
            .min(input.len());
        let input = &input[..permitted];
        let end = position
            .checked_add(input.len() as u64)
            .filter(|end| *end <= i64::MAX as u64)
            .ok_or(-27)?;
        if end > backend.length(entry.backing)? {
            backend.resize(entry.backing, end)?;
        }
        let written = backend.write_at(entry.backing, position, input)?;
        if written > input.len() {
            return Err(-5);
        }
        entry.cursor = position + written as u64;
        Ok((position, written))
    }

    pub fn write_at<B: Backing<H>>(
        &self,
        id: u64,
        offset: u64,
        input: &[u8],
        backend: &mut B,
    ) -> Result<usize, i32> {
        let entry = self.entries.get(&id).ok_or(-9)?;
        if !entry.writable {
            return Err(-9);
        }
        if offset > i64::MAX as u64 {
            return Err(-22);
        }
        if input.is_empty() {
            return Ok(0);
        }
        let end = offset
            .checked_add(input.len() as u64)
            .filter(|end| *end <= i64::MAX as u64)
            .ok_or(-27)?;
        if end > backend.length(entry.backing)? {
            backend.resize(entry.backing, end)?;
        }
        let written = backend.write_at(entry.backing, offset, input)?;
        if written > input.len() {
            return Err(-5);
        }
        Ok(written)
    }

    pub fn seek<B: Backing<H>>(
        &mut self,
        id: u64,
        offset: i64,
        basis: u64,
        backend: &mut B,
    ) -> Result<u64, i32> {
        let entry = self.entries.get_mut(&id).ok_or(-9)?;
        let base = match basis {
            mnu_abi::HANDLE_SEEK_START => 0,
            mnu_abi::HANDLE_SEEK_CURRENT => entry.cursor,
            mnu_abi::HANDLE_SEEK_END => backend.length(entry.backing)?,
            _ => return Err(-22),
        };
        let position = (base as i128) + (offset as i128);
        if !(0..=i64::MAX as i128).contains(&position) {
            return Err(-22);
        }
        entry.cursor = position as u64;
        Ok(entry.cursor)
    }
}

/// Dispatch generic Provider frames. The caller must pass delivery metadata
/// obtained from native IPC, never flags supplied in the request payload, and
/// close any received attachments itself. RAM mapping uses separately attached
/// backing Handles; it must not construct a second Provider pager/cache.
pub fn handle_provider_request<H: Copy, B: Backing<H>>(
    descriptions: &mut Descriptions<H>,
    request: &[u8],
    delivery_flags: u32,
    attachment_count: u32,
    backend: &mut B,
    response: &mut [u8],
) -> Result<Option<usize>, i32> {
    use mnu_abi::provider;
    let (header, payload) = provider::RequestHeader::decode(request).map_err(|_| -22)?;
    let authenticated = delivery_flags == mnu_abi::IPC_DELIVERY_NATIVE_OBJECT;
    if authenticated && attachment_count == 0 && header.opcode == provider::OP_RELEASE {
        descriptions.release(header.object_id, backend)?;
        return Ok(None);
    }
    let maximum_data = if !authenticated || attachment_count != 0 {
        0
    } else {
        match header.opcode {
            provider::OP_READ | provider::OP_READ_AT => header.length as usize,
            provider::OP_READ_WITH_POSITION => header.length as usize + provider::READ_POSITION_LEN,
            provider::OP_WRITE_BOUNDED => core::mem::size_of::<u64>(),
            provider::OP_CONTROL => header.length as usize,
            _ => 0,
        }
    };
    // Validate reply capacity before changing position or backing contents.
    if response.len() < provider::RESPONSE_HEADER_LEN + maximum_data {
        return Err(-22);
    }
    let result: Result<(u64, Vec<u8>), i32> = if !authenticated {
        Err(-13)
    } else if attachment_count != 0 {
        Err(-22)
    } else {
        match header.opcode {
            provider::OP_READ | provider::OP_READ_WITH_POSITION => {
                let mut data = vec![0; header.length as usize];
                descriptions
                    .read(header.object_id, &mut data, backend)
                    .map(|(position, read)| {
                        data.truncate(read);
                        if header.opcode == provider::OP_READ_WITH_POSITION {
                            let mut positioned =
                                Vec::with_capacity(provider::READ_POSITION_LEN + read);
                            positioned.extend_from_slice(&position.to_le_bytes());
                            positioned.extend_from_slice(&data);
                            data = positioned;
                        }
                        (read as u64, data)
                    })
            }
            provider::OP_READ_AT => {
                let mut data = vec![0; header.length as usize];
                descriptions
                    .read_at(header.object_id, header.basis, &mut data, backend)
                    .map(|read| {
                        data.truncate(read);
                        (read as u64, data)
                    })
            }
            provider::OP_WRITE => descriptions
                .write(header.object_id, payload, backend)
                .map(|written| (written as u64, Vec::new())),
            provider::OP_WRITE_BOUNDED => descriptions
                .write_bounded(header.object_id, payload, header.basis, backend)
                .map(|(position, written)| (written as u64, position.to_le_bytes().to_vec())),
            provider::OP_WRITE_AT => descriptions
                .write_at(header.object_id, header.basis, payload, backend)
                .map(|written| (written as u64, Vec::new())),
            provider::OP_SEEK => descriptions
                .seek(header.object_id, header.argument, header.basis, backend)
                .map(|position| (position, Vec::new())),
            provider::OP_SYNC => descriptions
                .length(header.object_id, backend)
                .map(|_| (0, Vec::new())),
            provider::OP_CONTROL => {
                use mochios_posix_protocol::shared_memory as wire;
                match header.basis {
                    wire::CONTROL_LENGTH if payload.is_empty() && header.length == 8 => {
                        descriptions
                            .length(header.object_id, backend)
                            .map(|length| (8, length.to_le_bytes().to_vec()))
                    }
                    wire::CONTROL_RESIZE if payload.len() == 8 && header.length == 0 => {
                        let length = u64::from_le_bytes(payload.try_into().unwrap());
                        descriptions
                            .resize(header.object_id, length, backend)
                            .map(|_| (0, Vec::new()))
                    }
                    wire::CONTROL_RESIZE_BOUNDED if payload.len() == 16 && header.length == 0 => {
                        let length = u64::from_le_bytes(payload[..8].try_into().unwrap());
                        let ceiling = u64::from_le_bytes(payload[8..].try_into().unwrap());
                        descriptions
                            .resize_bounded(header.object_id, length, ceiling, backend)
                            .map(|_| (0, Vec::new()))
                    }
                    wire::CONTROL_GET_FLAGS if payload.is_empty() && header.length == 4 => {
                        descriptions
                            .status_flags(header.object_id)
                            .map(|flags| (4, flags.to_le_bytes().to_vec()))
                    }
                    wire::CONTROL_SET_FLAGS if payload.len() == 4 && header.length == 0 => {
                        let flags = u32::from_le_bytes(payload.try_into().unwrap());
                        descriptions
                            .set_status_flags(header.object_id, flags)
                            .map(|_| (0, Vec::new()))
                    }
                    wire::CONTROL_UPDATE_FLAGS if header.length == 0 => {
                        mochios_posix_protocol::decode_file_flags_update(payload)
                            .map_err(|_| -22)
                            .and_then(|(mask, flags)| {
                                descriptions.update_status_flags(header.object_id, mask, flags)
                            })
                            .map(|_| (0, Vec::new()))
                    }
                    wire::CONTROL_STAT
                        if payload.is_empty()
                            && header.length as usize
                                == mochios_posix_protocol::FILE_STATUS_LEN =>
                    {
                        descriptions
                            .status(header.object_id, backend)
                            .and_then(|status| {
                                let mut data = vec![0; mochios_posix_protocol::FILE_STATUS_LEN];
                                mochios_posix_protocol::encode_file_status(status, &mut data)
                                    .map_err(|_| -5)?;
                                Ok((data.len() as u64, data))
                            })
                    }
                    wire::CONTROL_LENGTH
                    | wire::CONTROL_RESIZE
                    | wire::CONTROL_RESIZE_BOUNDED
                    | wire::CONTROL_GET_FLAGS
                    | wire::CONTROL_SET_FLAGS
                    | wire::CONTROL_UPDATE_FLAGS
                    | wire::CONTROL_STAT => Err(-22),
                    _ => Err(-95),
                }
            }
            // Attached-buffer reads and mapping delegation require
            // their own validated handlers; never pretend they succeeded.
            _ => Err(-95),
        }
    };
    let (status, value, data) = match result {
        Ok((value, data)) => (0, value, data),
        Err(errno) => (i64::from(errno), 0, Vec::new()),
    };
    provider::ResponseHeader {
        opcode: header.opcode,
        status,
        object_id: header.object_id,
        value,
        data_length: data.len() as u32,
    }
    .encode(&data, response)
    .map(Some)
    .map_err(|_| -5)
}
