//! Service-owned open descriptions for RAM backing. Provider object IDs select
//! these descriptions only after native transport authentication; they are not
//! client FD numbers. Dup/fork aliases retain one description and cursor.

use std::collections::BTreeMap;

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
    append: bool,
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
        let next = self.next.checked_add(1).ok_or(-23)?;
        let retained = backend.retain(backing)?;
        let id = self.next;
        self.entries.insert(
            id,
            Description {
                backing: retained,
                writable,
                cursor: 0,
                append: false,
            },
        );
        self.next = next;
        Ok(id)
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

    pub fn resize<B: Backing<H>>(&self, id: u64, length: u64, backend: &mut B) -> Result<(), i32> {
        let entry = self.entries.get(&id).ok_or(-9)?;
        if !entry.writable {
            return Err(-9);
        }
        if length > i64::MAX as u64 {
            return Err(-22);
        }
        // ftruncate does not change an open description's file position.
        backend.resize(entry.backing, length)
    }

    pub fn set_append(&mut self, id: u64, append: bool) -> Result<(), i32> {
        self.entries.get_mut(&id).ok_or(-9)?.append = append;
        Ok(())
    }

    pub fn append(&self, id: u64) -> Result<bool, i32> {
        Ok(self.entries.get(&id).ok_or(-9)?.append)
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
        let entry = self.entries.get_mut(&id).ok_or(-9)?;
        if !entry.writable {
            return Err(-9);
        }
        if input.is_empty() {
            return Ok(0);
        }
        let position = if entry.append {
            backend.length(entry.backing)?
        } else {
            entry.cursor
        };
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
        Ok(written)
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
            provider::OP_WRITE_AT => descriptions
                .write_at(header.object_id, header.basis, payload, backend)
                .map(|written| (written as u64, Vec::new())),
            provider::OP_SEEK => descriptions
                .seek(header.object_id, header.argument, header.basis, backend)
                .map(|position| (position, Vec::new())),
            provider::OP_SYNC => descriptions
                .length(header.object_id, backend)
                .map(|_| (0, Vec::new())),
            // Control, attached-buffer reads and mapping delegation require
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
