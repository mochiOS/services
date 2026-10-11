//! Reads the immutable boot generation through an explicitly inherited SEND
//! Handle. No kernel path API, service discovery, or mutable Data fallback.

use mochi_user_platform as platform;
use mochios_filesystem_protocol as wire;
use platform::syscall::{self, SysError, SysResult};
use std::sync::Mutex;

const MAX_BOOT_FILE_BYTES: usize = 256 * 1024 * 1024;
const MAX_DIRECTORY_BYTES: usize = 256 * 1024;
type Transport = fn(u32, &[u8], &mut [u8]) -> SysResult<usize>;
static READER: Mutex<Option<Client<Transport>>> = Mutex::new(None);

pub(crate) fn initialize() -> SysResult<()> {
    let handle = platform::handle::inherited(wire::BOOTSTRAP_READ_HANDLE_KEY)?;
    // SEND alone is sufficient. Reject incorrectly delegated broader authority.
    if platform::handle::rights(handle)? != platform::handle::HANDLE_RIGHT_SEND {
        return Err(error(syscall::EACCES));
    }
    platform::handle::remove_context_handle(wire::BOOTSTRAP_READ_HANDLE_KEY)?;
    let mut reader = READER.lock().map_err(|_| error(syscall::EIO))?;
    if reader.is_some() {
        return Err(error(syscall::EEXIST));
    }
    *reader = Some(Client::new(handle, native_call as Transport));
    Ok(())
}

fn native_call(endpoint: u32, request: &[u8], reply: &mut [u8]) -> SysResult<usize> {
    let mut handles = platform::ipc::IpcObjectHandles::default();
    let result = platform::ipc::call_object_handles(endpoint, request, reply, &mut handles);
    let attached = handles.reserved != 0 || handles.count != 0;
    for entry in handles
        .handles
        .iter()
        .take((handles.count as usize).min(handles.handles.len()))
    {
        if entry.handle != 0 {
            let _ = platform::handle::close(entry.handle);
        }
    }
    if attached {
        return Err(error(syscall::EIO));
    }
    let length = (result? & 0xffff_ffff) as usize;
    if length > reply.len() {
        return Err(error(syscall::EIO));
    }
    Ok(length)
}

pub(crate) fn read_file(path: &str) -> SysResult<Vec<u8>> {
    let mut reader = READER.lock().map_err(|_| error(syscall::EIO))?;
    reader
        .as_mut()
        .ok_or_else(|| error(syscall::EAGAIN))?
        .read_file(path, MAX_BOOT_FILE_BYTES)
}

pub(crate) fn read_dir_names(path: &str) -> SysResult<Vec<String>> {
    let mut reader = READER.lock().map_err(|_| error(syscall::EIO))?;
    reader
        .as_mut()
        .ok_or_else(|| error(syscall::EAGAIN))?
        .read_dir_names(path, MAX_DIRECTORY_BYTES)
}

fn error(raw: u64) -> SysError {
    SysError::from_raw(raw as i64)
}

fn buffer(length: usize) -> SysResult<Vec<u8>> {
    let mut result = Vec::new();
    result
        .try_reserve_exact(length)
        .map_err(|_| error(syscall::ENOMEM))?;
    result.resize(length, 0);
    Ok(result)
}

pub(crate) struct Client<F> {
    endpoint: u32,
    next_request: u64,
    transport: F,
}

impl<F: FnMut(u32, &[u8], &mut [u8]) -> SysResult<usize>> Client<F> {
    pub(crate) fn new(endpoint: u32, transport: F) -> Self {
        Self {
            endpoint,
            next_request: 1,
            transport,
        }
    }

    fn exchange(
        &mut self,
        opcode: u16,
        path: &str,
        offset: u64,
        budget: usize,
    ) -> SysResult<(wire::Header, Vec<u8>)> {
        if !path.starts_with('/') || path.contains('\0') || path.len() > wire::MAX_PATH_LEN {
            return Err(error(syscall::EINVAL));
        }
        let id = self.next_request;
        self.next_request = id.checked_add(1).ok_or_else(|| error(syscall::EOVERFLOW))?;
        let mut request = buffer(wire::HEADER_LEN + path.len())?;
        wire::encode(
            wire::Header {
                opcode,
                request_id: id,
                offset,
                flags: budget as u32,
                length: path.len() as u32,
                ..wire::Header::default()
            },
            path.as_bytes(),
            &mut request,
        )
        .map_err(|_| error(syscall::EINVAL))?;
        let mut reply = buffer(wire::HEADER_LEN + budget)?;
        let length = (self.transport)(self.endpoint, &request, &mut reply)?;
        let received = reply.get(..length).ok_or_else(|| error(syscall::EIO))?;
        let (header, payload) = wire::decode(received).map_err(|_| error(syscall::EIO))?;
        if length != wire::HEADER_LEN + payload.len()
            || header.opcode != wire::OP_STATUS
            || header.request_id != id
            || header.mount_id != 0
            || header.node_id != 0
            || header.open_id != 0
            || header.mode != 0
            || header.flags & !wire::BOOTSTRAP_EOF != 0
            || payload.len() > budget
        {
            return Err(error(syscall::EIO));
        }
        if header.status != 0 {
            if !(-4095..0).contains(&header.status)
                || !payload.is_empty()
                || header.flags != 0
                || header.offset != 0
            {
                return Err(error(syscall::EIO));
            }
            return Err(SysError::from_raw(header.status as i64));
        }
        reply.drain(..wire::HEADER_LEN);
        reply.truncate(header.length as usize);
        Ok((header, reply))
    }

    pub(crate) fn read_file(&mut self, path: &str, maximum: usize) -> SysResult<Vec<u8>> {
        let mut output = Vec::new();
        loop {
            let offset = output.len() as u64;
            let budget = (maximum - output.len())
                .saturating_add(1)
                .min(wire::BOOTSTRAP_MAX_TRANSFER);
            let (header, bytes) = self.exchange(wire::OP_READ, path, offset, budget)?;
            if header.offset != offset + bytes.len() as u64 || bytes.is_empty() && header.flags == 0
            {
                return Err(error(syscall::EIO));
            }
            if bytes.len() > maximum - output.len() {
                return Err(SysError::from_raw(-27));
            }
            output
                .try_reserve(bytes.len())
                .map_err(|_| error(syscall::ENOMEM))?;
            output.extend_from_slice(&bytes);
            if header.flags == wire::BOOTSTRAP_EOF {
                return Ok(output);
            }
        }
    }

    pub(crate) fn read_dir_names(&mut self, path: &str, maximum: usize) -> SysResult<Vec<String>> {
        let mut names = Vec::new();
        let mut cursor = 0;
        let mut total = 0usize;
        loop {
            let (header, bytes) =
                self.exchange(wire::OP_READDIR, path, cursor, wire::BOOTSTRAP_MAX_TRANSFER)?;
            if header.offset < cursor
                || header.flags == 0 && (header.offset == cursor || bytes.is_empty())
            {
                return Err(error(syscall::EIO));
            }
            total = total
                .checked_add(bytes.len())
                .filter(|total| *total <= maximum)
                .ok_or_else(|| error(syscall::EOVERFLOW))?;
            let mut payload = bytes.as_slice();
            while !payload.is_empty() {
                let (entry, name, consumed) =
                    wire::decode_dir_entry(payload).map_err(|_| error(syscall::EIO))?;
                if entry.node_id != 0 || entry.kind != 0 || name == b"." || name == b".." {
                    return Err(error(syscall::EIO));
                }
                let name = std::str::from_utf8(name).map_err(|_| error(syscall::EIO))?;
                let mut owned = String::new();
                owned
                    .try_reserve_exact(name.len())
                    .map_err(|_| error(syscall::ENOMEM))?;
                owned.push_str(name);
                names.try_reserve(1).map_err(|_| error(syscall::ENOMEM))?;
                names.push(owned);
                payload = &payload[consumed..];
            }
            if header.flags == wire::BOOTSTRAP_EOF {
                return Ok(names);
            }
            cursor = header.offset;
        }
    }
}
