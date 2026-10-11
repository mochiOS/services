//! Bounded request handling for a private, read-only bootstrap endpoint.
//!
//! The endpoint owner must delegate SEND authority explicitly and dispatch only
//! messages received on that endpoint, rejecting Handle attachments. This is
//! not the runtime filesystem provider endpoint: READ and READDIR carry an
//! absolute path instead of provider-owned node/open IDs. All such IDs, status,
//! and mode must be zero. The selected partition must remain immutable.
//!
//! Requests use filesystem-protocol v1. `flags` is the byte budget and `offset`
//! is a file position or directory cookie. Replies use OP_STATUS, preserve the
//! request ID, carry negative errno on failure, and set `flags = EOF` on EOF.
//! Directory replies contain name-only directory records (node ID/kind zero).
//! No PID, service name, FD, raw pointer, or disk authority is serialized.

use std::io;

use mochios_filesystem_protocol as wire;

use crate::bootstrap_read::BootstrapReader;

pub use wire::{BOOTSTRAP_EOF as EOF, BOOTSTRAP_MAX_TRANSFER as MAX_TRANSFER};
const MAX_ENTRIES: usize = 128;

/// Format a reply into caller-owned storage. Malformed requests receive EINVAL
/// (request ID zero if their header cannot be decoded); unknown operations
/// receive ENOSYS. Only an undersized reply buffer prevents an error reply.
pub fn respond(reader: &BootstrapReader, request: &[u8], reply: &mut [u8]) -> io::Result<usize> {
    if reply.len() < wire::HEADER_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "reply header buffer too small",
        ));
    }
    let mut response = wire::Header {
        opcode: wire::OP_STATUS,
        ..wire::Header::default()
    };
    let result = wire::decode(request)
        .map_err(|_| io::Error::from_raw_os_error(22))
        .and_then(|(header, path)| {
            response.request_id = header.request_id;
            if request.len() != wire::HEADER_LEN + path.len()
                || header.mount_id != 0
                || header.node_id != 0
                || header.open_id != 0
                || header.status != 0
                || header.mode != 0
            {
                return Err(io::Error::from_raw_os_error(22));
            }
            if !matches!(header.opcode, wire::OP_READ | wire::OP_READDIR) {
                return Err(io::Error::from_raw_os_error(38));
            }
            let budget = header.flags as usize;
            if budget == 0
                || budget > MAX_TRANSFER
                || path.is_empty()
                || path.len() > wire::MAX_PATH_LEN
            {
                return Err(io::Error::from_raw_os_error(22));
            }
            let path = std::str::from_utf8(path).map_err(|_| io::Error::from_raw_os_error(22))?;
            if !path.starts_with('/') || path.contains('\0') {
                return Err(io::Error::from_raw_os_error(22));
            }
            // Reject rather than silently truncate a caller's declared budget.
            let output = reply
                .get_mut(wire::HEADER_LEN..wire::HEADER_LEN + budget)
                .ok_or_else(|| io::Error::from_raw_os_error(22))?;
            if header.opcode == wire::OP_READ {
                let count = reader.read_at(path, header.offset, output)?;
                response.offset = header.offset + count as u64;
                response.flags = if count < budget { EOF } else { 0 };
                Ok(count)
            } else {
                if budget <= wire::DIRENT_HEADER_LEN {
                    return Err(io::Error::from_raw_os_error(22));
                }
                // Reserve per-record overhead before passing the remaining name
                // budget to the reader. Thus even 255-byte names fit precisely.
                let entries =
                    (budget / (wire::DIRENT_HEADER_LEN + wire::MAX_NAME_LEN)).clamp(1, MAX_ENTRIES);
                let page = reader.read_directory(
                    path,
                    header.offset,
                    entries,
                    budget - entries * wire::DIRENT_HEADER_LEN,
                )?;
                let mut length = 0;
                for name in page.names {
                    length += wire::encode_dir_entry(0, 0, name.as_bytes(), &mut output[length..])
                        .map_err(|_| io::Error::from_raw_os_error(5))?;
                }
                response.offset = page.next_entry;
                response.flags = if page.eof { EOF } else { 0 };
                Ok(length)
            }
        });
    let length = match result {
        Ok(length) => length,
        Err(error) => {
            response.status = -errno(&error);
            response.offset = 0;
            response.flags = 0;
            0
        }
    };
    response.length = length as u32;
    // Payload is already in place; encoding an empty header avoids copying it
    // or allocating a second message-sized buffer.
    let mut header = [0; wire::HEADER_LEN];
    wire::encode(
        wire::Header {
            length: 0,
            ..response
        },
        &[],
        &mut header,
    )
    .map_err(|_| io::Error::from_raw_os_error(5))?;
    header[48..52].copy_from_slice(&response.length.to_le_bytes());
    reply[..wire::HEADER_LEN].copy_from_slice(&header);
    Ok(wire::HEADER_LEN + length)
}

fn errno(error: &io::Error) -> i32 {
    if let Some(code) = error.raw_os_error().filter(|code| *code > 0) {
        return code;
    }
    match error.kind() {
        io::ErrorKind::NotFound => 2,
        io::ErrorKind::PermissionDenied => 13,
        io::ErrorKind::AlreadyExists => 17,
        io::ErrorKind::NotADirectory => 20,
        io::ErrorKind::IsADirectory => 21,
        io::ErrorKind::InvalidInput => 22,
        io::ErrorKind::FileTooLarge => 27,
        io::ErrorKind::StorageFull => 28,
        io::ErrorKind::ReadOnlyFilesystem => 30,
        io::ErrorKind::OutOfMemory => 12,
        _ => 5,
    }
}
