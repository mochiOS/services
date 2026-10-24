//! Private handoff from the POSIX dispatcher to its FIFO owner. The dispatcher
//! has already authenticated open policy and obtained a retained FS reply.
//! Metadata alone is never sufficient to ask for new READ/WRITE authority.
use crate::{
    fifo::Access,
    fifo_manager::{AdmittedInode, FilesystemScope},
    filesystem_reference::Reference,
};
use mnu_abi::IpcObjectHandles;
use mochios_filesystem_protocol as fs;

pub const MAGIC: &[u8; 4] = b"FIOP";
pub const PREFIX_LEN: usize = 8;
pub const MAX_REQUEST: usize = PREFIX_LEN + fs::HEADER_LEN + fs::NODE_STATUS_LEN;
pub const STOP: &[u8; 8] = b"FIST\x01\0\0\0";

pub fn encode(
    header: fs::Header,
    payload: &[u8],
    access: Access,
    nonblocking: bool,
) -> Result<Vec<u8>, i32> {
    if payload.len() != fs::NODE_STATUS_LEN {
        return Err(-22);
    }
    let mut bytes = vec![0; MAX_REQUEST];
    bytes[..4].copy_from_slice(MAGIC);
    bytes[4..6].copy_from_slice(&1u16.to_le_bytes());
    bytes[6] = match access {
        Access::Read => 0,
        Access::Write => 1,
    };
    bytes[7] = u8::from(nonblocking);
    let length = fs::encode(header, payload, &mut bytes[PREFIX_LEN..]).map_err(|_| -22)?;
    bytes.truncate(PREFIX_LEN + length);
    Ok(bytes)
}

/// Authentication comes from native endpoint-owner identity, never a number in
/// bytes. Until scope.admit consumes a reference it remains caller-owned.
pub fn admit_with(
    scope: FilesystemScope,
    trusted_dispatcher: bool,
    bytes: &[u8],
    objects: &mut IpcObjectHandles,
    adopt: impl FnOnce(mnu_abi::IpcObjectHandle) -> Result<Reference, i32>,
) -> Result<(AdmittedInode, bool), i32> {
    if !trusted_dispatcher || objects.delivery_flags != mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE {
        return Err(-13);
    }
    if bytes.len() != MAX_REQUEST
        || &bytes[..4] != MAGIC
        || bytes[4..6] != 1u16.to_le_bytes()
        || bytes[7] > 1
    {
        return Err(-22);
    }
    let access = match bytes[6] {
        0 => Access::Read,
        1 => Access::Write,
        _ => return Err(-22),
    };
    let (header, payload) = fs::decode(&bytes[PREFIX_LEN..]).map_err(|_| -22)?;
    // Correlation to the original FS call is checked by the dispatcher before
    // forwarding; the private trusted bridge revalidates the complete reply.
    let admitted = scope.admit(header, header.request_id, payload, objects, access, adopt)?;
    Ok((admitted, bytes[7] != 0))
}

pub fn data_rights(access: Access) -> u64 {
    mnu_abi::HANDLE_RIGHT_CONTROL
        | mnu_abi::HANDLE_RIGHT_DUPLICATE
        | mnu_abi::HANDLE_RIGHT_TRANSFER
        | mnu_abi::HANDLE_RIGHT_WAIT
        | match access {
            Access::Read => mnu_abi::HANDLE_RIGHT_READ,
            Access::Write => mnu_abi::HANDLE_RIGHT_WRITE,
        }
}
