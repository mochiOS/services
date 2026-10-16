//! Owner-side checks for explicitly attached open-description Handles.
//! A POSIX credential, path, or numeric open ID cannot replace this authority.
use mochios_filesystem_protocol as wire;

/// Authority issued with a newly opened description. Directory cursors are
/// seekable streams, not byte-addressable pager backing.
pub fn open_rights(flags: u32) -> u64 {
    let mut rights = mnu_abi::HANDLE_RIGHT_DUPLICATE
        | mnu_abi::HANDLE_RIGHT_CONTROL
        | mnu_abi::HANDLE_RIGHT_TRANSFER;
    if flags & (wire::OPEN_AT_READ | wire::OPEN_AT_SEARCH) != 0 {
        rights |= mnu_abi::HANDLE_RIGHT_READ;
    }
    if flags & wire::OPEN_AT_WRITE != 0 {
        rights |= mnu_abi::HANDLE_RIGHT_WRITE;
    }
    if flags & wire::OPEN_AT_DIRECTORY == 0 {
        rights |= mnu_abi::HANDLE_RIGHT_SEEK;
        if flags & wire::OPEN_AT_READ != 0 {
            rights |= mnu_abi::HANDLE_RIGHT_MAP;
        }
    } else if flags & wire::OPEN_AT_READ != 0 {
        rights |= mnu_abi::HANDLE_RIGHT_SEEK;
    }
    rights
}

pub fn authorize(opcode: u16, rights: u64) -> Result<(), i32> {
    let required = mnu_abi::HANDLE_RIGHT_TRANSFER
        | match opcode {
            wire::OP_TRUNCATE_HANDLE => mnu_abi::HANDLE_RIGHT_WRITE,
            wire::OP_CHMOD_HANDLE
            | wire::OP_CHOWN_HANDLE
            | wire::OP_SET_FLAGS_HANDLE
            | wire::OP_UPDATE_FLAGS_HANDLE => mnu_abi::HANDLE_RIGHT_CONTROL,
            wire::OP_SYNC_HANDLE | wire::OP_GET_FLAGS_HANDLE => 0,
            _ => return Err(38),
        };
    if rights & required == required {
        Ok(())
    } else {
        Err(13)
    }
}
