//! Owner-side checks for explicitly attached open-description Handles.
//! A POSIX credential, path, or numeric open ID cannot replace this authority.
use mochios_filesystem_protocol as wire;

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
