//! Native object delivery has already authenticated the selected provider ID.
//! No pathname, PID, client FD or credential is accepted in this operation.
use crate::service::FilesystemService;
use mnu_abi::provider;
use mochios_filesystem_protocol::{self as wire, description_flags as flags};

pub fn handle(
    service: &mut FilesystemService,
    header: provider::RequestHeader,
    payload: &[u8],
    attachments: u32,
) -> Result<(u64, Vec<u8>), i32> {
    if attachments != 0 || header.argument != 0 || header.data_length as usize != payload.len() {
        return Err(22);
    }
    match (header.opcode, header.basis) {
        (provider::OP_QUERY | provider::OP_CONTROL, flags::GET) => {
            if !payload.is_empty() || header.length != 4 {
                return Err(22);
            }
            let result = service.get_flags_handle(wire::Header::default(), header.object_id)?;
            Ok((4, result.header.flags.to_le_bytes().to_vec()))
        }
        (provider::OP_CONTROL, flags::UPDATE) => {
            if header.length != 0 {
                return Err(22);
            }
            let (mask, flags) = flags::decode_update(payload).ok_or(22)?;
            service.update_flags_handle(
                wire::Header {
                    flags,
                    ..Default::default()
                },
                header.object_id,
                mask,
            )?;
            Ok((0, Vec::new()))
        }
        _ => Err(95),
    }
}
