//! Admission is an optional envelope around three atomic mutations, not a
//! pathname permission or a new source of filesystem authority.
use mnu_abi::{IpcObjectHandle, IpcObjectHandles};
use mochios_filesystem_protocol as protocol;

pub const TICKET_RIGHTS: u64 = mnu_abi::HANDLE_RIGHT_WAIT | mnu_abi::HANDLE_RIGHT_TRANSFER;
const FLAGS: u32 = protocol::MUTATION_ADMISSION | protocol::MUTATION_ADMISSION_ATTACHED;

pub fn requested(header: protocol::Header) -> bool {
    header.flags & FLAGS != 0
}

/// These are borrowed views of the received references. The receiver must
/// retain the ORIGINAL attachment list until the reply completes, then close
/// every original reference even on malformed requests or failed replies.
pub struct Request {
    pub header: protocol::Header,
    pub sources: IpcObjectHandles,
    pub ticket: Option<u32>,
}

impl Request {
    pub fn decode(mut header: protocol::Header, received: &IpcObjectHandles) -> Result<Self, i32> {
        if received.delivery_flags != mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE {
            return Err(13);
        }
        if !matches!(
            header.opcode,
            protocol::OP_OPEN_AT | protocol::OP_TRUNCATE_HANDLE | protocol::OP_TRUNCATE_AT
        ) || header.flags & protocol::MUTATION_ADMISSION == 0
            || received.count as usize > received.handles.len()
        {
            return Err(22);
        }
        let mut sources = *received;
        let ticket = if header.flags & protocol::MUTATION_ADMISSION_ATTACHED != 0 {
            let index = sources.count.checked_sub(1).ok_or(22)? as usize;
            let object = sources.handles[index];
            if object.handle == 0 || object.reserved != 0 || object.rights != TICKET_RIGHTS {
                return Err(13);
            }
            // Distinct references are required. Do not let removal of the
            // trailing ticket hide a malformed/aliased target reference.
            if sources.handles[..index]
                .iter()
                .any(|source| source.handle == object.handle)
            {
                return Err(22);
            }
            sources.count -= 1;
            sources.handles[index] = IpcObjectHandle::default();
            Some(object.handle)
        } else {
            None
        };
        header.flags &= !FLAGS;
        Ok(Self {
            header,
            sources,
            ticket,
        })
    }
}

/// No delivery proof or surplus authority is forwarded in an outgoing reply.
pub fn reply_attachment(handle: u32) -> IpcObjectHandles {
    let mut outgoing = IpcObjectHandles::default();
    outgoing.count = 1;
    outgoing.handles[0] = IpcObjectHandle {
        handle,
        reserved: 0,
        rights: TICKET_RIGHTS,
    };
    outgoing
}
