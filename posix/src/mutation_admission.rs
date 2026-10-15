//! Borrowed request envelope; POSIX policy is still checked on every attempt.
use crate::{AttachedObject, STATUS_EINVAL};
use mochios_posix_protocol as protocol;

pub const TICKET_RIGHTS: u64 = mnu_abi::HANDLE_RIGHT_WAIT | mnu_abi::HANDLE_RIGHT_TRANSFER;
const FLAGS: u32 = protocol::MUTATION_ADMISSION | protocol::MUTATION_ADMISSION_ATTACHED;

pub struct Request<'a, H> {
    pub header: protocol::Header,
    pub sources: &'a [AttachedObject<H>],
    /// None: legacy operation; Some(None): queue a new position;
    /// Some(Some(ticket)): retry with the explicitly attached position.
    pub admission: Option<Option<AttachedObject<H>>>,
}

impl<'a, H: Copy> Request<'a, H> {
    pub fn decode(
        mut header: protocol::Header,
        handles: &'a [AttachedObject<H>],
    ) -> Result<Self, i32> {
        if header.flags & FLAGS == 0 {
            return Ok(Self {
                header,
                sources: handles,
                admission: None,
            });
        }
        if header.status != 0
            || header.flags & !FLAGS != 0
            || header.flags & protocol::MUTATION_ADMISSION == 0
            || !matches!(
                header.opcode,
                protocol::OP_OPEN_AT | protocol::OP_FTRUNCATE | protocol::OP_TRUNCATE_AT
            )
        {
            return Err(STATUS_EINVAL);
        }
        let (sources, ticket) = if header.flags & protocol::MUTATION_ADMISSION_ATTACHED != 0 {
            let (ticket, sources) = handles.split_last().ok_or(STATUS_EINVAL)?;
            if ticket.rights != TICKET_RIGHTS {
                return Err(-13);
            }
            (sources, Some(*ticket))
        } else {
            (handles, None)
        };
        header.flags = 0;
        Ok(Self {
            header,
            sources,
            admission: Some(ticket),
        })
    }
}
