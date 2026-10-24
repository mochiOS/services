//! Generic native Provider I/O for an owner-resolved FIFO description.
//! This adapter does not resolve paths, manufacture inode authority or complete
//! blocking opens. Received attachments remain owned by the caller.
use crate::fifo::{Channel, DescriptionId, Error, Readiness};
use mnu_abi::provider;

/// Created only after the owner has registered a native Provider reference.
/// Native object IDs are owner-local routing data, never client credentials.
/// Dup/fork/transfer share this binding; OP_RELEASE retires it once, on the last
/// native reference. Caller must choose the binding from its authenticated
/// native object table, not from a client-supplied PID, FD or inode number.
#[derive(Clone, Copy)]
pub struct Binding {
    object_id: u64,
    description: DescriptionId,
}

impl Binding {
    pub fn new(object_id: u64, description: DescriptionId) -> Result<Self, i32> {
        if object_id == 0 {
            return Err(-22);
        }
        Ok(Self {
            object_id,
            description,
        })
    }
}

/// Native readiness describes operations that can complete, including EOF or
/// broken writes. POSIX poll additionally needs the owner's typed readiness.
pub fn native_signals(ready: Readiness) -> u64 {
    (if ready.readable || ready.end_of_stream {
        mnu_abi::HANDLE_SIGNAL_READABLE
    } else {
        0
    }) | (if ready.writable || ready.write_error {
        mnu_abi::HANDLE_SIGNAL_WRITABLE
    } else {
        0
    }) | (if ready.hangup || ready.write_error {
        mnu_abi::HANDLE_SIGNAL_PEER_CLOSED
    } else {
        0
    })
}

fn status(error: Error) -> i32 {
    match error {
        Error::BadDescription | Error::WrongAccess => -9,
        Error::OpenPending | Error::WouldBlock => -11,
        // This conversion is for data writes. Nonblocking open with no reader
        // must instead map NoReaders to ENXIO at the open-policy boundary.
        Error::NoReaders => -32,
        Error::ResourceLimit => -23,
        Error::NoMemory => -12,
    }
}

/// A complete native request is validated, including reply capacity, before
/// consuming bytes or changing peer counts. A trusted release has no reply.
pub fn handle_provider_request(
    channel: &mut Channel,
    binding: Binding,
    request: &[u8],
    delivery_flags: u32,
    attachment_count: u32,
    response: &mut [u8],
) -> Result<Option<usize>, i32> {
    let (header, payload) = provider::RequestHeader::decode(request).map_err(|_| -22)?;
    let authenticated = delivery_flags == mnu_abi::IPC_DELIVERY_NATIVE_OBJECT;
    if authenticated
        && attachment_count == 0
        && header.object_id == binding.object_id
        && header.opcode == provider::OP_RELEASE
    {
        channel.close(binding.description).map_err(status)?;
        return Ok(None);
    }
    let maximum_data = if authenticated
        && attachment_count == 0
        && header.object_id == binding.object_id
        && header.opcode == provider::OP_READ
    {
        header.length as usize
    } else {
        0
    };
    if response.len() < provider::RESPONSE_HEADER_LEN + maximum_data {
        return Err(-22);
    }
    let mut data = [0; provider::MAX_DATA_LEN];
    let result = if !authenticated {
        Err(-13)
    } else if attachment_count != 0 || header.object_id != binding.object_id {
        Err(-22)
    } else {
        channel
            .observe(binding.description)
            .map_err(status)
            .and_then(|_| match header.opcode {
                provider::OP_MEMORY_OBJECT => Ok((0, 0)),
                provider::OP_READ => channel
                    .read(binding.description, &mut data[..header.length as usize])
                    .map(|count| (count as u64, count))
                    .map_err(status),
                provider::OP_WRITE => channel
                    .write(binding.description, payload)
                    .map(|count| (count as u64, 0))
                    .map_err(status),
                provider::OP_SEEK
                | provider::OP_READ_AT
                | provider::OP_WRITE_AT
                | provider::OP_READ_WITH_POSITION
                | provider::OP_WRITE_BOUNDED => Err(-29),
                _ => Err(-95),
            })
    };
    let (status, value, length) = match result {
        Ok((value, length)) => (0, value, length),
        Err(status) => (i64::from(status), 0, 0),
    };
    provider::ResponseHeader {
        opcode: header.opcode,
        object_id: header.object_id,
        status,
        value,
        data_length: length as u32,
    }
    .encode(&data[..length], response)
    .map(Some)
    .map_err(|_| -22)
}
