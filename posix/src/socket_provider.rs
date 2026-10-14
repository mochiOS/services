//! Dispatch generic native Provider requests into userspace socket semantics.
//! Delivery metadata must come from the kernel, not request bytes. Received
//! attachments remain owned by the caller and must be closed there.

use crate::socket::{Shutdown, Streams};
use mnu_abi::provider;
use mochios_posix_protocol::socket as wire;

/// Native readiness means an operation can complete, including EOF/EPIPE.
/// POSIX poll must inspect CONTROL_READINESS to distinguish those outcomes.
pub fn native_signals(ready: crate::socket::Readiness) -> u64 {
    (if ready.readable {
        mnu_abi::HANDLE_SIGNAL_READABLE
    } else {
        0
    }) | (if ready.writable || ready.write_closed {
        mnu_abi::HANDLE_SIGNAL_WRITABLE
    } else {
        0
    }) | (if ready.read_closed && ready.write_closed {
        mnu_abi::HANDLE_SIGNAL_PEER_CLOSED
    } else {
        0
    })
}

pub fn handle_provider_request(
    streams: &mut Streams,
    request: &[u8],
    delivery_flags: u32,
    attachment_count: u32,
    response: &mut [u8],
) -> Result<Option<usize>, i32> {
    let (header, payload) = provider::RequestHeader::decode(request).map_err(|_| -22)?;
    let authenticated = delivery_flags == mnu_abi::IPC_DELIVERY_NATIVE_OBJECT;
    if authenticated && attachment_count == 0 && header.opcode == provider::OP_RELEASE {
        streams.release(header.object_id)?;
        return Ok(None);
    }
    let maximum_data = if authenticated && attachment_count == 0 {
        match header.opcode {
            provider::OP_READ | provider::OP_CONTROL => header.length as usize,
            _ => 0,
        }
    } else {
        0
    };
    // No read, write, flags update or shutdown before reply capacity validation.
    if response.len() < provider::RESPONSE_HEADER_LEN + maximum_data {
        return Err(-22);
    }
    let mut data = [0; provider::MAX_DATA_LEN];
    let result: Result<(u64, usize), i32> = if !authenticated {
        Err(-13)
    } else if attachment_count != 0 {
        Err(-22)
    } else {
        match header.opcode {
            provider::OP_READ => streams
                .read(header.object_id, &mut data[..header.length as usize])
                .map(|count| (count as u64, count)),
            provider::OP_WRITE => streams
                .write(header.object_id, payload)
                .map(|count| (count as u64, 0)),
            provider::OP_CONTROL => match header.basis {
                wire::CONTROL_GET_OPTIONS if payload.is_empty() && header.length == 4 => {
                    streams.options(header.object_id).map(|options| {
                        data[..4].copy_from_slice(&options.to_le_bytes());
                        (4, 4)
                    })
                }
                wire::CONTROL_SET_OPTIONS if payload.len() == 4 && header.length == 0 => {
                    let options = u32::from_le_bytes(payload.try_into().unwrap());
                    streams
                        .set_options(header.object_id, options)
                        .map(|_| (0, 0))
                }
                wire::CONTROL_SHUTDOWN if payload.len() == 4 && header.length == 0 => {
                    let how = match u32::from_le_bytes(payload.try_into().unwrap()) {
                        wire::SHUTDOWN_READ => Some(Shutdown::Read),
                        wire::SHUTDOWN_WRITE => Some(Shutdown::Write),
                        wire::SHUTDOWN_BOTH => Some(Shutdown::Both),
                        _ => None,
                    };
                    how.ok_or(-22)
                        .and_then(|how| streams.shutdown(header.object_id, how))
                        .map(|_| (0, 0))
                }
                wire::CONTROL_READINESS if payload.is_empty() && header.length == 4 => {
                    streams.readiness(header.object_id).map(|ready| {
                        let bits = if ready.readable { wire::READY_READ } else { 0 }
                            | if ready.writable { wire::READY_WRITE } else { 0 }
                            | if ready.read_closed {
                                wire::READ_CLOSED
                            } else {
                                0
                            }
                            | if ready.write_closed {
                                wire::WRITE_CLOSED
                            } else {
                                0
                            };
                        data[..4].copy_from_slice(&bits.to_le_bytes());
                        (4, 4)
                    })
                }
                wire::CONTROL_GET_OPTIONS
                | wire::CONTROL_SET_OPTIONS
                | wire::CONTROL_SHUTDOWN
                | wire::CONTROL_READINESS => Err(-22),
                _ => Err(-95),
            },
            provider::OP_SEEK
            | provider::OP_READ_AT
            | provider::OP_WRITE_AT
            | provider::OP_READ_WITH_POSITION => streams.options(header.object_id).and(Err(-29)),
            _ => Err(-95),
        }
    };
    let (status, value, count) = match result {
        Ok((value, count)) => (0, value, count),
        Err(error) => (i64::from(error), 0, 0),
    };
    provider::ResponseHeader {
        opcode: header.opcode,
        status,
        object_id: header.object_id,
        value,
        data_length: count as u32,
    }
    .encode(&data[..count], response)
    .map(Some)
    .map_err(|_| -5)
}
