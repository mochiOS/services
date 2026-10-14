//! Record commitment over an explicitly delegated RAM object. The socket
//! adapter authenticates IPC delivery, identifies the attached socket on its
//! owning endpoint, and resolves the destination before selecting the queue.

use crate::{
    socket_record::{RecordQueue, SourceAddress},
    AttachedObject,
};
use mochios_posix_protocol::{
    socket::Address,
    socket_record::{self as wire, Operation, Request},
};

/// Only kernel-supplied IPC attachment metadata may enter this function.
/// Returns borrowed receiver-local socket and RAM-buffer references. The
/// dispatcher's common cleanup owns and closes both references on every path.
pub fn authorize<H: Copy + Default + Eq>(
    request: Request,
    delivery_flags: u32,
    attachments: &[AttachedObject<H>],
) -> Result<(AttachedObject<H>, AttachedObject<H>), i32> {
    request.validate().map_err(|_| -22)?;
    if delivery_flags != mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE {
        return Err(-13);
    }
    if attachments.len() != 2 {
        return Err(-22);
    }
    let socket = attachments[0];
    let buffer = attachments[1];
    if socket.handle == H::default()
        || buffer.handle == H::default()
        || socket.rights != request.socket_rights()
        || buffer.rights != request.buffer_rights()
    {
        return Err(-13);
    }
    Ok((socket, buffer))
}

/// A native implementation must query MemoryObjectLength first: this checks
/// RAM type as well as extent, avoiding recursive RPC to an arbitrary Provider
/// supplied as a "buffer". No borrowed Rust slices of concurrently mapped RAM
/// are constructed. Data is copied through native positioned Handle I/O.
pub trait RecordBuffer {
    fn extent(&self) -> Result<u64, i32>;
    fn read(&mut self, offset: u64, output: &mut [u8]) -> Result<(), i32>;
    fn write(&mut self, offset: u64, input: &[u8]) -> Result<(), i32>;
}

/// Serialize this entire operation with other accesses to the selected queue.
/// `source` is the sending description's saved address, not request data.
/// A successful return commits exactly one record (or one PEEK), even when
/// its payload is empty. Errors never consume/append a record.
pub fn transfer(
    queue: &mut RecordQueue,
    request: Request,
    source: SourceAddress,
    send_capacity: usize,
    buffer: &mut impl RecordBuffer,
    response: &mut [u8],
) -> Result<usize, i32> {
    request.validate().map_err(|_| -22)?;
    // Validate reply capacity before touching the queue or shared memory.
    if response.len() < wire::MAX_REPLY_LEN {
        return Err(-22);
    }
    let end = request
        .offset
        .checked_add(u64::from(request.length))
        .ok_or(-22)?;
    if end > buffer.extent()? {
        return Err(-22);
    }
    let length = request.length as usize;
    if request.operation == Operation::Send && !queue.can_push(length, send_capacity)? {
        return Err(-11);
    }
    let mut data = Vec::new();
    data.try_reserve_exact(length).map_err(|_| -12)?;
    data.resize(length, 0);
    match request.operation {
        Operation::Send => {
            buffer.read(request.offset, &mut data)?;
            let reply = wire::Reply {
                copied: request.length,
                length: request.length,
                source: None,
            };
            // Prepare the infallible success bytes before final commitment.
            let count = reply.encode(request, response).map_err(|_| -5)?;
            queue.push(source, &data, send_capacity)?;
            Ok(count)
        }
        Operation::Receive => {
            let record = queue.receive(&mut data, true)?;
            let source = Address::decode(record.source.encoded()).map_err(|_| -5)?;
            let reply = wire::Reply {
                copied: record.copied as u32,
                length: record.length as u32,
                source: Some(source),
            };
            let count = reply.encode(request, response).map_err(|_| -5)?;
            buffer.write(request.offset, &data[..record.copied])?;
            if !request.peek {
                // Queue serialization preserves the exact record just copied;
                // discard the suffix only after the output copy succeeds.
                queue.receive(&mut [], false)?;
            }
            Ok(count)
        }
    }
}

#[cfg(target_os = "mochios")]
pub struct NativeBuffer {
    /// Borrowed IPC-received reference. The dispatcher, not this view, closes it.
    handle: u32,
}

#[cfg(target_os = "mochios")]
impl NativeBuffer {
    pub fn borrowed(handle: u32) -> Self {
        Self { handle }
    }
}

#[cfg(target_os = "mochios")]
impl RecordBuffer for NativeBuffer {
    fn extent(&self) -> Result<u64, i32> {
        mochi_user_platform::syscall::call1(
            mnu_abi::SyscallNumber::MemoryObjectLength,
            self.handle as u64,
        )
        .map_err(|error| error.raw() as i32)
    }

    fn read(&mut self, offset: u64, output: &mut [u8]) -> Result<(), i32> {
        let count = mochi_user_platform::handle::read_at(self.handle, output, offset)
            .map_err(|error| error.raw() as i32)?;
        if count == output.len() {
            Ok(())
        } else {
            Err(-5)
        }
    }

    fn write(&mut self, offset: u64, input: &[u8]) -> Result<(), i32> {
        let count = mochi_user_platform::handle::write_at(self.handle, input, offset)
            .map_err(|error| error.raw() as i32)?;
        if count == input.len() {
            Ok(())
        } else {
            Err(-5)
        }
    }
}
