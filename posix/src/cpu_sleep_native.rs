//! Native completion streams for the serialized CPU sleep dispatcher.
use mochi_user_platform as platform;
use mochios_posix_protocol::{self as protocol, cpu_sleep as wire};
use posix_service::{AttachedObject, PeerIdentity, PosixService, RequestImage};

struct Owned(u32);
impl Drop for Owned {
    fn drop(&mut self) {
        let _ = platform::handle::close(self.0);
    }
}

pub(super) struct Channel(Owned);
pub(super) type Registry = posix_service::cpu_sleep::Registry<Channel>;

fn failure(error: platform::syscall::SysError) -> i32 {
    protocol::status::normalize_failure(error.raw())
}

fn not_ready(error: &platform::syscall::SysError) -> bool {
    mnu_abi::status::Error::from_raw(error.raw() as u64) == Some(mnu_abi::status::Error::NotReady)
}

impl posix_service::cpu_sleep::Completion for Channel {
    fn peer_closed(&mut self) -> Result<bool, i32> {
        let mut item = [mnu_abi::HandleWaitItem {
            handle: self.0.0,
            interests: mnu_abi::HANDLE_SIGNAL_PEER_CLOSED,
            ..Default::default()
        }];
        match platform::process::wait_many(&mut item, mnu_abi::HANDLE_WAIT_POLL) {
            Ok(_) => Ok(true),
            Err(error) if not_ready(&error) => Ok(false),
            Err(error) => Err(failure(error)),
        }
    }

    fn publish(&mut self, result: Result<(), i32>) -> Result<bool, i32> {
        let mut packet = [0; wire::COMPLETION_LEN];
        wire::encode_completion(result, &mut packet).map_err(|_| protocol::STATUS_EIO)?;
        // All-or-none and nonblocking are per-call properties. Never enqueue a
        // partial status record or hold the service loop behind a slow reader.
        match platform::syscall::call4(
            platform::syscall::SyscallNumber::StreamWrite,
            u64::from(self.0.0),
            packet.as_ptr() as u64,
            packet.len() as u64,
            mnu_abi::STREAM_WRITE_COMPLETE | mnu_abi::STREAM_IO_TRY,
        ) {
            Ok(length) if length == packet.len() as u64 => Ok(true),
            Ok(_) => Err(protocol::STATUS_EIO),
            Err(error) if not_ready(&error) => Ok(false),
            Err(error) => Err(failure(error)),
        }
    }
}

pub(super) fn begin<B: posix_service::process_timer_request::ClockBackend<u32>>(
    waits: &mut Registry,
    service: &mut PosixService<u32>,
    peer: PeerIdentity,
    image: RequestImage,
    header: protocol::Header,
    payload: &[u8],
    attachments: &[AttachedObject<u32>],
    backend: &mut B,
    sender: u64,
) -> Result<bool, i32> {
    if header.flags != 0
        || header.status != 0
        || header.payload_len as usize != payload.len()
        || !attachments.is_empty()
    {
        return Err(posix_service::STATUS_EINVAL);
    }
    wire::decode_request(payload).map_err(|_| posix_service::STATUS_EINVAL)?;
    let mut pair = mnu_abi::StreamPair::default();
    platform::syscall::call1(
        platform::syscall::SyscallNumber::StreamPairCreate,
        (&mut pair as *mut mnu_abi::StreamPair) as u64,
    )
    .map_err(failure)?;
    let reader = Owned(pair.read);
    let writer = Channel(Owned(pair.write));
    platform::syscall::call2(
        platform::syscall::SyscallNumber::HandleOptionsSet,
        u64::from(reader.0),
        mnu_abi::HANDLE_OPTION_NONBLOCKING,
    )
    .map_err(failure)?;
    waits.begin_request_with_reply(
        service,
        peer,
        image,
        header,
        payload,
        attachments,
        writer,
        backend,
        |deadline| reply(sender, header.request_id, reader.0, deadline),
    )
}

fn reply(sender: u64, request_id: u64, reader: u32, deadline: u128) -> bool {
    let mut payload = [0; wire::REPLY_LEN];
    if wire::encode_reply(deadline, &mut payload).is_err() {
        return false;
    }
    let mut bytes = [0; protocol::HEADER_LEN + wire::REPLY_LEN];
    let header = protocol::Header {
        opcode: protocol::OP_STATUS,
        request_id,
        payload_len: payload.len() as u32,
        ..Default::default()
    };
    let Ok(length) = protocol::encode(header, &payload, &mut bytes) else {
        return false;
    };
    let mut handles = platform::ipc::IpcObjectHandles::default();
    handles.count = 1;
    handles.handles[0] = platform::ipc::IpcObjectHandle {
        handle: reader,
        reserved: 0,
        rights: wire::COMPLETION_RIGHTS,
    };
    platform::ipc::reply_object_handles(sender, &bytes[..length], &handles).is_ok()
}
