//! Deferred reply endpoints, bounded before consuming any notification.
use super::RuntimeProcesses;
use mochi_user_platform as platform;
use mochios_posix_protocol as protocol;
use posix_service::timer_callback::Completion;
use posix_service::{AttachedObject, PeerIdentity, PosixService, RequestImage};

#[derive(Clone, Copy)]
struct Wait {
    sender: u64,
    peer: PeerIdentity,
    image: RequestImage,
    identity: mnu_abi::ExecutionIdentity,
    header: protocol::Header,
}

#[derive(Default)]
pub(super) struct Waits(Vec<Wait>);

impl Waits {
    pub(super) fn begin(
        &mut self,
        service: &mut PosixService<u32>,
        processes: &mut RuntimeProcesses,
        sender: u64,
        peer: PeerIdentity,
        image: RequestImage,
        header: protocol::Header,
        payload: &[u8],
        attachments: &[AttachedObject<u32>],
    ) -> Result<(), i32> {
        if header.flags != 0
            || header.status != 0
            || header.payload_len as usize != payload.len()
            || !attachments.is_empty()
        {
            return Err(posix_service::STATUS_EINVAL);
        }
        protocol::timer_callback::decode_request(payload)
            .map_err(|_| posix_service::STATUS_EINVAL)?;
        let identity = platform::ipc::endpoint_execution_identity(sender)
            .map_err(|_| protocol::STATUS_EPERM)?;
        if self.0.len() >= 1024
            || self
                .0
                .iter()
                .any(|wait| wait.peer.process_id == peer.process_id)
        {
            return Err(protocol::STATUS_EAGAIN);
        }
        self.0.try_reserve(1).map_err(|_| protocol::STATUS_ENOMEM)?;
        let wait = Wait {
            sender,
            peer,
            image,
            identity,
            header,
        };
        if poll(wait, service, processes)? == Completion::Pending {
            self.0.push(wait);
        }
        Ok(())
    }

    pub(super) fn observe(
        &mut self,
        service: &mut PosixService<u32>,
        processes: &mut RuntimeProcesses,
    ) {
        let mut index = 0;
        while index < self.0.len() {
            let wait = self.0[index];
            match poll(wait, service, processes) {
                Ok(Completion::Pending) => {
                    index += 1;
                    continue;
                }
                Err(status) => {
                    reply(wait, Err(status));
                }
                Ok(_) => {}
            }
            self.0.swap_remove(index);
        }
    }
}

fn poll(
    wait: Wait,
    service: &mut PosixService<u32>,
    processes: &mut RuntimeProcesses,
) -> Result<Completion, i32> {
    let identity = platform::ipc::endpoint_execution_identity(wait.sender)
        .map_err(|error| super::process_control::lifecycle_failure(error.raw()))?;
    if identity != wait.identity {
        return Err(protocol::STATUS_EPERM);
    }
    service.poll_timer_callback(
        wait.peer,
        wait.image,
        identity,
        wait.header,
        &protocol::timer_callback::REQUEST,
        &[],
        processes,
        |event| reply(wait, Ok(event)),
    )
}

fn reply(wait: Wait, event: Result<protocol::timer_callback::Event, i32>) -> bool {
    let mut payload = [0; protocol::timer_callback::REPLY_LEN];
    let (status, length) = match event {
        Ok(event) => {
            if protocol::timer_callback::encode(event, &mut payload).is_err() {
                return false;
            }
            (0, payload.len())
        }
        Err(status) => (status, 0),
    };
    let header = protocol::Header {
        opcode: protocol::OP_STATUS,
        request_id: wait.header.request_id,
        status,
        payload_len: length as u32,
        ..Default::default()
    };
    let mut bytes = [0; protocol::HEADER_LEN + protocol::timer_callback::REPLY_LEN];
    match protocol::encode(header, &payload[..length], &mut bytes) {
        Ok(count) => platform::ipc::reply(wait.sender, &bytes[..count]).is_ok(),
        Err(_) => false,
    }
}
