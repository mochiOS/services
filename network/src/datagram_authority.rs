//! An explicit network authority can be delegated without impersonating its
//! original requester or lending the requester's entire CapabilitySet.
use alloc::vec::Vec;
use mnu_abi::provider;
use mochi_user_platform as platform;
use mochios_net_device_protocol::datagram_authority as wire;
const TAG: u64 = 1 << 60;
const LIMIT: usize = 64;
pub(crate) const RIGHTS: u64 = mnu_abi::HANDLE_RIGHT_CONTROL
    | mnu_abi::HANDLE_RIGHT_DUPLICATE
    | mnu_abi::HANDLE_RIGHT_TRANSFER;
pub(crate) struct Server {
    endpoint: Result<u32, mochi_user_syscall::SysError>,
    next: u64,
    live: Vec<u64>,
}
impl Server {
    pub(crate) fn new() -> Self {
        Self {
            endpoint: platform::ipc::create_handle(),
            next: 1,
            live: Vec::new(),
        }
    }
    /// Returns true only for this protocol/Provider namespace. All attachments
    /// remain owned by the caller, including malformed/denied requests.
    pub(crate) fn dispatch(
        &mut self,
        sender: u64,
        bytes: &[u8],
        handles: &platform::ipc::IpcObjectHandles,
    ) -> bool {
        if bytes.starts_with(b"NUDP") {
            let result = (|| {
                if bytes.len() != wire::ACQUIRE.len()
                    || bytes[4..6] != [1, 0]
                    || handles.count != 0
                    || !matches!(
                        handles.delivery_flags,
                        0 | mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE
                    )
                {
                    return Err(-22);
                }
                if bytes[6..8] != [1, 0] {
                    return Err(-38);
                }
                if platform::capability::check_thread(sender, "net.connect") != Ok(1) {
                    return Err(-13);
                }
                let endpoint = *self.endpoint.as_ref().map_err(|_| -5)?;
                if self.live.len() == LIMIT || self.next >= TAG {
                    return Err(-24);
                }
                self.live.try_reserve(1).map_err(|_| -12)?;
                let id = TAG | self.next;
                self.next += 1;
                let handle = platform::handle::create_provider_object(endpoint, id, RIGHTS)
                    .map_err(|_| -5)?;
                self.live.push(id);
                Ok((id, handle))
            })();
            let mut response = [0; wire::REPLY_LEN];
            match result {
                Ok((id, handle)) => {
                    let mut attached = platform::ipc::IpcObjectHandles::default();
                    attached.count = 1;
                    attached.handles[0] = platform::ipc::IpcObjectHandle {
                        handle,
                        reserved: 0,
                        rights: RIGHTS,
                    };
                    wire::reply(0, &mut response).unwrap();
                    if platform::ipc::reply_object_handles(sender, &response, &attached).is_err() {
                        self.live.retain(|value| *value != id);
                    }
                    let _ = platform::handle::close(handle);
                }
                Err(status) => {
                    wire::reply(status, &mut response).unwrap();
                    let _ = platform::ipc::reply(sender, &response);
                }
            }
            return true;
        }
        let Ok((header, input)) = provider::RequestHeader::decode(bytes) else {
            return false;
        };
        if header.object_id & TAG == 0 {
            return false;
        }
        let native =
            handles.delivery_flags == mnu_abi::IPC_DELIVERY_NATIVE_OBJECT && handles.count == 0;
        if native && header.opcode == provider::OP_RELEASE {
            self.live.retain(|id| *id != header.object_id);
            return true;
        }
        let mut data = [0; wire::LIMITS_LEN];
        let result = (|| {
            if !native {
                return Err(-13);
            }
            if !self.live.contains(&header.object_id) {
                return Err(-9);
            }
            if header.opcode != provider::OP_CONTROL || header.basis != wire::QUERY_LIMITS {
                return Err(-95);
            }
            if !input.is_empty() || header.length as usize != wire::LIMITS_LEN {
                return Err(-22);
            }
            wire::Limits {
                minimum_port: 1024,
                maximum_payload: 1472,
            }
            .encode(&mut data)
            .map_err(|_| -5)
        })();
        let (status, length) = match result {
            Ok(n) => (0, n),
            Err(status) => (status, 0),
        };
        let mut response = [0; provider::RESPONSE_HEADER_LEN + wire::LIMITS_LEN];
        let count = provider::ResponseHeader {
            opcode: header.opcode,
            status,
            object_id: header.object_id,
            value: length as u64,
            data_length: length as u32,
        }
        .encode(&data[..length], &mut response)
        .unwrap();
        let _ = platform::ipc::reply(sender, &response[..count]);
        true
    }
}
