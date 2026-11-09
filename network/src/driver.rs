use alloc::vec::Vec;
use mochi_user_platform as platform;
use mochios_net_device_protocol::{
    DeviceStatistics, HEADER_LEN, INTERFACE_INFO_LEN, InterfaceInfo, MAX_FRAME_LEN, Opcode,
    STATISTICS_LEN, STATUS_LEN, decode_frame, decode_interface_info, decode_statistics,
    decode_status, encode_empty, encode_frame,
};

const DRIVER_NAME: &str = "virtio-net.driver";
const REQUEST_MAX: usize = HEADER_LEN + 4 + MAX_FRAME_LEN;
pub(crate) struct DriverClient {
    thread: u64,
    peer: platform::execution_peer::MeasuredPeer,
    next_request: u64,
}

fn trusted_peer(thread: u64) -> Result<platform::execution_peer::MeasuredPeer, u64> {
    let peer = platform::execution_peer::capture(thread).map_err(|error| error.raw() as u64)?;
    let c = &peer.context;
    if c.provenance != 1
        || c.subject_key_id != [0; 32]
        || c.package_id.get(..c.package_id_len as usize) != Some(b"org.mochios.network.virtio-net")
        || c.developer_id.get(..c.developer_id_len as usize) != Some(b"org.mochios.system")
    {
        return Err(mochi_user_syscall::EACCES);
    }
    Ok(peer)
}
impl DriverClient {
    pub(crate) fn connect(deadline: u64) -> Result<Self, u64> {
        loop {
            match platform::process::find_by_name(DRIVER_NAME) {
                Ok(thread) if thread != 0 => {
                    let peer = trusted_peer(thread)?;
                    return Ok(Self {
                        thread,
                        peer,
                        next_request: 1,
                    });
                }
                Ok(_) | Err(_) => {}
            }
            let now = platform::time::ticks().map_err(|e| e.raw() as u64)?;
            if now >= deadline {
                return Err(mochi_user_syscall::EAGAIN);
            }
            platform::thread::yield_now()
        }
    }
    fn id(&mut self) -> u64 {
        let id = self.next_request;
        self.next_request = self.next_request.wrapping_add(1).max(1);
        id
    }
    fn call(&self, request: &[u8], reply: &mut [u8]) -> Result<usize, u64> {
        self.current()?;
        let result =
            platform::ipc::call(self.thread, request, reply).map_err(|e| e.raw() as u64)?;
        self.current()?;
        let len = (result & 0xffff_ffff) as usize;
        if result >> 32 != self.thread || len > reply.len() {
            Err(mochi_user_syscall::EIO)
        } else {
            Ok(len)
        }
    }
    fn current(&self) -> Result<(), u64> {
        let current = trusted_peer(self.thread)?;
        if current.image != self.peer.image
            || current.context != self.peer.context
            || !platform::handle::same_object(current.process.0, self.peer.process.0)
                .map_err(|error| error.raw() as u64)?
        {
            return Err(mochi_user_syscall::EACCES);
        }
        Ok(())
    }
    pub(crate) fn info(&mut self) -> Result<InterfaceInfo, u64> {
        let id = self.id();
        let mut request = [0; HEADER_LEN];
        encode_empty(Opcode::GetInterfaceInfo, id, &mut request)
            .map_err(|_| mochi_user_syscall::EINVAL)?;
        let mut reply = [0; INTERFACE_INFO_LEN];
        let n = self.call(&request, &mut reply)?;
        metadata_status(&reply[..n], Opcode::InterfaceInfo, id)?;
        let (reply_id, info) =
            decode_interface_info(&reply[..n]).map_err(|_| mochi_user_syscall::EIO)?;
        if reply_id != id {
            return Err(mochi_user_syscall::EIO);
        }
        Ok(info)
    }
    pub(crate) fn transmit(&mut self, frame: &[u8]) -> Result<(), u64> {
        let id = self.id();
        let mut request = [0; REQUEST_MAX];
        let n = encode_frame(Opcode::TransmitFrame, id, frame, &mut request)
            .map_err(|_| mochi_user_syscall::EINVAL)?;
        let mut reply = [0; STATUS_LEN];
        let r = self.call(&request[..n], &mut reply)?;
        let (reply_id, status) = decode_status(Opcode::TransmitComplete, &reply[..r])
            .map_err(|_| mochi_user_syscall::EIO)?;
        if reply_id != id {
            return Err(mochi_user_syscall::EIO);
        }
        crate::status::driver_result(status)
    }
    pub(crate) fn receive(&mut self) -> Result<Option<Vec<u8>>, u64> {
        let id = self.id();
        let mut request = [0; HEADER_LEN];
        encode_empty(Opcode::ReceiveFrame, id, &mut request)
            .map_err(|_| mochi_user_syscall::EINVAL)?;
        let mut reply = [0; REQUEST_MAX];
        let n = self.call(&request, &mut reply)?;
        if n == STATUS_LEN {
            let (reply_id, status) = decode_status(Opcode::FrameReceived, &reply[..n])
                .map_err(|_| mochi_user_syscall::EIO)?;
            if reply_id != id {
                return Err(mochi_user_syscall::EIO);
            }
            crate::status::receive_status(status)?;
            return Ok(None);
        }
        let (reply_id, frame) = decode_frame(Opcode::FrameReceived, &reply[..n])
            .map_err(|_| mochi_user_syscall::EIO)?;
        if reply_id != id {
            return Err(mochi_user_syscall::EIO);
        }
        Ok(Some(frame.to_vec()))
    }
    pub(crate) fn statistics(&mut self) -> Result<DeviceStatistics, u64> {
        let id = self.id();
        let mut request = [0; HEADER_LEN];
        encode_empty(Opcode::GetStatistics, id, &mut request)
            .map_err(|_| mochi_user_syscall::EINVAL)?;
        let mut reply = [0; STATISTICS_LEN];
        let n = self.call(&request, &mut reply)?;
        metadata_status(&reply[..n], Opcode::Statistics, id)?;
        let (reply_id, stats) = decode_statistics(Opcode::Statistics, &reply[..n])
            .map_err(|_| mochi_user_syscall::EIO)?;
        if reply_id != id {
            return Err(mochi_user_syscall::EIO);
        }
        Ok(stats)
    }
}

// Metadata success has a fixed larger frame. A status-only reply is a failure;
// zero/positive status, a wrong operation or another request ID is malformed.
fn metadata_status(bytes: &[u8], opcode: Opcode, id: u64) -> Result<(), u64> {
    if bytes.len() != STATUS_LEN {
        return Ok(());
    }
    let (reply_id, status) = decode_status(opcode, bytes).map_err(|_| mochi_user_syscall::EIO)?;
    if reply_id != id || status >= 0 || status == i32::MIN {
        return Err(mochi_user_syscall::EIO);
    }
    Err(status as i64 as u64)
}
