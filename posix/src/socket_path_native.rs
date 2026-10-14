//! Pathname binding uses authenticated session policy and retained directory
//! references. The socket worker never holds the policy mutex across FS IPC.

use mochi_user_platform as platform;
use mochios_filesystem_protocol as fs;
use mochios_posix_protocol::socket as wire;
use posix_service::{
    OpenedObject, PosixService,
    socket::Streams,
    socket_binding::{Bindings, Filesystem, NODE_RIGHTS},
};
use std::sync::{Arc, Mutex};

struct Snapshot {
    endpoint: u32,
    root: u32,
    cwd: Option<u32>,
    uid: u32,
    gid: u32,
    groups: [u32; fs::MAX_SUPPLEMENTARY_GROUPS],
    group_count: usize,
    mode: u32,
}
impl Drop for Snapshot {
    fn drop(&mut self) {
        let _ = platform::handle::close(self.root);
        if let Some(cwd) = self.cwd {
            let _ = platform::handle::close(cwd);
        }
    }
}
fn snapshot(
    state: &Arc<Mutex<PosixService<u32>>>,
    sender: u64,
    path: &[u8],
) -> Result<Snapshot, i32> {
    let identity =
        platform::ipc::endpoint_execution_identity(sender).map_err(|e| e.raw() as i32)?;
    let endpoint =
        platform::handle::inherited(fs::CONTROL_HANDLE_KEY).map_err(|e| e.raw() as i32)?;
    let state = state.lock().map_err(|_| -5)?;
    let peer = state.registered_peer(identity.process_id).ok_or(-1)?;
    let session = state.session(peer.process_id).ok_or(-1)?;
    let dirs = state.session_directories(peer.process_id).ok_or(-9)?;
    let groups = state.supplementary_groups(peer.process_id).unwrap_or(&[]);
    if groups.len() > fs::MAX_SUPPLEMENTARY_GROUPS {
        return Err(-22);
    }
    let mut copied_groups = [0; fs::MAX_SUPPLEMENTARY_GROUPS];
    copied_groups[..groups.len()].copy_from_slice(groups);
    let rights = mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_TRANSFER;
    if dirs.root.rights & rights != rights
        || (path.first() != Some(&b'/') && dirs.cwd.rights & rights != rights)
    {
        return Err(-13);
    }
    let root = platform::handle::duplicate(dirs.root.handle, rights).map_err(|e| e.raw() as i32)?;
    let mut snapshot = Snapshot {
        endpoint,
        root,
        cwd: None,
        uid: session.effective_uid,
        gid: session.effective_gid,
        groups: copied_groups,
        group_count: groups.len(),
        mode: 0o777 & !(session.umask & 0o777),
    };
    if path.first() != Some(&b'/') {
        snapshot.cwd =
            Some(platform::handle::duplicate(dirs.cwd.handle, rights).map_err(|e| e.raw() as i32)?);
    }
    Ok(snapshot)
}
fn close_received(handles: &platform::ipc::IpcObjectHandles) {
    for (index, attached) in handles
        .handles
        .iter()
        .take(handles.count as usize)
        .enumerate()
    {
        if attached.handle != 0
            && !handles.handles[..index]
                .iter()
                .any(|old| old.handle == attached.handle)
        {
            let _ = platform::handle::close(attached.handle);
        }
    }
}
impl Filesystem<u32> for Snapshot {
    fn create_socket(&mut self, path: &[u8]) -> Result<(OpenedObject<u32>, fs::NodeStatus), i32> {
        let mut request = [0; fs::HEADER_LEN + fs::CREDENTIALS_MAX_LEN + wire::MAX_UNIX_NAME_BYTES];
        let mut payload = [0; fs::CREDENTIALS_MAX_LEN + wire::MAX_UNIX_NAME_BYTES];
        let payload_len = fs::encode_credentials_payload(
            self.uid,
            self.gid,
            &self.groups[..self.group_count],
            path,
            &mut payload,
        )
        .map_err(|_| -22)?;
        let header = fs::Header {
            opcode: fs::OP_CREATE_SOCKET_AT,
            request_id: 1,
            length: payload_len as u32,
            mode: self.mode,
            flags: fs::SOCKET_AT_ROOT_ATTACHED
                | if self.cwd.is_some() {
                    fs::SOCKET_AT_BASE_ATTACHED
                } else {
                    0
                },
            ..Default::default()
        };
        let request_len =
            fs::encode(header, &payload[..payload_len], &mut request).map_err(|_| -22)?;
        let mut handles = platform::ipc::IpcObjectHandles::default();
        for handle in [Some(self.root), self.cwd].into_iter().flatten() {
            let slot = handles.count as usize;
            handles.handles[slot] = platform::ipc::IpcObjectHandle {
                handle,
                reserved: 0,
                rights: mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_TRANSFER,
            };
            handles.count += 1;
        }
        let mut response = [0; fs::HEADER_LEN + fs::NODE_STATUS_LEN];
        let received = posix_service::filesystem_transport::call_native(&mut handles, |native| {
            platform::ipc::call_object_handles(
                self.endpoint,
                &request[..request_len],
                &mut response,
                native,
            )
        })
        .map_err(|e| e.raw() as i32);
        let result = (|| {
            let length = received? as u32 as usize;
            let (reply, payload) = fs::decode(response.get(..length).ok_or(-5)?).map_err(|_| -5)?;
            if reply.opcode != fs::OP_STATUS || reply.request_id != 1 || handles.delivery_flags != 0
            {
                return Err(-5);
            }
            if reply.status != 0 {
                return Err(
                    if reply.status < 0 && handles.count == 0 && payload.is_empty() {
                        reply.status
                    } else {
                        -5
                    },
                );
            }
            if handles.count != 1
                || handles.handles[0].handle == 0
                || handles.handles[0].reserved != 0
                || handles.handles[0].rights != NODE_RIGHTS
                || reply.open_id == 0
            {
                return Err(-5);
            }
            let status = fs::decode_node_status(payload).map_err(|_| -5)?;
            if reply.node_id != status.node_id {
                return Err(-5);
            }
            Ok((
                OpenedObject {
                    handle: handles.handles[0].handle,
                    rights: handles.handles[0].rights,
                },
                status,
            ))
        })();
        if result.is_err() {
            close_received(&handles);
        }
        result
    }
    fn close(&mut self, handle: u32) {
        let _ = platform::handle::close(handle);
    }
}

pub fn control(
    streams: &mut Streams,
    bindings: &mut Bindings<u32>,
    state: &Arc<Mutex<PosixService<u32>>>,
    sender: u64,
    header: mnu_abi::provider::RequestHeader,
    payload: &[u8],
    response: &mut [u8],
) -> Result<usize, i32> {
    use mnu_abi::provider;
    if response.len() < provider::RESPONSE_HEADER_LEN + header.length as usize {
        return Err(-22);
    }
    let mut data = [0; wire::MAX_ADDRESS_LEN];
    let result = (|| {
        if header.basis == wire::CONTROL_BIND {
            if header.length != 0 {
                return Err(-22);
            }
            let wire::Address::UnixPath(path) = wire::Address::decode(payload).map_err(|_| -22)?
            else {
                return Err(-95);
            };
            let mut backend = snapshot(state, sender, path)?;
            bindings.bind_path(streams, header.object_id, path, &mut backend)?;
            Ok(0)
        } else if header.basis == wire::CONTROL_LISTEN {
            if header.length != 0
                || payload.len() != 4
                || bindings.retained_file(header.object_id).is_none()
            {
                return Err(-22);
            }
            let backlog = u32::from_le_bytes(payload.try_into().map_err(|_| -22)?);
            streams.listen(header.object_id, backlog)?;
            Ok(0)
        } else {
            if !payload.is_empty() {
                return Err(-22);
            }
            let path = bindings.address(header.object_id).ok_or(-9)?;
            let capacity = (header.length as usize).min(data.len());
            wire::Address::UnixPath(path)
                .encode(&mut data[..capacity])
                .map_err(|_| -22)
        }
    })();
    let (status, count) = match result {
        Ok(count) => (0, count),
        Err(error) => (i64::from(error), 0),
    };
    provider::ResponseHeader {
        opcode: header.opcode,
        object_id: header.object_id,
        status,
        value: count as u64,
        data_length: count as u32,
    }
    .encode(&data[..count], response)
    .map_err(|_| -5)
}
