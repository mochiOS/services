#[cfg(target_os = "mochios")]
fn main() {
    use mochi_user_platform as platform;
    use mochios_filesystem_protocol as filesystem_protocol;
    use mochios_posix_protocol as protocol;
    use posix_service::{AttachedObject, PeerIdentity, PosixService};

    let _ = platform::logger::init_from_env();
    platform::logln!("posix.service: start");
    let Some(ready_target) = platform::service_ready::take_bootstrap_target() else {
        platform::logln!("posix.service: missing ready target");
        platform::process::exit(1);
    };
    let endpoint_handle = match platform::ipc::create_handle() {
        Ok(handle) => handle,
        Err(error) => {
            platform::logln!(
                "posix.service: endpoint handle creation failed errno={}",
                error.raw()
            );
            platform::process::exit(1);
        }
    };
    let delegated_rights = platform::handle::HANDLE_RIGHT_SEND
        | platform::handle::HANDLE_RIGHT_DUPLICATE
        | platform::handle::HANDLE_RIGHT_TRANSFER;
    if let Err(error) =
        platform::service_ready::notify_handle(ready_target, 0, endpoint_handle, delegated_rights)
    {
        platform::logln!(
            "posix.service: endpoint publication failed errno={}",
            error.raw()
        );
        platform::process::exit(1);
    }
    platform::logln!("posix.service: endpoint ready");

    let mut service = PosixService::new();
    let filesystem_endpoint =
        match platform::handle::inherited(filesystem_protocol::CONTROL_HANDLE_KEY) {
            Ok(endpoint) => endpoint,
            Err(error) => {
                platform::logln!(
                    "posix.service: missing filesystem endpoint errno={}",
                    error.raw()
                );
                platform::process::exit(1);
            }
        };
    let mut filesystem = RuntimeFilesystem {
        endpoint: filesystem_endpoint,
    };
    let mut request_bytes = vec![0u8; protocol::MAX_MESSAGE_LEN];
    let mut response_bytes = vec![0u8; protocol::MAX_MESSAGE_LEN];
    loop {
        let mut received_handles = platform::ipc::IpcObjectHandles::default();
        let message = match platform::ipc::wait_object_handles(
            endpoint_handle as u64,
            &mut request_bytes,
            &mut received_handles,
        ) {
            Ok(message) => message,
            Err(_) => {
                platform::thread::yield_now();
                continue;
            }
        };
        let sender = message >> 32;
        let length = (message & 0xffff_ffff) as usize;
        let attached_count = (received_handles.count as usize).min(received_handles.handles.len());
        let attachments_valid = attached_count == received_handles.count as usize
            && received_handles
                .handles
                .iter()
                .take(attached_count)
                .all(|attachment| attachment.handle != 0 && attachment.reserved == 0);
        let attachments: Vec<AttachedObject<u32>> = received_handles
            .handles
            .iter()
            .take(attached_count)
            .map(|attachment| AttachedObject {
                handle: attachment.handle,
                rights: attachment.rights,
            })
            .collect();
        let peer = platform::process::thread_security_context(sender)
            .ok()
            .map(|context| PeerIdentity {
                process_id: context.process_id,
                effective_uid: context.effective_uid,
                effective_gid: context.effective_gid,
            });
        let decoded = request_bytes
            .get(..length)
            .and_then(|bytes| protocol::decode(bytes).ok());
        let object_response = match (peer, decoded, attachments_valid) {
            (Some(peer), Some((header, payload)), true) => {
                service.handle_objects(peer, header, payload, &attachments, &mut filesystem)
            }
            (_, Some((header, _)), _) => posix_service::ObjectResponse {
                response: invalid_response(header.request_id),
                handles: Vec::new(),
            },
            _ => posix_service::ObjectResponse {
                response: invalid_response(0),
                handles: Vec::new(),
            },
        };
        for attachment in received_handles.handles.iter().take(attached_count) {
            let _ = platform::handle::close(attachment.handle);
        }
        if let Ok(response_len) = protocol::encode(
            object_response.response.header,
            &object_response.response.payload,
            &mut response_bytes,
        ) {
            if object_response.handles.is_empty() {
                let _ = platform::ipc::reply(sender, &response_bytes[..response_len]);
            } else {
                let mut outgoing = platform::ipc::IpcObjectHandles::default();
                outgoing.count = object_response.handles.len() as u32;
                for (slot, opened) in outgoing
                    .handles
                    .iter_mut()
                    .zip(object_response.handles.iter())
                {
                    *slot = platform::ipc::IpcObjectHandle {
                        handle: opened.handle,
                        reserved: 0,
                        rights: opened.rights,
                    };
                }
                let _ = platform::ipc::reply_object_handles(
                    sender,
                    &response_bytes[..response_len],
                    &outgoing,
                );
            }
        }
        for opened in object_response.handles {
            let _ = platform::handle::close(opened.handle);
        }
    }
}

#[cfg(target_os = "mochios")]
fn invalid_response(request_id: u64) -> posix_service::Response {
    posix_service::Response {
        header: mochios_posix_protocol::Header {
            opcode: mochios_posix_protocol::OP_STATUS,
            request_id,
            status: posix_service::STATUS_EINVAL,
            ..mochios_posix_protocol::Header::default()
        },
        payload: Vec::new(),
    }
}

#[cfg(target_os = "mochios")]
struct RuntimeFilesystem {
    endpoint: mochi_user_platform::handle::Handle,
}

#[cfg(target_os = "mochios")]
impl RuntimeFilesystem {
    fn empty_call(
        &self,
        header: mochios_filesystem_protocol::Header,
        payload: &[u8],
        mut handles: mochi_user_platform::ipc::IpcObjectHandles,
    ) -> Result<(), i32> {
        use mochi_user_platform as platform;
        use mochios_filesystem_protocol as filesystem;

        let mut request = vec![0u8; filesystem::HEADER_LEN + payload.len()];
        let request_len = filesystem::encode(header, payload, &mut request).map_err(|_| -22)?;
        let mut response = [0u8; filesystem::HEADER_LEN];
        if platform::ipc::call_object_handles(
            self.endpoint,
            &request[..request_len],
            &mut response,
            &mut handles,
        )
        .is_err()
        {
            close_runtime_handles(&handles);
            return Err(-5);
        }
        let (response, payload) = match filesystem::decode(&response) {
            Ok(decoded) => decoded,
            Err(_) => {
                close_runtime_handles(&handles);
                return Err(-5);
            }
        };
        if handles.count != 0 {
            close_runtime_handles(&handles);
            return Err(-5);
        }
        if response.opcode != filesystem::OP_STATUS || !payload.is_empty() || response.status != 0 {
            return Err(if response.status < 0 {
                response.status
            } else {
                -5
            });
        }
        Ok(())
    }

    fn status_call(
        &self,
        header: mochios_filesystem_protocol::Header,
        payload: &[u8],
        mut handles: mochi_user_platform::ipc::IpcObjectHandles,
    ) -> Result<mochios_filesystem_protocol::NodeStatus, i32> {
        use mochi_user_platform as platform;
        use mochios_filesystem_protocol as filesystem;

        let mut request = vec![0u8; filesystem::HEADER_LEN + payload.len()];
        let request_len = filesystem::encode(header, payload, &mut request).map_err(|_| -22)?;
        let mut response = vec![0u8; filesystem::HEADER_LEN + filesystem::NODE_STATUS_LEN];
        if platform::ipc::call_object_handles(
            self.endpoint,
            &request[..request_len],
            &mut response,
            &mut handles,
        )
        .is_err()
        {
            close_runtime_handles(&handles);
            return Err(-5);
        }
        let (response, payload) = match filesystem::decode(&response) {
            Ok(decoded) => decoded,
            Err(_) => {
                close_runtime_handles(&handles);
                return Err(-5);
            }
        };
        if handles.count != 0 {
            close_runtime_handles(&handles);
            return Err(-5);
        }
        if response.opcode != filesystem::OP_STATUS || response.status != 0 {
            return Err(if response.status < 0 {
                response.status
            } else {
                -5
            });
        }
        filesystem::decode_node_status(payload).map_err(|_| -5)
    }

    fn open_call(
        &self,
        header: mochios_filesystem_protocol::Header,
        path: &[u8],
        mut handles: mochi_user_platform::ipc::IpcObjectHandles,
    ) -> Result<posix_service::OpenedObject<mochi_user_platform::handle::Handle>, i32> {
        use mochi_user_platform as platform;
        use mochios_filesystem_protocol as filesystem;

        let mut request = vec![0u8; filesystem::HEADER_LEN + path.len()];
        let request_len = filesystem::encode(header, path, &mut request).map_err(|_| -22)?;
        let mut reply = vec![0u8; filesystem::HEADER_LEN];
        if platform::ipc::call_object_handles(
            self.endpoint,
            &request[..request_len],
            &mut reply,
            &mut handles,
        )
        .is_err()
        {
            close_runtime_handles(&handles);
            return Err(-5);
        }
        let (response, payload) = match filesystem::decode(&reply) {
            Ok(decoded) => decoded,
            Err(_) => {
                close_runtime_handles(&handles);
                return Err(-5);
            }
        };
        if response.opcode != filesystem::OP_STATUS || !payload.is_empty() || response.status != 0 {
            close_runtime_handles(&handles);
            return Err(if response.status < 0 {
                response.status
            } else {
                -5
            });
        }
        if handles.count != 1 || handles.handles[0].reserved != 0 {
            close_runtime_handles(&handles);
            return Err(-5);
        }
        let opened = handles.handles[0];
        Ok(posix_service::OpenedObject {
            handle: opened.handle,
            rights: opened.rights,
        })
    }

    fn path_handles(
        paths: posix_service::PathObjects<mochi_user_platform::handle::Handle>,
    ) -> Result<mochi_user_platform::ipc::IpcObjectHandles, i32> {
        use mochi_user_platform as platform;

        let required =
            platform::handle::HANDLE_RIGHT_READ | platform::handle::HANDLE_RIGHT_TRANSFER;
        let mut handles = platform::ipc::IpcObjectHandles::default();
        for object in [Some(paths.root), paths.base].into_iter().flatten() {
            if object.rights & required != required {
                return Err(-13);
            }
            let index = handles.count as usize;
            handles.handles[index] = platform::ipc::IpcObjectHandle {
                handle: object.handle,
                reserved: 0,
                rights: required,
            };
            handles.count += 1;
        }
        Ok(handles)
    }
}

#[cfg(target_os = "mochios")]
impl posix_service::FilesystemBackend<mochi_user_platform::handle::Handle> for RuntimeFilesystem {
    fn open_session_root(
        &mut self,
        effective_uid: u32,
        effective_gid: u32,
    ) -> Result<posix_service::SessionDirectories<mochi_user_platform::handle::Handle>, i32> {
        use mochi_user_platform as platform;
        use mochios_filesystem_protocol as filesystem;

        let open_root = || {
            self.open_call(
                filesystem::Header {
                    opcode: filesystem::OP_OPEN_AT,
                    request_id: 1,
                    offset: u64::from(effective_uid) | (u64::from(effective_gid) << 32),
                    length: 1,
                    flags: filesystem::OPEN_AT_READ | filesystem::OPEN_AT_DIRECTORY,
                    ..filesystem::Header::default()
                },
                b"/",
                platform::ipc::IpcObjectHandles::default(),
            )
        };
        let root = open_root()?;
        let cwd = match open_root() {
            Ok(cwd) => cwd,
            Err(status) => {
                let _ = platform::handle::close(root.handle);
                return Err(status);
            }
        };
        Ok(posix_service::SessionDirectories {
            root: posix_service::AttachedObject {
                handle: root.handle,
                rights: root.rights,
            },
            cwd: posix_service::AttachedObject {
                handle: cwd.handle,
                rights: cwd.rights,
            },
        })
    }

    fn open_at(
        &mut self,
        request: &posix_service::PreparedOpen,
        paths: posix_service::PathObjects<mochi_user_platform::handle::Handle>,
    ) -> Result<posix_service::OpenedObject<mochi_user_platform::handle::Handle>, i32> {
        use mochios_filesystem_protocol as filesystem;
        use mochios_posix_protocol as posix;

        let mut flags = filesystem::OPEN_AT_ROOT_ATTACHED;
        if paths.base.is_some() {
            flags |= filesystem::OPEN_AT_BASE_ATTACHED;
        }
        for (source, target) in [
            (posix::OPEN_READ, filesystem::OPEN_AT_READ),
            (posix::OPEN_WRITE, filesystem::OPEN_AT_WRITE),
            (posix::OPEN_CREATE, filesystem::OPEN_AT_CREATE),
            (posix::OPEN_EXCLUSIVE, filesystem::OPEN_AT_EXCLUSIVE),
            (posix::OPEN_TRUNCATE, filesystem::OPEN_AT_TRUNCATE),
            (posix::OPEN_APPEND, filesystem::OPEN_AT_APPEND),
            (posix::OPEN_DIRECTORY, filesystem::OPEN_AT_DIRECTORY),
            (posix::OPEN_NOFOLLOW, filesystem::OPEN_AT_NOFOLLOW),
        ] {
            if request.options & source != 0 {
                flags |= target;
            }
        }
        let header = filesystem::Header {
            opcode: filesystem::OP_OPEN_AT,
            request_id: 1,
            offset: u64::from(request.effective_uid) | (u64::from(request.effective_gid) << 32),
            length: request.path.len() as u32,
            flags,
            mode: request.mode,
            ..filesystem::Header::default()
        };
        let handles = Self::path_handles(paths)?;
        self.open_call(header, request.path.as_bytes(), handles)
    }

    fn stat_at(
        &mut self,
        request: &posix_service::PreparedStat,
        paths: posix_service::PathObjects<mochi_user_platform::handle::Handle>,
    ) -> Result<mochios_posix_protocol::FileStatus, i32> {
        use mochios_filesystem_protocol as filesystem;
        use mochios_posix_protocol as posix;
        let mut flags = filesystem::STAT_AT_ROOT_ATTACHED;
        if paths.base.is_some() {
            flags |= filesystem::STAT_AT_BASE_ATTACHED;
        }
        if request.flags & posix::STAT_NOFOLLOW != 0 {
            flags |= filesystem::STAT_AT_NOFOLLOW;
        }
        let handles = Self::path_handles(paths)?;
        let status = self.status_call(
            filesystem::Header {
                opcode: filesystem::OP_STAT_AT,
                request_id: 2,
                offset: u64::from(request.effective_uid) | (u64::from(request.effective_gid) << 32),
                length: request.path.len() as u32,
                flags,
                ..filesystem::Header::default()
            },
            request.path.as_bytes(),
            handles,
        )?;
        filesystem_status_to_posix(status)
    }

    fn fstat(
        &mut self,
        file: posix_service::AttachedObject<mochi_user_platform::handle::Handle>,
    ) -> Result<mochios_posix_protocol::FileStatus, i32> {
        use mochi_user_platform as platform;
        use mochios_filesystem_protocol as filesystem;

        if file.rights & platform::handle::HANDLE_RIGHT_TRANSFER == 0 {
            return Err(-13);
        }
        let mut handles = platform::ipc::IpcObjectHandles::default();
        handles.count = 1;
        handles.handles[0] = platform::ipc::IpcObjectHandle {
            handle: file.handle,
            reserved: 0,
            rights: platform::handle::HANDLE_RIGHT_TRANSFER,
        };
        let status = self.status_call(
            filesystem::Header {
                opcode: filesystem::OP_STAT_HANDLE,
                request_id: 3,
                ..filesystem::Header::default()
            },
            &[],
            handles,
        )?;
        filesystem_status_to_posix(status)
    }

    fn access_at(
        &mut self,
        request: &posix_service::PreparedAccess,
        paths: posix_service::PathObjects<mochi_user_platform::handle::Handle>,
    ) -> Result<(), i32> {
        use mochios_filesystem_protocol as filesystem;
        use mochios_posix_protocol as posix;
        let mut flags = filesystem::ACCESS_AT_ROOT_ATTACHED;
        if paths.base.is_some() {
            flags |= filesystem::ACCESS_AT_BASE_ATTACHED;
        }
        for (source, target) in [
            (posix::ACCESS_READ, filesystem::ACCESS_AT_READ),
            (posix::ACCESS_WRITE, filesystem::ACCESS_AT_WRITE),
            (posix::ACCESS_EXECUTE, filesystem::ACCESS_AT_EXECUTE),
        ] {
            if request.modes & source != 0 {
                flags |= target;
            }
        }
        if request.flags & posix::ACCESS_NOFOLLOW != 0 {
            flags |= filesystem::ACCESS_AT_NOFOLLOW;
        }
        let handles = Self::path_handles(paths)?;
        self.empty_call(
            filesystem::Header {
                opcode: filesystem::OP_ACCESS_AT,
                request_id: 4,
                offset: u64::from(request.uid) | (u64::from(request.gid) << 32),
                length: request.path.len() as u32,
                flags,
                ..filesystem::Header::default()
            },
            request.path.as_bytes(),
            handles,
        )
    }

    fn retain_object(
        &mut self,
        object: posix_service::AttachedObject<mochi_user_platform::handle::Handle>,
    ) -> Result<posix_service::AttachedObject<mochi_user_platform::handle::Handle>, i32> {
        use mochi_user_platform as platform;

        if object.rights & platform::handle::HANDLE_RIGHT_DUPLICATE == 0 {
            return Err(-13);
        }
        let handle = platform::handle::duplicate(object.handle, object.rights).map_err(|error| {
            -(i32::try_from(error.raw().unsigned_abs()).unwrap_or(i32::MAX))
        })?;
        Ok(posix_service::AttachedObject {
            handle,
            rights: object.rights,
        })
    }

    fn release_object(
        &mut self,
        object: posix_service::AttachedObject<mochi_user_platform::handle::Handle>,
    ) {
        let _ = mochi_user_platform::handle::close(object.handle);
    }

    fn directory_path(
        &mut self,
        root: posix_service::AttachedObject<mochi_user_platform::handle::Handle>,
        directory: posix_service::AttachedObject<mochi_user_platform::handle::Handle>,
    ) -> Result<Vec<u8>, i32> {
        use mochi_user_platform as platform;
        use mochios_filesystem_protocol as filesystem;

        let header = filesystem::Header {
            opcode: filesystem::OP_PATH_HANDLE,
            request_id: 5,
            ..filesystem::Header::default()
        };
        let mut request = [0u8; filesystem::HEADER_LEN];
        let request_len = filesystem::encode(header, &[], &mut request).map_err(|_| -22)?;
        let mut response = vec![0u8; filesystem::MAX_MESSAGE_LEN];
        let mut handles = Self::path_handles(posix_service::PathObjects {
            root,
            base: Some(directory),
        })?;
        let received = match platform::ipc::call_object_handles(
            self.endpoint,
            &request[..request_len],
            &mut response,
            &mut handles,
        ) {
            Ok(received) => received,
            Err(_) => {
                close_runtime_handles(&handles);
                return Err(-5);
            }
        };
        close_runtime_handles(&handles);
        let length = (received & 0xffff_ffff) as usize;
        let bytes = response.get(..length).ok_or(-5)?;
        let (response, payload) = filesystem::decode(bytes).map_err(|_| -5)?;
        if response.opcode != filesystem::OP_STATUS || response.status != 0 {
            return Err(if response.status == 0 { -5 } else { response.status });
        }
        Ok(payload.to_vec())
    }
}

#[cfg(target_os = "mochios")]
fn filesystem_status_to_posix(
    status: mochios_filesystem_protocol::NodeStatus,
) -> Result<mochios_posix_protocol::FileStatus, i32> {
    use mochios_filesystem_protocol as filesystem;

    let file_type = match status.kind {
        filesystem::NODE_TYPE_REGULAR => 0o100000,
        filesystem::NODE_TYPE_DIRECTORY => 0o040000,
        filesystem::NODE_TYPE_SYMLINK => 0o120000,
        filesystem::NODE_TYPE_SPECIAL => 0o020000,
        _ => return Err(-5),
    };
    Ok(mochios_posix_protocol::FileStatus {
        device: status.device,
        inode: status.node_id,
        mode: file_type | (status.mode & 0o7777),
        link_count: status.link_count,
        uid: status.uid,
        gid: status.gid,
        special_device: status.special_device,
        size: i64::try_from(status.size).map_err(|_| -75)?,
        block_size: i64::from(status.block_size),
        blocks: i64::try_from(status.blocks).map_err(|_| -75)?,
        access_time_seconds: i64::try_from(status.access_time_seconds).map_err(|_| -75)?,
        access_time_nanoseconds: i64::from(status.access_time_nanoseconds),
        modification_time_seconds: i64::try_from(status.modification_time_seconds)
            .map_err(|_| -75)?,
        modification_time_nanoseconds: i64::from(status.modification_time_nanoseconds),
        change_time_seconds: i64::try_from(status.change_time_seconds).map_err(|_| -75)?,
        change_time_nanoseconds: i64::from(status.change_time_nanoseconds),
    })
}

#[cfg(target_os = "mochios")]
fn close_runtime_handles(handles: &mochi_user_platform::ipc::IpcObjectHandles) {
    for handle in handles.handles.iter().take(handles.count as usize) {
        let _ = mochi_user_platform::handle::close(handle.handle);
    }
}

#[cfg(not(target_os = "mochios"))]
fn main() {}
