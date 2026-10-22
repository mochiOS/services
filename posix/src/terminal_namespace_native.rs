use mochi_user_platform as platform;
use mochios_filesystem_protocol as wire;
use posix_service::{
    OpenedObject,
    terminal_namespace::{self, Backend},
};

/// Process-lifetime authority for terminal node publication. The namespace
/// itself is owned by filesystem.service and outlives this open description.
pub(super) struct Directory {
    pub(super) object: OpenedObject<u32>,
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = platform::handle::close(self.object.handle);
    }
}

pub(super) fn prepare(filesystem: &super::RuntimeFilesystem) -> Result<Directory, i32> {
    struct Native<'a>(&'a super::RuntimeFilesystem);
    impl Backend for Native<'_> {
        fn open_directory(
            &mut self,
            path: &[u8],
            parent: Option<OpenedObject<u32>>,
        ) -> Result<OpenedObject<u32>, i32> {
            let payload = super::RuntimeFilesystem::credential_payload(0, 0, &[], path)?;
            let mut handles = platform::ipc::IpcObjectHandles::default();
            if let Some(parent) = parent {
                handles.count = 1;
                handles.handles[0] = mnu_abi::IpcObjectHandle {
                    handle: parent.handle,
                    reserved: 0,
                    rights: mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_TRANSFER,
                };
            }
            self.0.open_call(
                wire::Header {
                    opcode: wire::OP_OPEN_AT,
                    request_id: 70,
                    length: payload.len() as u32,
                    flags: wire::OPEN_AT_READ
                        | wire::OPEN_AT_DIRECTORY
                        | wire::OPEN_AT_NOFOLLOW
                        | if parent.is_some() {
                            wire::OPEN_AT_BASE_ATTACHED
                        } else {
                            0
                        },
                    ..Default::default()
                },
                &payload,
                handles,
            )
        }
        fn create_directory(&mut self, parent: OpenedObject<u32>, name: &[u8]) -> Result<(), i32> {
            let mut payload = vec![0; wire::device_namespace::HEADER_LEN + name.len()];
            let length = wire::device_namespace::encode(
                wire::OP_DEVICE_NODE_CREATE,
                wire::device_namespace::Request {
                    kind: wire::device_namespace::KIND_DIRECTORY,
                    mode: 0o755,
                    uid: 0,
                    gid: 0,
                    name,
                },
                &mut payload,
            )
            .map_err(|_| -22)?;
            let mut handles = platform::ipc::IpcObjectHandles::default();
            handles.count = 1;
            handles.handles[0] = mnu_abi::IpcObjectHandle {
                handle: parent.handle,
                reserved: 0,
                rights: mnu_abi::HANDLE_RIGHT_CONTROL | mnu_abi::HANDLE_RIGHT_TRANSFER,
            };
            let status = self.0.status_call(
                wire::Header {
                    opcode: wire::OP_DEVICE_NODE_CREATE,
                    request_id: 71,
                    length: length as u32,
                    ..Default::default()
                },
                &payload[..length],
                handles,
            )?;
            if status.kind != wire::NODE_TYPE_DIRECTORY {
                return Err(-20);
            }
            Ok(())
        }
        fn close(&mut self, handle: u32) {
            let _ = platform::handle::close(handle);
        }
    }
    terminal_namespace::prepare(&mut Native(filesystem)).map(|object| Directory { object })
}
