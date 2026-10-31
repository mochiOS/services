//! Borrow only the three objects explicitly attached to this launch request.
//! The server owns/cleans the references; no provider I/O occurs in this plan.
use mochi_user_platform as p;
use mochios_posix_client::ObjectHandleAttachment;
use mochios_posix_protocol as posix;

#[derive(Clone, Copy)]
pub(crate) struct Stdio {
    objects: [ObjectHandleAttachment<u32>; 3],
    metadata: [u64; 3],
}
impl Stdio {
    pub(crate) fn new(
        objects: &[p::ipc::IpcObjectHandle],
        metadata: [u64; 3],
    ) -> Result<Self, p::syscall::SysError> {
        let invalid = || p::syscall::SysError::from_raw(p::syscall::EINVAL as i64);
        let denied = || p::syscall::SysError::from_raw(p::syscall::EACCES as i64);
        let [first, second, third] = objects else {
            return Err(invalid());
        };
        let mut result = Self {
            objects: [ObjectHandleAttachment {
                handle: 0,
                rights: 0,
            }; 3],
            metadata,
        };
        for (index, object) in [first, second, third].iter().enumerate() {
            if object.handle == 0
                || object.reserved != 0
                || object.rights & !mnu_abi::HANDLE_RIGHT_ALL != 0
            {
                return Err(invalid());
            }
            let required = mnu_abi::HANDLE_RIGHT_WAIT
                | mnu_abi::HANDLE_RIGHT_DUPLICATE
                | mnu_abi::HANDLE_RIGHT_TRANSFER
                | if index == 0 {
                    mnu_abi::HANDLE_RIGHT_READ
                } else {
                    mnu_abi::HANDLE_RIGHT_WRITE
                };
            if object.rights & required != required {
                return Err(denied());
            }
            let mut decoded =
                posix::decode_inherited_fd_metadata(metadata[index]).ok_or_else(invalid)?;
            if posix::inherited_fd_kind_requires_handle(decoded.kind) != Some(true)
                || decoded.open_flags & 3 == 3
                || (index == 0 && !mochios_posix_client::fd::access_allows_read(decoded.open_flags))
                || (index != 0
                    && !mochios_posix_client::fd::access_allows_write(decoded.open_flags))
                || (mochios_posix_client::fd::access_allows_read(decoded.open_flags)
                    && object.rights & mnu_abi::HANDLE_RIGHT_READ == 0)
                || (mochios_posix_client::fd::access_allows_write(decoded.open_flags)
                    && object.rights & mnu_abi::HANDLE_RIGHT_WRITE == 0)
            {
                return Err(invalid());
            }
            // Explicit remapping to child stdio has dup2 semantics. Parent
            // CLOEXEC remains local and must not close the child's new FD.
            decoded.descriptor_flags = 0;
            result.metadata[index] =
                posix::encode_inherited_fd_metadata(decoded).ok_or_else(invalid)?;
            result.objects[index] = ObjectHandleAttachment {
                handle: object.handle,
                rights: object.rights,
            };
        }
        Ok(result)
    }

    pub(crate) fn handles(&self) -> [mnu_abi::process_create::HandleGrant; 3] {
        core::array::from_fn(|index| mnu_abi::process_create::HandleGrant {
            key: posix::fd_handle_key(index as i32).unwrap(),
            source: self.objects[index].handle,
            target: 0,
            rights: self.objects[index].rights,
        })
    }
    pub(crate) fn values(&self) -> [mnu_abi::process_create::Value; 4] {
        core::array::from_fn(|index| {
            if index == 0 {
                mnu_abi::process_create::Value {
                    key: posix::FD_TABLE_KEY,
                    value: posix::FD_TABLE_VERSION,
                }
            } else {
                mnu_abi::process_create::Value {
                    key: posix::fd_metadata_key(index as i32 - 1).unwrap(),
                    value: self.metadata[index - 1],
                }
            }
        })
    }
}
