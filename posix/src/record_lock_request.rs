//! Observe only an explicitly attached file outside POSIX state, then validate
//! the native request image before changing process-owned lock state.
use super::*;
use protocol::record_lock::{self as wire, Operation, Origin};

#[must_use = "finish must validate the image before applying lock policy"]
pub struct Pending<H> {
    request_id: u64,
    pub(super) result: Result<Observation<H>, i32>,
}

impl<H> Pending<H> {
    pub fn file_key(&self) -> Option<record_lock::FileKey> {
        self.result.as_ref().ok().map(|observed| observed.key)
    }
}

pub(super) struct Observation<H> {
    pub(super) file: AttachedObject<H>,
    pub(super) key: record_lock::FileKey,
    pub(super) request: wire::Request,
    pub(super) position: i64,
    pub(super) size: i64,
}

/// Incoming references remain owned by the IPC receive until finish explicitly
/// transfers one to the service's file-lifetime registry. No provider discovery
/// fallback is used: a terminal/device or foreign object is not a regular file.
pub fn inspect<H: Copy, F: FilesystemBackend<H>>(
    header: protocol::Header,
    payload: &[u8],
    handles: &[AttachedObject<H>],
    filesystem: &mut F,
    mut position: impl FnMut(AttachedObject<H>) -> Result<i64, i32>,
) -> Pending<H> {
    let result = (|| {
        if header.opcode != protocol::OP_RECORD_LOCK
            || header.flags != 0
            || header.status != 0
            || header.payload_len as usize != payload.len()
        {
            return Err(STATUS_EINVAL);
        }
        let request = wire::decode_request(payload).map_err(|_| STATUS_EINVAL)?;
        let [file] = handles else {
            return Err(STATUS_EINVAL);
        };
        let rights = wire::required_rights(request);
        if file.rights & rights != rights {
            return Err(-13);
        }
        // Metadata uses TRANSFER only, including write-only descriptions.
        let status = filesystem.fstat(AttachedObject {
            handle: file.handle,
            rights: mnu_abi::HANDLE_RIGHT_TRANSFER,
        })?;
        if status.mode & 0o170000 != 0o100000 {
            return Err(STATUS_EINVAL);
        }
        let position = if request.origin == Origin::Current {
            position(AttachedObject {
                handle: file.handle,
                rights: mnu_abi::HANDLE_RIGHT_SEEK,
            })?
        } else {
            0
        };
        Ok(Observation {
            file: *file,
            key: record_lock::FileKey {
                device: status.device,
                inode: status.inode,
            },
            request,
            position,
            size: status.size,
        })
    })();
    Pending {
        request_id: header.request_id,
        result,
    }
}

/// Returns the incoming reference taken into service ownership, if any. Every
/// other incoming reference must still be closed by the receive loop, even on
/// failed replies. Ownership transfer requires no DUPLICATE or CONTROL right.
pub fn finish<H: Copy, F: FilesystemBackend<H>>(
    service: &mut PosixService<H>,
    peer: PeerIdentity,
    pending: Pending<H>,
    image_validation: Result<(), i32>,
    filesystem: &mut F,
) -> (ObjectResponse<H>, Option<H>) {
    let result = (|| {
        image_validation?;
        let observed = pending.result?;
        // Confirm that lifecycle observation did not retire this owner while
        // the filesystem was answering. Do this before reserving or mutating.
        service.record_locks(peer)?;
        service.release_unused_record_lock_files(filesystem);
        let retain = matches!(observed.request.operation, Operation::Set(_))
            && !service
                .record_lock_files
                .iter()
                .any(|(key, _)| *key == observed.key);
        if retain {
            service.record_lock_files.try_reserve(1).map_err(|_| -37)?;
        }
        // Allocate the scalar reply before mutation. A successful lock cannot
        // be stranded merely because building its response ran out of memory.
        let mut payload = Vec::new();
        payload
            .try_reserve_exact(wire::REPLY_LEN)
            .map_err(|_| -12)?;
        payload.resize(wire::REPLY_LEN, 0);
        let reply = service.record_locks(peer)?.apply(
            observed.key,
            observed.request,
            observed.position,
            observed.size,
        )?;
        // The state machine emits only codec-valid replies. Encode before
        // handing over the incoming reference to keep ownership unambiguous.
        wire::encode_reply(reply, &mut payload).map_err(|_| protocol::STATUS_EIO)?;
        let retained = if retain {
            service
                .record_lock_files
                .push((observed.key, observed.file));
            Some(observed.file.handle)
        } else {
            None
        };
        service.release_unused_record_lock_files(filesystem);
        Ok((object_payload(pending.request_id, payload), retained))
    })();
    result.unwrap_or_else(|status| (object_error(pending.request_id, status), None))
}

impl<H: Copy> PosixService<H> {
    /// Local reference release only: no filesystem/provider RPC while holding
    /// POSIX state. Invoke after native exit observation, as well as unlock.
    /// Keeping one live reference per locked file prevents inode reuse until
    /// the final owner's lock has been retired, including unlinked files.
    pub fn release_unused_record_lock_files<F: FilesystemBackend<H>>(
        &mut self,
        filesystem: &mut F,
    ) {
        self.record_lock_files.retain(|(file, object)| {
            if self.record_locks.has_file(*file) || self.record_lock_waits.has_file(*file) {
                true
            } else {
                filesystem.release_object(*object);
                false
            }
        });
    }
}
