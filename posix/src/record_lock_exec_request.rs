//! File observations never run under POSIX state. The runtime must revalidate
//! native request provenance before installing or extending a preparation.
use super::*;
use protocol::record_lock_exec as wire;

#[must_use = "finish must validate the native image before changing preparation state"]
pub struct Pending {
    request_id: u64,
    result: Result<(wire::Request, Vec<record_lock::FileKey>), i32>,
}

pub fn inspect<H: Copy, F: FilesystemBackend<H>>(
    header: protocol::Header,
    payload: &[u8],
    files: &[AttachedObject<H>],
    filesystem: &mut F,
) -> Pending {
    let result = (|| {
        if header.opcode != protocol::OP_RECORD_LOCK_EXEC
            || header.flags != 0
            || header.status != 0
            || header.payload_len as usize != payload.len()
        {
            return Err(STATUS_EINVAL);
        }
        let request = wire::decode(payload).map_err(|_| STATUS_EINVAL)?;
        match request {
            wire::Request::Prepare(_)
                if files.is_empty() || files.len() > mnu_abi::IPC_MAX_OBJECT_HANDLES =>
            {
                return Err(STATUS_EINVAL);
            }
            wire::Request::Cancel(_) if !files.is_empty() => return Err(STATUS_EINVAL),
            _ => {}
        }
        // Reject the entire envelope before making any filesystem call.
        if files
            .iter()
            .any(|file| file.rights & mnu_abi::HANDLE_RIGHT_TRANSFER == 0)
        {
            return Err(-13);
        }
        let mut keys = Vec::new();
        keys.try_reserve(files.len()).map_err(|_| -37)?;
        for file in files {
            let status = filesystem.fstat(AttachedObject {
                handle: file.handle,
                rights: mnu_abi::HANDLE_RIGHT_TRANSFER,
            })?;
            if status.mode & 0o170000 != 0o100000 {
                return Err(STATUS_EINVAL);
            }
            keys.push(record_lock::FileKey {
                device: status.device,
                inode: status.inode,
            });
        }
        Ok((request, keys))
    })();
    Pending {
        request_id: header.request_id,
        result,
    }
}

pub fn finish<H: Copy>(
    service: &mut PosixService<H>,
    peer: PeerIdentity,
    pending: Pending,
    image_validation: Result<(), i32>,
) -> ObjectResponse<H> {
    let result = (|| {
        image_validation?;
        let (request, files) = pending.result?;
        let mut payload = Vec::new();
        payload.try_reserve_exact(wire::LEN).map_err(|_| -37)?;
        payload.resize(wire::LEN, 0);
        let token = match request {
            wire::Request::Prepare(0) => service
                .prepare_record_lock_exec(peer, &files)?
                .map_or(0, record_lock_exec::Token::as_raw),
            wire::Request::Prepare(token) => {
                service.extend_record_lock_exec(
                    peer,
                    record_lock_exec::Token::from_raw(token).unwrap(),
                    &files,
                )?;
                token
            }
            wire::Request::Cancel(token) => {
                service.cancel_record_lock_exec(
                    peer,
                    record_lock_exec::Token::from_raw(token).unwrap(),
                )?;
                0
            }
        };
        wire::encode_reply(token, &mut payload).map_err(|_| protocol::STATUS_EIO)?;
        Ok(object_payload(pending.request_id, payload))
    })();
    result.unwrap_or_else(|status| object_error(pending.request_id, status))
}
