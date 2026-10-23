//! Deferred record-lock admission reuses the regular FileHandle observation.
//! No provider RPC or source-reference clone occurs under the policy lock.
use super::*;
use protocol::{record_lock as locks, record_lock_wait as wire};
use record_lock_wait::Completion;

#[must_use = "finish must validate the native image and signal epoch"]
pub struct Pending<H> {
    result: Result<(record_lock_request::Pending<H>, u64), i32>,
}

impl<H> Pending<H> {
    pub fn file_key(&self) -> Option<record_lock::FileKey> {
        self.result
            .as_ref()
            .ok()
            .and_then(|(file, _)| file.file_key())
    }
    pub fn epoch(&self) -> Option<u64> {
        self.result.as_ref().ok().map(|(_, epoch)| *epoch)
    }
}

pub fn inspect<H: Copy, F: FilesystemBackend<H>>(
    header: protocol::Header,
    payload: &[u8],
    handles: &[AttachedObject<H>],
    filesystem: &mut F,
    position: impl FnMut(AttachedObject<H>) -> Result<i64, i32>,
) -> Pending<H> {
    let result = (|| {
        if header.opcode != protocol::OP_RECORD_LOCK_WAIT
            || header.flags != 0
            || header.status != 0
            || header.payload_len as usize != payload.len()
        {
            return Err(STATUS_EINVAL);
        }
        let request = wire::decode(payload).map_err(|_| STATUS_EINVAL)?;
        let file = record_lock_request::inspect(
            protocol::Header {
                opcode: protocol::OP_RECORD_LOCK,
                payload_len: locks::REQUEST_LEN as u32,
                ..header
            },
            &payload[..locks::REQUEST_LEN],
            handles,
            filesystem,
            position,
        );
        Ok((file, request.epoch))
    })();
    Pending { result }
}

/// The caller must reserve its deferred-job slot and reply storage first.
/// On Pending/Replied, ownership of at most one received reference transfers
/// to the file pin registry. On error/Undelivered all received refs stay local.
pub fn finish<H: Copy, F: FilesystemBackend<H>>(
    service: &mut PosixService<H>,
    peer: PeerIdentity,
    identity: mnu_abi::ExecutionIdentity,
    pending: Pending<H>,
    validation: Result<(), i32>,
    filesystem: &mut F,
    reply: impl FnOnce() -> bool,
) -> (Result<Completion, i32>, Option<H>) {
    let result = (|| {
        validation?;
        let (file, epoch) = pending.result?;
        let observed = file.result?;
        service.validate_wait_delivery_epoch(peer, identity, epoch)?;
        let locks::Operation::Set(kind) = observed.request.operation else {
            return Err(STATUS_EINVAL);
        };
        let base = match observed.request.origin {
            locks::Origin::Start => 0,
            locks::Origin::Current => observed.position,
            locks::Origin::End => observed.size,
        };
        let range =
            record_lock::Range::normalize(base, observed.request.start, observed.request.length)
                .map_err(|error| match error {
                    record_lock::Error::Overflow => STATUS_EOVERFLOW,
                    _ => STATUS_EINVAL,
                })?;
        service.record_locks(peer)?;
        service.release_unused_record_lock_files(filesystem);
        let retain = !service
            .record_lock_files
            .iter()
            .any(|(key, _)| *key == observed.key);
        if retain {
            service.record_lock_files.try_reserve(1).map_err(|_| -37)?;
        }
        let completion =
            service.begin_record_lock_wait_with_reply(peer, observed.key, kind, range, reply)?;
        let retained = if retain && completion != Completion::Undelivered {
            service
                .record_lock_files
                .push((observed.key, observed.file));
            Some(observed.file.handle)
        } else {
            None
        };
        Ok((completion, retained))
    })();
    match result {
        Ok((completion, retained)) => (Ok(completion), retained),
        Err(error) => (Err(error), None),
    }
}
