//! POSIX wait interruption selected by an explicitly delegated ThreadHandle.
//! No self-reported PID/TID or application signal is needed.
use super::*;

pub struct Pending {
    request_id: u64,
    target: Result<mnu_abi::ExecutionIdentity, i32>,
}

/// Run native ThreadHandle status outside the POSIX state mutex. The incoming
/// reference is borrowed, never retained, and no discovery fallback is used.
pub fn inspect<H: Copy>(
    peer: PeerIdentity,
    header: protocol::Header,
    payload: &[u8],
    handles: &[AttachedObject<H>],
    mut status: impl FnMut(H) -> Result<mnu_abi::ThreadStatus, i32>,
) -> Pending {
    let target = (|| {
        if header.opcode != protocol::OP_THREAD_WAIT_INTERRUPT
            || header.flags != 0
            || header.status != 0
            || header.payload_len != 0
            || !payload.is_empty()
        {
            return Err(STATUS_EINVAL);
        }
        let [thread] = handles else {
            return Err(STATUS_EINVAL);
        };
        if thread.rights & protocol::THREAD_WAIT_INTERRUPT_RIGHTS
            != protocol::THREAD_WAIT_INTERRUPT_RIGHTS
        {
            return Err(-13);
        }
        let status = status(thread.handle)?;
        if status.process_id != peer.process_id || status.process_id == 0 || status.thread_id == 0 {
            return Err(protocol::STATUS_EPERM);
        }
        if status.reserved != 0
            || !(mnu_abi::THREAD_STATE_READY..=mnu_abi::THREAD_STATE_TERMINATED)
                .contains(&status.state)
        {
            return Err(protocol::STATUS_EIO);
        }
        if status.state == mnu_abi::THREAD_STATE_TERMINATED {
            return Err(protocol::STATUS_ESRCH);
        }
        Ok(mnu_abi::ExecutionIdentity {
            process_id: status.process_id,
            thread_id: status.thread_id,
        })
    })();
    Pending {
        request_id: header.request_id,
        target,
    }
}

pub fn finish<H: Copy>(
    service: &mut PosixService<H>,
    peer: PeerIdentity,
    pending: Pending,
    validation: Result<(), i32>,
) -> ObjectResponse<H> {
    let result = (|| {
        validation?;
        service.record_locks(peer)?;
        let target = pending.target?;
        if target.process_id != peer.process_id {
            return Err(protocol::STATUS_EPERM);
        }
        let key = (target.process_id, target.thread_id);
        let epoch = service
            .signal_delivery_epochs
            .get_mut(&key)
            .ok_or(protocol::STATUS_ESRCH)?;
        *epoch = epoch.checked_add(1).ok_or(STATUS_EOVERFLOW)?;
        Ok(())
    })();
    object_error(pending.request_id, result.err().unwrap_or(0))
}
