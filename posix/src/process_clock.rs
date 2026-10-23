//! POSIX visibility is decided here; native accounting reads only retained
//! objects provided by launch registration, never an arbitrary kernel PID.
use super::*;

impl<H: Copy> PosixService<H> {
    pub fn handle_process_clock<P: ProcessBackend<H>>(
        &self,
        peer: PeerIdentity,
        header: protocol::Header,
        payload: &[u8],
        attached: &[AttachedObject<H>],
        processes: &mut P,
    ) -> ObjectResponse<H> {
        let result = (|| {
            if header.opcode != protocol::OP_PROCESS_CPU_CLOCK
                || header.flags != 0
                || header.status != 0
                || !attached.is_empty()
            {
                return Err(STATUS_EINVAL);
            }
            let target = protocol::process_clock::target(payload).map_err(|_| STATUS_EINVAL)?;
            let target = if target == 0 { peer.process_id } else { target };
            let caller = self
                .sessions
                .get(&peer.process_id)
                .ok_or(protocol::STATUS_ESRCH)?;
            if !self.processes.contains_key(&peer.process_id) {
                return Err(protocol::STATUS_ESRCH);
            }
            let subject = self.sessions.get(&target).ok_or(protocol::STATUS_ESRCH)?;
            if peer.process_id != target
                && caller.effective_uid != 0
                && ![subject.real_uid, subject.effective_uid].contains(&caller.effective_uid)
                && ![subject.real_uid, subject.effective_uid].contains(&caller.real_uid)
            {
                return Err(protocol::STATUS_EPERM);
            }
            let handle = *self.processes.get(&target).ok_or(protocol::STATUS_ESRCH)?;
            if self
                .process_wait_states
                .get(&target)
                .is_some_and(|state| state.exit_observed)
                || matches!(processes.status(handle)?, ProcessLifecycle::Exited { .. })
            {
                return Err(protocol::STATUS_ESRCH);
            }
            let usage = processes.execution_usage(handle)?;
            if usage.ticks_per_second == 0 || usage.reserved != 0 {
                return Err(protocol::STATUS_EIO);
            }
            let sample = protocol::process_clock::Sample {
                process_id: target,
                user_ticks: usage.user_ticks,
                kernel_ticks: usage.kernel_ticks,
                ticks_per_second: usage.ticks_per_second,
            };
            let mut payload = vec![0; protocol::process_clock::SAMPLE_LEN];
            protocol::process_clock::encode(sample, &mut payload)
                .map_err(|_| protocol::STATUS_EIO)?;
            Ok(payload)
        })();
        match result {
            Ok(payload) => ObjectResponse {
                response: Response {
                    header: protocol::Header {
                        opcode: protocol::OP_STATUS,
                        request_id: header.request_id,
                        payload_len: payload.len() as u32,
                        ..Default::default()
                    },
                    payload,
                },
                handles: Vec::new(),
            },
            Err(status) => object_error(header.request_id, status),
        }
    }
}
