//! Userspace interval timers over aggregate native process execution metrics.
use super::*;
use protocol::interval_timer::{self, CpuClock, Value};

#[derive(Clone, Copy, Debug)]
pub(super) struct CpuTimer {
    schedule: timer_schedule::Schedule,
    previous: mnu_abi::ProcessExecutionUsage,
}

fn elapsed(usage: mnu_abi::ProcessExecutionUsage, clock: CpuClock) -> Result<u128, i32> {
    if usage.reserved != 0 || usage.ticks_per_second == 0 {
        return Err(protocol::STATUS_EIO);
    }
    let ticks = u128::from(usage.user_ticks)
        + match clock {
            CpuClock::Virtual => 0,
            CpuClock::Profile => u128::from(usage.kernel_ticks),
        };
    Ok(ticks * 1_000_000_000 / u128::from(usage.ticks_per_second))
}

impl CpuTimer {
    fn observe(
        mut self,
        usage: mnu_abi::ProcessExecutionUsage,
        clock: CpuClock,
    ) -> Result<(Self, Value, bool), i32> {
        if usage.ticks_per_second != self.previous.ticks_per_second
            || usage.user_ticks < self.previous.user_ticks
            || usage.kernel_ticks < self.previous.kernel_ticks
        {
            return Err(protocol::STATUS_EIO);
        }
        let now = elapsed(usage, clock)?;
        let (schedule, expirations) = self.schedule.observe(now);
        self.schedule = schedule;
        self.previous = usage;
        let remaining_ns =
            u64::try_from(self.schedule.remaining(now)).map_err(|_| STATUS_EOVERFLOW)?;
        let value = Value {
            interval_ns: self.schedule.interval() as u64,
            remaining_ns,
        };
        Ok((self, value, expirations != 0))
    }
}

impl<H: Copy> PosixService<H> {
    pub(super) fn has_cpu_timer_state(&self, owner: u64) -> bool {
        self.cpu_timers
            .range((owner, 1)..=(owner, 2))
            .next()
            .is_some()
    }

    pub fn has_cpu_timers(&self) -> bool {
        self.cpu_timers.iter().any(|(&(owner, _), timer)| {
            timer.schedule.deadline().is_some()
                && self
                    .process_wait_states
                    .get(&owner)
                    .is_some_and(|state| !state.exit_observed && state.termination_signal.is_none())
        })
    }

    fn store_cpu_timer(&mut self, owner: u64, clock: CpuClock, timer: CpuTimer) {
        let key = (owner, clock as u32);
        if timer.schedule.deadline().is_none() && timer.schedule.interval() == 0 {
            self.cpu_timers.remove(&key);
        } else {
            self.cpu_timers.insert(key, timer);
        }
    }

    fn observe_cpu_timer(
        &mut self,
        owner: u64,
        clock: CpuClock,
        usage: mnu_abi::ProcessExecutionUsage,
    ) -> Result<Value, i32> {
        let Some(timer) = self.cpu_timers.get(&(owner, clock as u32)).copied() else {
            return Ok(Value::default());
        };
        let (timer, value, due) = timer.observe(usage, clock)?;
        if due {
            self.enqueue_signal(
                owner,
                match clock {
                    CpuClock::Virtual => protocol::SIGNAL_VTALRM,
                    CpuClock::Profile => protocol::SIGNAL_PROF,
                },
            )?;
        }
        self.store_cpu_timer(owner, clock, timer);
        Ok(value)
    }

    /// Sample independently of client RPCs. A failed owner must not prevent
    /// observation of the others, or consume its own expiration state.
    pub fn expire_cpu_timers<P: ProcessBackend<H>>(
        &mut self,
        processes: &mut P,
    ) -> Result<usize, i32> {
        let mut owners: Vec<_> = self
            .cpu_timers
            .iter()
            .filter_map(|(&(owner, _), timer)| timer.schedule.deadline().is_some().then_some(owner))
            .collect();
        owners.dedup();
        let mut observed = 0;
        let mut failure = None;
        for owner in owners {
            let result =
                (|| {
                    let handle = *self.processes.get(&owner).ok_or(protocol::STATUS_ESRCH)?;
                    if self.process_wait_states.get(&owner).is_none_or(|state| {
                        state.exit_observed || state.termination_signal.is_some()
                    }) || matches!(processes.status(handle)?, ProcessLifecycle::Exited { .. })
                    {
                        return Ok(());
                    }
                    let usage = processes.execution_usage(handle)?;
                    elapsed(usage, CpuClock::Profile)?;
                    let mut first_error = None;
                    for clock in [CpuClock::Virtual, CpuClock::Profile] {
                        if let Err(error) = self.observe_cpu_timer(owner, clock, usage) {
                            first_error.get_or_insert(error);
                        }
                    }
                    if let Some(error) = first_error {
                        return Err(error);
                    }
                    observed += 1;
                    Ok(())
                })();
            if let Err(error) = result {
                failure.get_or_insert(error);
            }
        }
        failure.map_or(Ok(observed), Err)
    }

    /// Only IPC-authenticated `peer` selects an owner. No PID, FD or caller
    /// selected ProcessHandle is accepted in the timer request.
    pub fn handle_cpu_timer_request<P: ProcessBackend<H>>(
        &mut self,
        peer: PeerIdentity,
        header: protocol::Header,
        payload: &[u8],
        handles: &[AttachedObject<H>],
        processes: &mut P,
    ) -> ObjectResponse<H> {
        let result = (|| {
            if header.flags != 0 || header.status != 0 || !handles.is_empty() {
                return Err(STATUS_EINVAL);
            }
            let setting = match header.opcode {
                protocol::OP_CPU_TIMER_GET => false,
                protocol::OP_CPU_TIMER_SET => true,
                _ => return Err(protocol::STATUS_ENOSYS),
            };
            let clock = CpuClock::decode(payload.get(..4).ok_or(STATUS_EINVAL)?)
                .map_err(|_| STATUS_EINVAL)?;
            let replacement = if setting {
                Some(interval_timer::decode(&payload[4..]).map_err(|_| STATUS_EINVAL)?)
            } else {
                if payload.len() != 4 {
                    return Err(STATUS_EINVAL);
                }
                None
            };
            let owner = peer.process_id;
            if !self.sessions.contains_key(&owner)
                || self
                    .process_wait_states
                    .get(&owner)
                    .is_none_or(|state| state.exit_observed)
            {
                return Err(protocol::STATUS_ESRCH);
            }
            let handle = *self.processes.get(&owner).ok_or(protocol::STATUS_ESRCH)?;
            if matches!(processes.status(handle)?, ProcessLifecycle::Exited { .. }) {
                return Err(protocol::STATUS_ESRCH);
            }
            let usage = processes.execution_usage(handle)?;
            let now = elapsed(usage, clock)?;
            let replacement = replacement
                .map(|value| {
                    timer_schedule::Schedule::arm(
                        now,
                        u128::from(value.remaining_ns),
                        u128::from(value.interval_ns),
                        false,
                        u128::MAX,
                    )
                    .map_err(|_| STATUS_EOVERFLOW)
                })
                .transpose()?;
            let previous = self.observe_cpu_timer(owner, clock, usage)?;
            let mut output = vec![0; interval_timer::LEN];
            interval_timer::encode(previous, &mut output).map_err(|_| STATUS_EINVAL)?;
            if let Some(schedule) = replacement {
                self.store_cpu_timer(
                    owner,
                    clock,
                    CpuTimer {
                        schedule,
                        previous: usage,
                    },
                );
            }
            Ok(output)
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
            Err(error) => object_error(header.request_id, error),
        }
    }
}
