//! CPU-budget policy over retained native process objects, never wall time.
use super::*;

pub const SWEEP_INTERVAL_MS: u64 = 100;
const SECOND: u128 = 1_000_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    None,
    Notify { cpu_nanoseconds: u128 },
    Terminate,
}

pub fn observe(
    usage: mnu_abi::ProcessExecutionUsage,
    limit: protocol::ResourceLimit,
    last_notification: Option<u128>,
) -> Result<Action, i32> {
    if usage.reserved != 0 || usage.ticks_per_second == 0 {
        return Err(protocol::STATUS_EIO);
    }
    if limit.soft > limit.hard {
        return Err(STATUS_EINVAL);
    }
    let ticks = u128::from(usage.user_ticks) + u128::from(usage.kernel_ticks);
    let rate = u128::from(usage.ticks_per_second);
    if limit.hard != protocol::RLIM_INFINITY && ticks > u128::from(limit.hard) * rate {
        return Ok(Action::Terminate);
    }
    if limit.soft == protocol::RLIM_INFINITY || ticks <= u128::from(limit.soft) * rate {
        return Ok(Action::None);
    }
    // u64 user+kernel ticks times 1e9 fits u128, even at rate 1. Repeats
    // require one additional CPU second since the actual notification, not
    // merely entry into a new rounded wall/CPU-second bucket.
    let cpu_nanoseconds = ticks * SECOND / rate;
    if last_notification.is_some_and(|last| cpu_nanoseconds.saturating_sub(last) < SECOND) {
        return Ok(Action::None);
    }
    Ok(Action::Notify { cpu_nanoseconds })
}

impl<H: Copy> PosixService<H> {
    fn cpu_limit_candidates(&self) -> impl Iterator<Item = (u64, H, protocol::ResourceLimit)> + '_ {
        self.resource_limits
            .iter()
            .filter_map(|(&(owner, resource), &limit)| {
                if resource != protocol::RLIMIT_CPU || limit.soft == protocol::RLIM_INFINITY {
                    return None;
                }
                let state = self.process_wait_states.get(&owner)?;
                if state.exit_observed || state.termination_signal.is_some() {
                    return None;
                }
                Some((owner, *self.processes.get(&owner)?, limit))
            })
    }

    pub fn has_finite_cpu_limits(&self) -> bool {
        self.cpu_limit_candidates().next().is_some()
    }

    /// Called by the reactor even when clients make no RPCs. A bad sample
    /// does not disable enforcement for another process, nor consume a notice.
    pub fn enforce_cpu_limits<P: ProcessBackend<H>>(
        &mut self,
        processes: &mut P,
    ) -> Result<usize, i32> {
        let candidates: Vec<_> = self.cpu_limit_candidates().collect();
        let mut actions = 0;
        let mut failure = None;
        for (owner, handle, limit) in candidates {
            let result = (|| {
                if matches!(processes.status(handle)?, ProcessLifecycle::Exited { .. }) {
                    return Ok(false);
                }
                let usage = processes.execution_usage(handle)?;
                match observe(usage, limit, self.cpu_notifications.get(&owner).copied())? {
                    Action::None => Ok(false),
                    Action::Notify { cpu_nanoseconds } => {
                        self.enqueue_signal(owner, protocol::SIGNAL_XCPU)?;
                        self.cpu_notifications.insert(owner, cpu_nanoseconds);
                        Ok(true)
                    }
                    Action::Terminate => {
                        // SIGKILL cannot depend on the target running a handler
                        // or returning to libc. Record wait semantics only
                        // after native termination has actually succeeded.
                        processes.terminate(handle, u64::from(128 + protocol::SIGNAL_KILL))?;
                        self.process_wait_states
                            .get_mut(&owner)
                            .unwrap()
                            .termination_signal = Some(protocol::SIGNAL_KILL);
                        Ok(true)
                    }
                }
            })();
            match result {
                Ok(changed) => actions += usize::from(changed),
                Err(error) => {
                    failure.get_or_insert(error);
                }
            }
        }
        failure.map_or(Ok(actions), Err)
    }
}
