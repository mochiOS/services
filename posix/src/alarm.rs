//! POSIX elapsed-time alarm policy, independent of native thread timers.
use super::*;

const SECOND: u64 = 1_000_000_000;

impl<H: Copy> PosixService<H> {
    /// Supply the reactor's native monotonic clock. Never use wall time:
    /// changing the civil clock must not change an outstanding alarm.
    pub fn with_monotonic_clock(mut self, clock: fn() -> Result<u64, i32>) -> Self {
        self.monotonic_clock = Some(clock);
        self
    }

    pub fn next_alarm_deadline(&self) -> Option<u64> {
        self.alarm_deadlines.values().copied().min()
    }

    pub fn expire_alarms(&mut self) -> Result<usize, i32> {
        if self.alarm_deadlines.is_empty() {
            return Ok(0);
        }
        let now = self.monotonic_clock.ok_or(protocol::STATUS_EIO)?()?;
        self.expire_alarms_at(now)
    }

    fn expire_alarms_at(&mut self, now: u64) -> Result<usize, i32> {
        let due: Vec<_> = self
            .alarm_deadlines
            .iter()
            .filter_map(|(&owner, &deadline)| (deadline <= now).then_some(owner))
            .collect();
        let mut count = 0;
        for owner in due {
            // Existing delivery handles ignored and blocked dispositions,
            // coalescing, provenance and native thread notification.
            self.enqueue_signal(owner, protocol::SIGNAL_ALRM)?;
            self.alarm_deadlines.remove(&owner);
            count += 1;
        }
        Ok(count)
    }

    pub(super) fn alarm_payload(&mut self, owner: u64, payload: &[u8]) -> Result<Vec<u8>, i32> {
        let seconds = u32::from_le_bytes(payload.try_into().map_err(|_| STATUS_EINVAL)?);
        if !self.sessions.contains_key(&owner)
            || self
                .process_wait_states
                .get(&owner)
                .is_none_or(|state| state.exit_observed)
        {
            return Err(protocol::STATUS_ESRCH);
        }
        let now = self.monotonic_clock.ok_or(protocol::STATUS_EIO)?()?;
        let deadline = if seconds == 0 {
            None
        } else {
            Some(
                now.checked_add(u64::from(seconds) * SECOND)
                    // This value means "wait forever" to the native reactor,
                    // not a representable finite timer deadline.
                    .filter(|&end| end != mnu_abi::HANDLE_WAIT_INFINITE)
                    .ok_or(STATUS_EOVERFLOW)?,
            )
        };
        self.expire_alarms_at(now)?;
        let previous = self
            .alarm_deadlines
            .get(&owner)
            .map_or(0, |&end| end.saturating_sub(now).div_ceil(SECOND));
        let previous = u32::try_from(previous).map_err(|_| STATUS_EOVERFLOW)?;
        let output = previous.to_le_bytes().to_vec();
        if let Some(deadline) = deadline {
            self.alarm_deadlines.insert(owner, deadline);
        } else {
            self.alarm_deadlines.remove(&owner);
        }
        Ok(output)
    }
}
