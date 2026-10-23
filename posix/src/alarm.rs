//! POSIX elapsed-time alarm policy, independent of native thread timers.
use super::*;

const SECOND: u64 = 1_000_000_000;

#[derive(Clone, Copy, Debug)]
pub(super) struct RealTimer {
    schedule: timer_schedule::Schedule,
}

impl RealTimer {
    fn value(self, now: u64) -> protocol::interval_timer::Value {
        protocol::interval_timer::Value {
            interval_ns: self.schedule.interval() as u64,
            remaining_ns: self.schedule.remaining(u128::from(now)) as u64,
        }
    }

    fn new(now: u64, value: protocol::interval_timer::Value) -> Result<Self, i32> {
        Ok(Self {
            schedule: timer_schedule::Schedule::arm(
                u128::from(now),
                u128::from(value.remaining_ns),
                u128::from(value.interval_ns),
                false,
                u128::from(mnu_abi::HANDLE_WAIT_INFINITE - 1),
            )
            .map_err(|_| STATUS_EOVERFLOW)?,
        })
    }

    fn after_expiration(self, now: u64) -> Self {
        Self {
            schedule: self.schedule.observe(u128::from(now)).0,
        }
    }
}

impl<H: Copy> PosixService<H> {
    /// Supply the reactor's native monotonic clock. Never use wall time:
    /// changing the civil clock must not change an outstanding alarm.
    pub fn with_monotonic_clock(mut self, clock: fn() -> Result<u64, i32>) -> Self {
        self.monotonic_clock = Some(clock);
        self
    }

    pub fn next_alarm_deadline(&self) -> Option<u64> {
        self.real_timers
            .values()
            .filter_map(|timer| timer.schedule.deadline().map(|end| end as u64))
            .min()
    }

    pub fn expire_alarms(&mut self) -> Result<usize, i32> {
        if self.next_alarm_deadline().is_none() {
            return Ok(0);
        }
        let now = self.monotonic_clock.ok_or(protocol::STATUS_EIO)?()?;
        self.expire_alarms_at(now)
    }

    fn expire_alarms_at(&mut self, now: u64) -> Result<usize, i32> {
        let due: Vec<_> = self
            .real_timers
            .iter()
            .filter_map(|(&owner, timer)| {
                timer
                    .schedule
                    .deadline()
                    .filter(|&deadline| deadline <= u128::from(now))
                    .map(|_| (owner, *timer))
            })
            .collect();
        let mut count = 0;
        for (owner, timer) in due {
            // Existing delivery handles ignored and blocked dispositions,
            // coalescing, provenance and native thread notification.
            self.enqueue_signal(owner, protocol::SIGNAL_ALRM)?;
            self.store_real_timer(owner, timer.after_expiration(now));
            count += 1;
        }
        Ok(count)
    }

    fn store_real_timer(&mut self, owner: u64, timer: RealTimer) {
        if timer.schedule.deadline().is_none() && timer.schedule.interval() == 0 {
            self.real_timers.remove(&owner);
        } else {
            self.real_timers.insert(owner, timer);
        }
    }

    fn timer_clock(&self, owner: u64) -> Result<u64, i32> {
        if !self.sessions.contains_key(&owner)
            || self
                .process_wait_states
                .get(&owner)
                .is_none_or(|state| state.exit_observed)
        {
            return Err(protocol::STATUS_ESRCH);
        }
        self.monotonic_clock.ok_or(protocol::STATUS_EIO)?()
    }

    pub(super) fn real_timer_payload(
        &mut self,
        owner: u64,
        replacement: Option<protocol::interval_timer::Value>,
    ) -> Result<Vec<u8>, i32> {
        let now = self.timer_clock(owner)?;
        // Reject unrepresentable replacement before expiring or changing state.
        let replacement = replacement
            .map(|value| RealTimer::new(now, value))
            .transpose()?;
        self.expire_alarms_at(now)?;
        let previous = self
            .real_timers
            .get(&owner)
            .map_or(protocol::interval_timer::Value::default(), |timer| {
                timer.value(now)
            });
        let mut output = vec![0; protocol::interval_timer::LEN];
        protocol::interval_timer::encode(previous, &mut output).map_err(|_| STATUS_EINVAL)?;
        if let Some(timer) = replacement {
            self.store_real_timer(owner, timer);
        }
        Ok(output)
    }

    pub(super) fn alarm_payload(&mut self, owner: u64, payload: &[u8]) -> Result<Vec<u8>, i32> {
        let seconds = u32::from_le_bytes(payload.try_into().map_err(|_| STATUS_EINVAL)?);
        let now = self.timer_clock(owner)?;
        let replacement = RealTimer::new(
            now,
            protocol::interval_timer::Value {
                interval_ns: 0,
                remaining_ns: u64::from(seconds) * SECOND,
            },
        )?;
        self.expire_alarms_at(now)?;
        let previous = self
            .real_timers
            .get(&owner)
            .map_or(0, |timer| timer.value(now).remaining_ns.div_ceil(SECOND));
        let previous = u32::try_from(previous).map_err(|_| STATUS_EOVERFLOW)?;
        let output = previous.to_le_bytes().to_vec();
        self.store_real_timer(owner, replacement);
        Ok(output)
    }
}
