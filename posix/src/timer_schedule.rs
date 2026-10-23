//! Userspace timer arithmetic. Clock selection and notification policy belong
//! to the caller; no native wait sentinel or kernel timer semantics enter here.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Schedule {
    deadline: Option<u128>,
    interval: u128,
    ceiling: u128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Overflow;

impl Schedule {
    /// Zero initial time disarms in either mode, retaining the interval.
    /// The caller selects a finite clock range, excluding any native sentinel.
    pub(super) fn arm(
        now: u128,
        initial: u128,
        interval: u128,
        absolute: bool,
        ceiling: u128,
    ) -> Result<Self, Overflow> {
        let deadline = if initial == 0 {
            None
        } else {
            let end = if absolute {
                initial
            } else {
                now.checked_add(initial).ok_or(Overflow)?
            };
            if end > ceiling {
                return Err(Overflow);
            }
            Some(end)
        };
        Ok(Self {
            deadline,
            interval,
            ceiling,
        })
    }

    pub(super) fn deadline(self) -> Option<u128> {
        self.deadline
    }

    pub(super) fn interval(self) -> u128 {
        self.interval
    }

    pub(super) fn remaining(self, now: u128) -> u128 {
        self.deadline.map_or(0, |end| end.saturating_sub(now))
    }

    /// Advance from the scheduled deadline, not observation time. Work is
    /// bounded even after many missed periods. The exact expiration count is
    /// returned separately: signal queueing/acceptance determines overruns.
    ///
    /// If no later finite deadline exists, report the observed expirations and
    /// disarm instead of wrapping into the past or a native infinite wait.
    pub(super) fn observe(mut self, now: u128) -> (Self, u128) {
        let Some(end) = self.deadline.filter(|&end| end <= now) else {
            return (self, 0);
        };
        if self.interval == 0 {
            self.deadline = None;
            return (self, 1);
        }
        // Every armed deadline is nonzero, so this addition cannot overflow,
        // even when now is u128::MAX and the interval is one.
        let count = (now - end) / self.interval + 1;
        self.deadline = count
            .checked_mul(self.interval)
            .and_then(|step| end.checked_add(step))
            .filter(|&next| next <= self.ceiling);
        (self, count)
    }
}
