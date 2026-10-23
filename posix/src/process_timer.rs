//! Service-local POSIX timer ownership and notification accounting.
//! This is not an IPC API: clock samples and peer identity must come from the
//! authenticated service dispatcher. No function pointer crosses this layer.
use super::*;
pub use protocol::process_timer::{Clock, Notification, Value};
use timer_schedule::Schedule;

pub const MAX_TIMERS_PER_PROCESS: usize = 128;
pub const MAX_OVERRUN: u32 = i32::MAX as u32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimerId(u64);

impl TimerId {
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// Independent clock domains sampled by the trusted adapter before state
/// admission. A failed native sample must not be replaced by a zero timestamp.
#[derive(Clone, Copy, Debug)]
pub struct Samples {
    pub realtime_ns: i128,
    pub monotonic_ns: u128,
    pub process_cpu_ns: u128,
}

impl Samples {
    fn now(self, basis: Clock) -> u128 {
        match basis {
            // Bias signed civil time into an ordered unsigned domain, so a
            // pre-epoch clock is representable without confusing zero with
            // disarm. Public timer durations remain ordinary nanoseconds.
            Clock::Realtime => (self.realtime_ns as u128) ^ (1u128 << 127),
            Clock::Monotonic => self.monotonic_ns,
            Clock::ProcessCpu => self.process_cpu_ns,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pending {
    pub timer: TimerId,
    pub notification: Notification,
    // Kept private so an external adapter must retain the actual selected
    // notification rather than manufacture completion tokens from timer IDs.
    sequence: u64,
    expirations: u128,
}

impl Pending {
    pub fn overrun(self) -> u32 {
        self.expirations
            .saturating_sub(1)
            .min(u128::from(MAX_OVERRUN)) as u32
    }
}

#[derive(Clone, Copy, Debug)]
struct Timer {
    owner: u64,
    id: TimerId,
    clock: Clock,
    basis: Clock,
    notification: Notification,
    schedule: Schedule,
    pending: Option<Pending>,
    last_overrun: u32,
}

#[derive(Debug)]
pub(super) struct Registry {
    timers: Vec<Timer>,
    next_id: u64,
    next_sequence: u64,
}

impl Registry {
    pub(super) const fn new() -> Self {
        Self {
            timers: Vec::new(),
            next_id: 1,
            next_sequence: 1,
        }
    }

    pub(super) fn has_owner(&self, owner: u64) -> bool {
        self.timers.iter().any(|timer| timer.owner == owner)
    }

    pub(super) fn retire_owner(&mut self, owner: u64) {
        self.timers.retain(|timer| timer.owner != owner);
    }
}

/// A borrow scoped to one admitted process. An ID from another process,
/// including one with UID zero, never selects its timer.
pub struct OwnedTimers<'a> {
    owner: u64,
    registry: &'a mut Registry,
}

impl OwnedTimers<'_> {
    pub(super) fn resolve(&self, raw: u64) -> Result<TimerId, i32> {
        let id = TimerId(raw);
        self.index(id)?;
        Ok(id)
    }

    pub(super) fn clocks_for(
        &self,
        id: TimerId,
        replacement: Option<bool>,
    ) -> Result<[Option<Clock>; 2], i32> {
        let timer = &self.registry.timers[self.index(id)?];
        let next = replacement
            .map(|absolute| {
                if timer.clock == Clock::Realtime && !absolute {
                    Clock::Monotonic
                } else {
                    timer.clock
                }
            })
            .filter(|clock| *clock != timer.basis);
        Ok([Some(timer.basis), next])
    }

    pub(super) fn preview_value(&self, id: TimerId, samples: Samples) -> Result<Value, i32> {
        let timer = &self.registry.timers[self.index(id)?];
        let now = samples.now(timer.basis);
        let schedule = timer.schedule.observe(now).0;
        Ok(Value {
            remaining_ns: schedule.remaining(now),
            interval_ns: schedule.interval(),
        })
    }
    fn index(&self, id: TimerId) -> Result<usize, i32> {
        self.registry
            .timers
            .iter()
            .position(|timer| timer.owner == self.owner && timer.id == id)
            .ok_or(STATUS_EINVAL)
    }

    pub fn create(&mut self, clock: Clock, notification: Notification) -> Result<TimerId, i32> {
        if let Notification::Signal { signal, .. } = notification {
            if !(1..=protocol::SIGNAL_MAX).contains(&signal) {
                return Err(STATUS_EINVAL);
            }
        }
        if matches!(notification, Notification::Thread { cookie: 0 }) {
            return Err(STATUS_EINVAL);
        }
        if self
            .registry
            .timers
            .iter()
            .filter(|timer| timer.owner == self.owner)
            .count()
            >= MAX_TIMERS_PER_PROCESS
        {
            return Err(protocol::STATUS_EAGAIN);
        }
        let next = self
            .registry
            .next_id
            .checked_add(1)
            .ok_or(protocol::STATUS_EAGAIN)?;
        self.registry
            .timers
            .try_reserve(1)
            .map_err(|_| protocol::STATUS_ENOMEM)?;
        let id = TimerId(self.registry.next_id);
        let notification = match notification {
            Notification::Default => Notification::Signal {
                signal: protocol::SIGNAL_ALRM,
                value: id.raw(),
            },
            notification => notification,
        };
        self.registry.timers.push(Timer {
            owner: self.owner,
            id,
            clock,
            basis: if clock == Clock::Realtime {
                Clock::Monotonic
            } else {
                clock
            },
            notification,
            schedule: Schedule::arm(0, 0, 0, false, u128::MAX).unwrap(),
            pending: None,
            last_overrun: 0,
        });
        self.registry.next_id = next;
        Ok(id)
    }

    pub fn delete(&mut self, id: TimerId) -> Result<(), i32> {
        let index = self.index(id)?;
        self.registry.timers.swap_remove(index);
        Ok(())
    }

    pub fn clock(&self, id: TimerId) -> Result<Clock, i32> {
        Ok(self.registry.timers[self.index(id)?].clock)
    }

    /// Resetting discards the timer's pending notification; POSIX leaves that
    /// choice unspecified. The overrun of the last accepted event is retained.
    /// Validate a replacement before changing any old schedule or notification.
    pub fn set(
        &mut self,
        id: TimerId,
        samples: Samples,
        initial_ns: u128,
        interval_ns: u128,
        absolute: bool,
    ) -> Result<Value, i32> {
        let index = self.index(id)?;
        let timer = &self.registry.timers[index];
        let basis = if timer.clock == Clock::Realtime && !absolute {
            Clock::Monotonic
        } else {
            timer.clock
        };
        let initial_ns = if basis == Clock::Realtime && initial_ns != 0 {
            initial_ns
                .checked_add(1u128 << 127)
                .ok_or(STATUS_EOVERFLOW)?
        } else {
            initial_ns
        };
        let replacement = Schedule::arm(
            samples.now(basis),
            initial_ns,
            interval_ns,
            absolute,
            u128::MAX,
        )
        .map_err(|_| STATUS_EOVERFLOW)?;
        let timer = &mut self.registry.timers[index];
        let previous_now = samples.now(timer.basis);
        let previous = timer.schedule.observe(previous_now).0;
        let previous = Value {
            remaining_ns: previous.remaining(previous_now),
            interval_ns: previous.interval(),
        };
        timer.schedule = replacement;
        timer.basis = basis;
        timer.pending = None;
        Ok(previous)
    }

    /// Observation creates at most one pending event per timer, not one per
    /// missed period. Repeated polling returns the same token with updated
    /// accounting until it is accepted, discarded, reset or deleted.
    pub fn observe(&mut self, id: TimerId, samples: Samples) -> Result<Option<Pending>, i32> {
        let index = self.index(id)?;
        let timer = &mut self.registry.timers[index];
        let (schedule, count) = timer.schedule.observe(samples.now(timer.basis));
        if count != 0 && timer.notification != Notification::None {
            if let Some(pending) = &mut timer.pending {
                pending.expirations = pending.expirations.saturating_add(count);
            } else {
                let next = self
                    .registry
                    .next_sequence
                    .checked_add(1)
                    .ok_or(STATUS_EOVERFLOW)?;
                timer.pending = Some(Pending {
                    timer: id,
                    notification: timer.notification,
                    sequence: self.registry.next_sequence,
                    expirations: count,
                });
                self.registry.next_sequence = next;
            }
        }
        timer.schedule = schedule;
        Ok(timer.pending)
    }

    pub fn value(&mut self, id: TimerId, samples: Samples) -> Result<Value, i32> {
        self.observe(id, samples)?;
        let timer = &self.registry.timers[self.index(id)?];
        Ok(Value {
            remaining_ns: timer.schedule.remaining(samples.now(timer.basis)),
            interval_ns: timer.schedule.interval(),
        })
    }

    pub fn overrun(&self, id: TimerId) -> Result<u32, i32> {
        Ok(self.registry.timers[self.index(id)?].last_overrun)
    }

    /// Sample the selected timer's clock at acceptance, not just at an earlier
    /// reactor wakeup. Expirations during that gap belong to this delivery.
    /// A failed or old completion cannot consume a replacement notification.
    pub fn accept(&mut self, selected: Pending, samples: Samples) -> Result<Pending, i32> {
        self.finish(selected, samples, true)
    }

    /// Used when delivery is intentionally discarded, for example SIG_IGN.
    /// It must not change the last delivered overrun value.
    pub fn discard(&mut self, selected: Pending, samples: Samples) -> Result<(), i32> {
        self.finish(selected, samples, false).map(|_| ())
    }

    fn finish(
        &mut self,
        selected: Pending,
        samples: Samples,
        accepted: bool,
    ) -> Result<Pending, i32> {
        let index = self.index(selected.timer)?;
        // Validate before observation so a stale completion changes nothing,
        // including a replacement timer's deadline or overrun accounting.
        self.registry.timers[index]
            .pending
            .filter(|pending| pending.sequence == selected.sequence)
            .ok_or(protocol::STATUS_EAGAIN)?;
        self.observe(selected.timer, samples)?;
        let timer = &mut self.registry.timers[index];
        let pending = timer
            .pending
            .filter(|pending| pending.sequence == selected.sequence)
            .ok_or(protocol::STATUS_EAGAIN)?;
        timer.pending = None;
        if accepted {
            timer.last_overrun = pending.overrun();
        }
        Ok(pending)
    }
}

impl<H: Copy> PosixService<H> {
    /// Service-internal admission, not a caller-supplied PID/UID wire request.
    /// Native image refresh must run before acquiring this synchronous borrow.
    pub fn process_timers(&mut self, peer: PeerIdentity) -> Result<OwnedTimers<'_>, i32> {
        if !self.sessions.contains_key(&peer.process_id)
            || !self.processes.contains_key(&peer.process_id)
            || self
                .process_wait_states
                .get(&peer.process_id)
                .is_none_or(|state| state.exit_observed)
        {
            return Err(protocol::STATUS_ESRCH);
        }
        Ok(OwnedTimers {
            owner: peer.process_id,
            registry: &mut self.process_timers,
        })
    }
}
