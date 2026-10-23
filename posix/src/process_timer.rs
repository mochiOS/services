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
    pub thread_cpu_ns: u128,
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
            Clock::ThreadCpu => self.thread_cpu_ns,
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
    /// Encode only a snapshot obtained at acceptance, not a caller's earlier
    /// peek. Value tokens are process-local registry keys, never C pointers.
    pub fn signal_origin(self) -> Result<protocol::signal_origin::Origin, i32> {
        let value_token = match self.notification {
            Notification::Signal { signal, value }
                if (1..=protocol::SIGNAL_MAX).contains(&signal) =>
            {
                value
            }
            _ => return Err(STATUS_EINVAL),
        };
        Ok(protocol::signal_origin::Origin {
            source: protocol::signal_origin::TIMER,
            timer: Some(protocol::signal_origin::TimerStatus {
                timer_id: self.timer.raw(),
                value_token,
                overrun: self.overrun(),
            }),
            ..protocol::signal_origin::Origin::system()
        })
    }

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
    // Native identity admitted by the service, never supplied on the wire.
    thread: Option<u64>,
    notification: Notification,
    schedule: Schedule,
    pending: Option<Pending>,
    last_overrun: u32,
}

impl Timer {
    fn observable(&self) -> bool {
        self.notification != Notification::None && self.schedule.deadline().is_some()
    }
}

#[derive(Debug)]
pub(super) struct Registry {
    // Strictly ordered by the non-reused global ID. Removal/retirement must
    // preserve that order so a reactor sweep does not do one full scan per ID.
    timers: Vec<Timer>,
    next_id: u64,
    next_sequence: u64,
}

impl Registry {
    // Internal field-split borrow, after the service has admitted the owner.
    pub(super) fn for_owner(&mut self, owner: u64) -> OwnedTimers<'_> {
        OwnedTimers {
            owner,
            registry: self,
        }
    }

    pub(super) fn has_observable(&self) -> bool {
        self.timers.iter().any(Timer::observable)
    }

    pub(super) fn observation_plan(&self) -> Result<Vec<(u64, TimerId, Clock)>, i32> {
        let mut plan = Vec::new();
        let count = self
            .timers
            .iter()
            .filter(|timer| timer.observable())
            .count();
        plan.try_reserve_exact(count)
            .map_err(|_| protocol::STATUS_ENOMEM)?;
        for timer in &self.timers {
            if timer.observable() {
                plan.push((timer.owner, timer.id, timer.basis));
            }
        }
        plan.sort_unstable_by_key(|&(owner, id, _)| (owner, id.raw()));
        Ok(plan)
    }

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

    pub(super) fn retire_thread(&mut self, owner: u64, thread: u64) {
        // This implementation invalidates clocks bound to a departed native
        // thread. Process-clock timers created by that thread remain owned by
        // the process and are deliberately not selected here.
        self.timers
            .retain(|timer| timer.owner != owner || timer.thread != Some(thread));
    }

    pub(super) fn pending_signal_mask(&self, owner: u64) -> u64 {
        self.timers
            .iter()
            .filter(|timer| timer.owner == owner)
            .filter_map(|timer| timer.pending)
            .fold(0, |mask, pending| match pending.notification {
                Notification::Signal { signal, .. } => mask | signal_bit(signal),
                _ => mask,
            })
    }

    /// Disposition changes discard pending occurrences, not the timer's
    /// schedule or the last accepted overrun. No native observation is needed.
    pub(super) fn discard_signals(&mut self, owner: u64, mask: u64) {
        for timer in &mut self.timers {
            if timer.owner == owner && timer.pending.is_some_and(|pending| {
                matches!(pending.notification, Notification::Signal { signal, .. } if mask & signal_bit(signal) != 0)
            }) {
                timer.pending = None;
            }
        }
    }
}

/// A borrow scoped to one admitted process. An ID from another process,
/// including one with UID zero, never selects its timer.
pub struct OwnedTimers<'a> {
    owner: u64,
    registry: &'a mut Registry,
}

impl OwnedTimers<'_> {
    /// Service-local selection only. Distinct timers using the same signal
    /// keep distinct pending events; selecting does not accept either event.
    pub fn pending_notifications(&self) -> impl Iterator<Item = Pending> + '_ {
        self.registry.timers.iter().filter_map(|timer| {
            (timer.owner == self.owner)
                .then_some(timer.pending)
                .flatten()
        })
    }

    pub fn pending_signals(&self, mask: u64) -> impl Iterator<Item = Pending> + '_ {
        self.pending_notifications()
            .filter(move |pending| match pending.notification {
                Notification::Signal { signal, .. } => mask & (1u64 << (signal - 1)) != 0,
                _ => false,
            })
    }

    /// Deterministic candidate for a joint signal selector. No event is
    /// consumed here; ordinary/thread-pending signals may still take priority.
    pub fn select_pending_signal(&self, mask: u64) -> Option<Pending> {
        self.pending_signals(mask)
            .filter_map(|pending| match pending.notification {
                Notification::Signal { signal, .. } => Some((signal, pending)),
                _ => None,
            })
            .min_by_key(|(signal, pending)| (*signal, pending.timer.raw()))
            .map(|(_, pending)| pending)
    }

    pub(super) fn selected_signal_basis(&self, selected: Pending) -> Result<Clock, i32> {
        let (index, pending) = self.selected(selected)?;
        if !matches!(pending.notification, Notification::Signal { .. }) {
            return Err(STATUS_EINVAL);
        }
        Ok(self.registry.timers[index].basis)
    }

    fn selected(&self, selected: Pending) -> Result<(usize, Pending), i32> {
        let index = self.index(selected.timer)?;
        let pending = self.registry.timers[index]
            .pending
            .filter(|pending| pending.sequence == selected.sequence)
            .ok_or(protocol::STATUS_EAGAIN)?;
        Ok((index, pending))
    }

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

    pub(super) fn clock_thread(&self, id: TimerId) -> Result<Option<u64>, i32> {
        Ok(self.registry.timers[self.index(id)?].thread)
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
        let index = self
            .registry
            .timers
            .binary_search_by_key(&id.raw(), |timer| timer.id.raw())
            .map_err(|_| STATUS_EINVAL)?;
        if self.registry.timers[index].owner != self.owner {
            return Err(STATUS_EINVAL);
        }
        Ok(index)
    }

    pub fn create(&mut self, clock: Clock, notification: Notification) -> Result<TimerId, i32> {
        self.create_for_thread(clock, notification, None)
    }

    pub(super) fn create_for_thread(
        &mut self,
        clock: Clock,
        notification: Notification,
        thread: Option<u64>,
    ) -> Result<TimerId, i32> {
        if (clock == Clock::ThreadCpu) != thread.is_some() || thread == Some(0) {
            return Err(STATUS_EINVAL);
        }
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
            thread,
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
        self.registry.timers.remove(index);
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

    /// Report a signal only when a new pending event was created, not when an
    /// already-pending event merely accumulated another overrun.
    pub(super) fn observe_new_signal(
        &mut self,
        id: TimerId,
        samples: Samples,
    ) -> Result<Option<u32>, i32> {
        let was_pending = self.registry.timers[self.index(id)?].pending.is_some();
        Ok(match self.observe(id, samples)? {
            Some(Pending {
                notification: Notification::Signal { signal, .. },
                ..
            }) if !was_pending => Some(signal),
            _ => None,
        })
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
        self.finish_with_reply(selected, samples, true, |_| true)?
            .ok_or(protocol::STATUS_EIO)
    }

    /// Publish first, then commit acceptance. The synchronous reply closure
    /// must not re-enter the registry or invoke application code. A failed
    /// publication leaves this event pending and the last overrun unchanged.
    /// False must mean nothing was published; no fallible work may follow a
    /// successful publication inside the closure.
    pub fn accept_with_reply<R>(
        &mut self,
        selected: Pending,
        samples: Samples,
        reply: R,
    ) -> Result<Option<Pending>, i32>
    where
        R: FnOnce(Pending) -> bool,
    {
        self.finish_with_reply(selected, samples, true, reply)
    }

    /// Used when delivery is intentionally discarded, for example SIG_IGN.
    /// It must not change the last delivered overrun value.
    pub fn discard(&mut self, selected: Pending, samples: Samples) -> Result<(), i32> {
        self.finish_with_reply(selected, samples, false, |_| true)
            .map(|_| ())
    }

    fn finish_with_reply<R>(
        &mut self,
        selected: Pending,
        samples: Samples,
        accepted: bool,
        reply: R,
    ) -> Result<Option<Pending>, i32>
    where
        R: FnOnce(Pending) -> bool,
    {
        // Validate before observation so a stale completion changes nothing,
        // including a replacement timer's deadline or overrun accounting.
        let (index, _) = self.selected(selected)?;
        self.observe(selected.timer, samples)?;
        let timer = &mut self.registry.timers[index];
        let pending = timer
            .pending
            .filter(|pending| pending.sequence == selected.sequence)
            .ok_or(protocol::STATUS_EAGAIN)?;
        if !reply(pending) {
            return Ok(None);
        }
        timer.pending = None;
        if accepted {
            timer.last_overrun = pending.overrun();
        }
        Ok(Some(pending))
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
