//! Bounded service-loop observation independent of client RPC. Native clock
//! and process observations only: no provider IPC or application callbacks.
use super::*;
use process_timer::{Clock, Samples};
use process_timer_request::{ClockBackend, Reading};

pub const OBSERVATION_INTERVAL_MS: u64 = 10;

impl<H: Copy> PosixService<H> {
    /// Apply generation side effects without copying timer events into the
    /// coalesced ordinary-signal slot. Call once per new timer pending event.
    pub(super) fn notify_timer_signal(&mut self, owner: u64, signal: u32) -> Result<(), i32> {
        self.prepare_signal_generation(owner, signal)?;
        if self.signals[&owner].ignored & signal_bit(signal) != 0 {
            self.process_timers
                .discard_signals(owner, signal_bit(signal));
        } else {
            self.signal_notifications.insert(owner);
        }
        self.remove_empty_signal_notification(owner);
        Ok(())
    }

    pub(super) fn remove_empty_signal_notification(&mut self, owner: u64) {
        if self
            .signals
            .get(&owner)
            .is_none_or(|state| state.pending() == 0)
            && self.process_timers.pending_signal_mask(owner) == 0
        {
            self.signal_notifications.remove(&owner);
        }
    }

    /// Called after validating the retained native ThreadHandle against its
    /// endpoint identity. Mask initialization can precede Handle registration;
    /// replay any still-deliverable process/timer event once the Handle exists.
    /// False permits Handle registration before mask initialization without
    /// creating an implicit unblocked mask or granting signal delivery.
    pub fn signal_thread_ready(
        &mut self,
        peer: PeerIdentity,
        sender: mnu_abi::ExecutionIdentity,
    ) -> Result<bool, i32> {
        if sender.process_id == 0 || sender.thread_id == 0 || sender.process_id != peer.process_id {
            return Err(protocol::STATUS_EPERM);
        }
        let key = (sender.process_id, sender.thread_id);
        let state = self
            .signals
            .get(&sender.process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        let Some(&blocked) = self.signal_masks.get(&key) else {
            return Ok(false);
        };
        self.signal_delivery_epochs
            .get(&key)
            .ok_or(protocol::STATUS_ESRCH)?;
        if (state.pending() | self.process_timers.pending_signal_mask(sender.process_id)) & !blocked
            != 0
        {
            self.signal_notifications.insert(sender.process_id);
        }
        if self.thread_pending_signals.get(&key).copied().unwrap_or(0) & !blocked != 0 {
            self.thread_signal_notifications.insert(key);
        }
        Ok(true)
    }

    pub fn has_observable_process_timers(&self) -> bool {
        self.process_timers.has_observable()
    }

    /// Cache each requested clock once per owner. A bad owner/clock does not
    /// consume its expiration or prevent independent timers from advancing.
    /// Revalidate the native image after sampling and before policy mutation.
    pub fn observe_process_timers<B: ClockBackend<H>>(
        &mut self,
        backend: &mut B,
    ) -> Result<usize, i32> {
        if !self.has_observable_process_timers() {
            return Ok(0);
        }
        let plan = self.process_timers.observation_plan()?;
        let mut observed = 0;
        let mut failure = None;
        for group in plan.chunk_by(|a, b| a.0 == b.0) {
            let owner = group[0].0;
            let result = (|| {
                let peer = self.registered_peer(owner).ok_or(protocol::STATUS_ESRCH)?;
                self.refresh_image_state(peer, backend)?;
                // A commit already observed at admission deleted the old
                // image's timers. Never revive entries from the old plan.
                if !self.process_timers.has_owner(owner) {
                    return Ok(());
                }
                let image = self.capture_request_image(peer)?;
                let process = *self.processes.get(&owner).ok_or(protocol::STATUS_ESRCH)?;
                let mut samples = Samples {
                    realtime_ns: 0,
                    monotonic_ns: 0,
                    process_cpu_ns: 0,
                    thread_cpu_ns: 0,
                };
                let mut thread_samples = Vec::new();
                thread_samples
                    .try_reserve_exact(
                        group
                            .iter()
                            .filter(|entry| entry.2 == Clock::ThreadCpu)
                            .count(),
                    )
                    .map_err(|_| protocol::STATUS_ENOMEM)?;
                let clocks = [Clock::Realtime, Clock::Monotonic, Clock::ProcessCpu];
                let mut available = [false; 3];
                let mut first_error = None;
                for &(_, id, clock) in group {
                    if clock != Clock::ThreadCpu {
                        continue;
                    }
                    let thread = self
                        .process_timers(peer)?
                        .clock_thread(id)?
                        .ok_or(protocol::STATUS_EIO)?;
                    if thread_samples.iter().any(|(target, _)| *target == thread) {
                        continue;
                    }
                    let reading = backend
                        .timer_thread_clock(process, thread)
                        .and_then(|reading| match reading {
                            Reading::Counter(value) => Ok(value),
                            _ => Err(protocol::STATUS_EIO),
                        });
                    if let Err(error) = reading {
                        first_error.get_or_insert(error);
                    }
                    thread_samples.push((thread, reading));
                }
                for (index, clock) in clocks.into_iter().enumerate() {
                    if !group.iter().any(|&(_, _, basis)| basis == clock) {
                        continue;
                    }
                    let result = backend.timer_clock(process, clock).and_then(|reading| {
                        match (clock, reading) {
                            (Clock::Realtime, Reading::Realtime(value)) => {
                                samples.realtime_ns = value
                            }
                            (Clock::Monotonic, Reading::Counter(value)) => {
                                samples.monotonic_ns = value
                            }
                            (Clock::ProcessCpu, Reading::Counter(value)) => {
                                samples.process_cpu_ns = value
                            }
                            _ => return Err(protocol::STATUS_EIO),
                        }
                        Ok(())
                    });
                    match result {
                        Ok(()) => available[index] = true,
                        Err(error) => {
                            first_error.get_or_insert(error);
                        }
                    }
                }
                self.validate_request_image(peer, image, backend)?;
                for &(_, id, clock) in group {
                    let index = match clock {
                        Clock::Realtime => 0,
                        Clock::Monotonic => 1,
                        Clock::ProcessCpu => 2,
                        Clock::ThreadCpu => {
                            let thread = self
                                .process_timers(peer)?
                                .clock_thread(id)?
                                .ok_or(protocol::STATUS_EIO)?;
                            let Some((_, Ok(value))) =
                                thread_samples.iter().find(|(target, _)| *target == thread)
                            else {
                                continue;
                            };
                            let mut per_thread = samples;
                            per_thread.thread_cpu_ns = *value;
                            match self
                                .process_timers(peer)?
                                .observe_new_signal(id, per_thread)
                            {
                                Ok(signal) => {
                                    observed += 1;
                                    if let Some(signal) = signal {
                                        self.notify_timer_signal(owner, signal)?;
                                    }
                                }
                                Err(error) => {
                                    first_error.get_or_insert(error);
                                }
                            }
                            continue;
                        }
                    };
                    if !available[index] {
                        continue;
                    }
                    match self.process_timers(peer)?.observe_new_signal(id, samples) {
                        Ok(signal) => {
                            observed += 1;
                            if let Some(signal) = signal {
                                self.notify_timer_signal(owner, signal)?;
                            }
                        }
                        Err(error) => {
                            first_error.get_or_insert(error);
                        }
                    }
                }
                first_error.map_or(Ok(()), Err)
            })();
            if let Err(error) = result {
                failure.get_or_insert(error);
            }
        }
        failure.map_or(Ok(observed), Err)
    }
}
