//! Timer-source acceptance and joint synchronous signal selection.
//! Selection is separate so this source cannot bypass ordinary/thread signal
//! priority. Native image/clock observations precede reply publication.
use super::*;
use process_timer::{Clock, Pending, Samples};
use process_timer_request::{ClockBackend, Reading};

impl<H: Copy> PosixService<H> {
    /// Synchronous wait entry for the native dispatcher. Thread-private events
    /// retain priority; process events and timers are selected by signal number
    /// (ordinary process events win equal-number ties). Distinct timers remain
    /// distinct events. Image, clocks and origin are checked before publication.
    pub fn poll_wait_signal_info_with_timers<B, R>(
        &mut self,
        peer: PeerIdentity,
        image: RequestImage,
        sender: mnu_abi::ExecutionIdentity,
        requested: u64,
        expected_epoch: u64,
        deadline: Option<u64>,
        now: u64,
        backend: &mut B,
        reply: R,
    ) -> Result<SignalWaitCompletion, i32>
    where
        B: ClockBackend<H>,
        R: FnOnce(protocol::signal_wait::Accepted) -> bool,
    {
        self.validate_request_image(peer, image, backend)?;
        self.validate_wait_delivery_epoch(peer, sender, expected_epoch)?;
        let key = (sender.process_id, sender.thread_id);
        let requested =
            requested & !(signal_bit(protocol::SIGNAL_KILL) | signal_bit(protocol::SIGNAL_STOP));
        if requested & !self.signal_masks[&key] != 0 {
            return Err(STATUS_EINVAL);
        }
        let own = self.thread_pending_signals.get(&key).copied().unwrap_or(0) & requested;
        let ordinary = self.signals[&sender.process_id].pending() & requested;
        let timer_requested = requested & !self.signals[&sender.process_id].ignored;
        let selected = if own == 0 {
            self.process_timers(peer)?
                .select_pending_signal(timer_requested)
                .filter(|pending| match pending.notification {
                    process_timer::Notification::Signal { signal, .. } => {
                        ordinary == 0 || signal < ordinary.trailing_zeros() + 1
                    }
                    _ => false,
                })
        } else {
            None
        };
        let Some(selected) = selected else {
            return self.poll_wait_signal_info_with_reply(
                peer,
                sender,
                requested,
                expected_epoch,
                deadline,
                now,
                reply,
            );
        };
        // A pending event is accepted even when the observed deadline expired.
        // The adapter resamples its own clock, not this wait's monotonic clock.
        let mut encoding_error = None;
        let accepted =
            self.accept_timer_signal_with_reply(peer, image, selected, backend, |pending| {
                let signal = match pending.notification {
                    process_timer::Notification::Signal { signal, .. } => signal,
                    _ => {
                        encoding_error = Some(STATUS_EINVAL);
                        return false;
                    }
                };
                match pending.signal_origin() {
                    Ok(origin) => reply(protocol::signal_wait::Accepted { signal, origin }),
                    Err(error) => {
                        encoding_error = Some(error);
                        false
                    }
                }
            })?;
        if let Some(error) = encoding_error {
            return Err(error);
        }
        Ok(if accepted.is_some() {
            SignalWaitCompletion::Replied
        } else {
            SignalWaitCompletion::Undelivered
        })
    }

    /// The image and peer come from authenticated admission, never request
    /// payload identity. This is an internal source adapter, not an IPC entry.
    /// Reply publication must be synchronous and may not run application code.
    /// Its false result must mean no publication occurred.
    pub fn accept_timer_signal_with_reply<B, R>(
        &mut self,
        peer: PeerIdentity,
        image: RequestImage,
        selected: Pending,
        backend: &mut B,
        reply: R,
    ) -> Result<Option<Pending>, i32>
    where
        B: ClockBackend<H>,
        R: FnOnce(Pending) -> bool,
    {
        let samples = self.timer_signal_samples(peer, image, selected, backend)?;
        let accepted = self
            .process_timers(peer)?
            .accept_with_reply(selected, samples, reply)?;
        if accepted.is_some() {
            self.remove_empty_signal_notification(peer.process_id);
        }
        Ok(accepted)
    }

    pub(super) fn timer_signal_samples<B: ClockBackend<H>>(
        &mut self,
        peer: PeerIdentity,
        image: RequestImage,
        selected: Pending,
        backend: &mut B,
    ) -> Result<Samples, i32> {
        self.validate_request_image(peer, image, backend)?;
        let basis = self.process_timers(peer)?.selected_signal_basis(selected)?;
        let process = *self
            .processes
            .get(&peer.process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        let mut samples = Samples {
            realtime_ns: 0,
            monotonic_ns: 0,
            process_cpu_ns: 0,
        };
        match (basis, backend.timer_clock(process, basis)?) {
            (Clock::Realtime, Reading::Realtime(value)) => samples.realtime_ns = value,
            (Clock::Monotonic, Reading::Counter(value)) => samples.monotonic_ns = value,
            (Clock::ProcessCpu, Reading::Counter(value)) => samples.process_cpu_ns = value,
            _ => return Err(protocol::STATUS_EIO),
        }
        self.validate_request_image(peer, image, backend)?;
        Ok(samples)
    }
}
