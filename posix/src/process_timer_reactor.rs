//! Bounded service-loop observation independent of client RPC. Native clock
//! and process observations only: no provider IPC or application callbacks.
use super::*;
use process_timer::{Clock, Samples};
use process_timer_request::{ClockBackend, Reading};

pub const OBSERVATION_INTERVAL_MS: u64 = 10;

impl<H: Copy> PosixService<H> {
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
                };
                let clocks = [Clock::Realtime, Clock::Monotonic, Clock::ProcessCpu];
                let mut available = [false; 3];
                let mut first_error = None;
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
                let mut timers = self.process_timers(peer)?;
                for &(_, id, clock) in group {
                    let index = match clock {
                        Clock::Realtime => 0,
                        Clock::Monotonic => 1,
                        Clock::ProcessCpu => 2,
                    };
                    if !available[index] {
                        continue;
                    }
                    match timers.observe(id, samples) {
                        Ok(_) => observed += 1,
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
