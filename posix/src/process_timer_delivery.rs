//! Timer-source acceptance used by the forthcoming joint signal dispatcher.
//! Selection is separate so this source cannot bypass ordinary/thread signal
//! priority. Native image/clock observations precede reply publication.
use super::*;
use process_timer::{Clock, Pending, Samples};
use process_timer_request::{ClockBackend, Reading};

impl<H: Copy> PosixService<H> {
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
        self.process_timers(peer)?
            .accept_with_reply(selected, samples, reply)
    }
}
