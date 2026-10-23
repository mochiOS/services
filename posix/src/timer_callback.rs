//! Authenticated callback-event acceptance. This layer never runs callbacks.
use super::*;
use process_timer::Notification;
use process_timer_request::ClockBackend;
use protocol::timer_callback::{self as wire, Event};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Completion {
    Pending,
    Published,
    Disconnected,
}

impl<H: Copy> PosixService<H> {
    /// Endpoint sender metadata and the native image lease are authoritative.
    /// Validate again at every deferred retry, including after sampling.
    pub fn poll_timer_callback<B: ClockBackend<H>>(
        &mut self,
        peer: PeerIdentity,
        image: RequestImage,
        sender: mnu_abi::ExecutionIdentity,
        header: protocol::Header,
        payload: &[u8],
        attachments: &[AttachedObject<H>],
        backend: &mut B,
        reply: impl FnOnce(Event) -> bool,
    ) -> Result<Completion, i32> {
        if header.opcode != protocol::OP_TIMER_THREAD_WAIT {
            return Err(protocol::STATUS_ENOSYS);
        }
        if header.flags != 0
            || header.status != 0
            || header.payload_len as usize != payload.len()
            || !attachments.is_empty()
        {
            return Err(STATUS_EINVAL);
        }
        wire::decode_request(payload).map_err(|_| STATUS_EINVAL)?;
        if sender.process_id == 0 || sender.process_id != peer.process_id || sender.thread_id == 0 {
            return Err(protocol::STATUS_EPERM);
        }
        self.validate_request_image(peer, image, backend)?;
        // Exited/unregistered receiving threads cannot consume notifications.
        let key = (peer.process_id, sender.thread_id);
        if !self.signal_delivery_epochs.contains_key(&key) {
            return Err(protocol::STATUS_ESRCH);
        }
        let timers = self.process_timers(peer)?;
        let Some(selected) = timers.select_pending_thread() else {
            return Ok(Completion::Pending);
        };
        let (clock, target) = timers.selected_thread_clock(selected)?;
        let process = *self
            .processes
            .get(&peer.process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        let samples = self
            .read_timer_clock(peer, process, clock, target, backend)
            .and_then(|reading| process_timer_reactor::sample(clock, reading));
        self.validate_request_image(peer, image, backend)?;
        let samples = samples?;
        let accepted =
            self.process_timers(peer)?
                .accept_with_reply(selected, samples, |pending| {
                    let Notification::Thread { cookie } = pending.notification else {
                        return false;
                    };
                    reply(Event {
                        timer: pending.timer.raw(),
                        cookie,
                        overrun: pending.overrun(),
                    })
                })?;
        Ok(if accepted.is_some() {
            Completion::Published
        } else {
            Completion::Disconnected
        })
    }
}
