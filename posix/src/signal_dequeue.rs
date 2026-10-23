//! Authenticated asynchronous dequeue. Publication, not selection, commits a
//! pending event and its delivery epoch. No application callback runs here.
use super::*;
use process_timer::{Notification, Pending};
use process_timer_request::ClockBackend;

pub(super) fn allocate_token(next: &mut u64) -> Result<u64, i32> {
    let token = (*next).max(1);
    *next = token.checked_add(1).ok_or(STATUS_EOVERFLOW)?;
    Ok(token)
}

struct Publication<'a> {
    state: &'a mut ProcessWaitState,
    epoch: &'a mut u64,
    next_epoch: u64,
    delivery: protocol::SignalDelivery,
    published: bool,
}
impl<'a> Publication<'a> {
    fn new(
        state: &'a mut ProcessWaitState,
        epoch: &'a mut u64,
        next_token: &mut u64,
        sender: mnu_abi::ExecutionIdentity,
        signal: u32,
        origin: protocol::signal_origin::Origin,
    ) -> Result<Self, i32> {
        if state.deliveries.len() >= MAX_OUTSTANDING_SIGNAL_DELIVERIES {
            return Err(protocol::STATUS_EAGAIN);
        }
        let next_epoch = epoch.checked_add(1).ok_or(STATUS_EOVERFLOW)?;
        let delivery = protocol::SignalDelivery {
            signal,
            token: allocate_token(next_token)?,
        };
        // Storage is allocated before any reply can publish this token.
        state.begin_delivery(delivery, sender.thread_id, origin);
        Ok(Self {
            state,
            epoch,
            next_epoch,
            delivery,
            published: false,
        })
    }
    fn publish(&mut self, reply: impl FnOnce(protocol::SignalDelivery) -> bool) -> bool {
        if !reply(self.delivery) {
            return false;
        }
        self.published = true;
        *self.epoch = self.next_epoch;
        true
    }
}
impl Drop for Publication<'_> {
    fn drop(&mut self) {
        if !self.published {
            self.state.deliveries.remove(&self.delivery.token);
        }
    }
}

#[derive(Clone, Copy)]
enum Candidate {
    Ordinary {
        signal: u32,
        origin_key: (u64, u64, u32),
    },
    Timer(Pending),
}

impl<H: Copy> PosixService<H> {
    /// Sender and image must come from authenticated endpoint admission.
    /// False means the reply did not publish; it must not run application code
    /// or perform fallible work after successful publication. None retains the
    /// event for retry. Some({0,0}) is a successfully published empty dequeue.
    pub fn dequeue_signal_with_timers<B, R>(
        &mut self,
        peer: PeerIdentity,
        image: RequestImage,
        sender: mnu_abi::ExecutionIdentity,
        backend: &mut B,
        reply: R,
    ) -> Result<Option<protocol::SignalDelivery>, i32>
    where
        B: ClockBackend<H>,
        R: FnOnce(protocol::SignalDelivery) -> bool,
    {
        if sender.process_id == 0 || sender.process_id != peer.process_id || sender.thread_id == 0 {
            return Err(protocol::STATUS_EPERM);
        }
        self.validate_request_image(peer, image, backend)?;
        let key = (sender.process_id, sender.thread_id);
        let blocked = *self.signal_masks.get(&key).ok_or(protocol::STATUS_ESRCH)?;
        self.signal_delivery_epochs
            .get(&key)
            .ok_or(protocol::STATUS_ESRCH)?;
        let eligible =
            !(blocked & !(signal_bit(protocol::SIGNAL_KILL) | signal_bit(protocol::SIGNAL_STOP)));
        let own = self.thread_pending_signals.get(&key).copied().unwrap_or(0) & eligible;
        let ordinary = self
            .signals
            .get(&sender.process_id)
            .ok_or(protocol::STATUS_ESRCH)?
            .pending()
            & eligible;
        let ignored = self.signals[&sender.process_id].ignored;
        let timer = self
            .process_timers(peer)?
            .select_pending_signal(eligible & !ignored);
        let candidate = if own != 0 {
            let signal = own.trailing_zeros() + 1;
            Some(Candidate::Ordinary { signal, origin_key: (sender.process_id, sender.thread_id, signal) })
        } else if let Some(timer) = timer.filter(|pending| {
            matches!(pending.notification, Notification::Signal { signal, .. } if ordinary == 0 || signal < ordinary.trailing_zeros() + 1)
        }) {
            Some(Candidate::Timer(timer))
        } else if ordinary != 0 {
            let signal = ordinary.trailing_zeros() + 1;
            Some(Candidate::Ordinary { signal, origin_key: (sender.process_id, 0, signal) })
        } else {
            None
        };
        let Some(candidate) = candidate else {
            let empty = protocol::SignalDelivery {
                signal: 0,
                token: 0,
            };
            return Ok(reply(empty).then_some(empty));
        };
        let (signal, origin, timer) = match candidate {
            Candidate::Ordinary { signal, origin_key } => {
                let origin = *self
                    .signal_origins
                    .get(&origin_key)
                    .ok_or(protocol::STATUS_EIO)?;
                (signal, origin, None)
            }
            Candidate::Timer(selected) => {
                let samples = self.timer_signal_samples(peer, image, selected, backend)?;
                // Resample before reserving publication storage. No acceptance
                // or last-overrun update occurs until the reply succeeds.
                let pending = self
                    .process_timers(peer)?
                    .observe(selected.timer, samples)?
                    .ok_or(protocol::STATUS_EAGAIN)?;
                let Notification::Signal { signal, .. } = pending.notification else {
                    return Err(STATUS_EINVAL);
                };
                (signal, pending.signal_origin()?, Some((pending, samples)))
            }
        };
        let state = self
            .process_wait_states
            .get_mut(&sender.process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        let epoch = self
            .signal_delivery_epochs
            .get_mut(&key)
            .ok_or(protocol::STATUS_ESRCH)?;
        let mut publication = Publication::new(
            state,
            epoch,
            &mut self.next_signal_delivery_token,
            sender,
            signal,
            origin,
        )?;
        let delivery = publication.delivery;
        let published = if let Some((pending, samples)) = timer {
            self.process_timers
                .for_owner(sender.process_id)
                .accept_with_reply(pending, samples, |_| publication.publish(reply))?
                .is_some()
        } else {
            let Candidate::Ordinary { origin_key, .. } = candidate else {
                unreachable!()
            };
            let pending = if origin_key.1 == 0 {
                &mut self
                    .signals
                    .get_mut(&sender.process_id)
                    .ok_or(protocol::STATUS_ESRCH)?
                    .pending
            } else {
                self.thread_pending_signals
                    .get_mut(&key)
                    .ok_or(protocol::STATUS_ESRCH)?
            };
            if publication.publish(reply) {
                *pending &= !signal_bit(signal);
                self.signal_origins.remove(&origin_key);
                true
            } else {
                false
            }
        };
        drop(publication);
        if published {
            self.remove_empty_signal_notification(sender.process_id);
        } else {
            // A previous interrupt may already have been acknowledged. Failed
            // reply publication must request another wake, even for one-shots.
            match candidate {
                Candidate::Ordinary { origin_key, .. } if origin_key.1 != 0 => {
                    self.thread_signal_notifications.insert(key);
                }
                _ => {
                    self.signal_notifications.insert(sender.process_id);
                }
            }
        }
        Ok(published.then_some(delivery))
    }
}
