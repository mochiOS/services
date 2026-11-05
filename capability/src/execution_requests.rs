//! Bounded ownership of calls waiting for execution consent. No renderer wait
//! runs here; the service can receive other messages while these calls are held.
use alloc::vec::Vec;
use mochi_user_platform as p;
use p::capability::consent::{Correlation, Ticket};
use p::syscall::{HandleWaitItem, NativeError, SysError};

use crate::{
    consent::{Approval, Controller, InputRoute, MAX_PENDING, Offer, Presenter, Session},
    consent_peer::Peer,
    execution_approval::Pending,
};

fn error(error: NativeError) -> SysError {
    SysError::from_raw(error.into_raw() as i64)
}
fn consent_error(error_value: crate::consent::Error) -> SysError {
    use crate::consent::Error;
    error(match error_value {
        Error::Full | Error::Busy => NativeError::ResourceUnavailable,
        Error::Exhausted => NativeError::LimitExceeded,
        Error::ClockWentBack => NativeError::BackingFailure,
        Error::Invalid => NativeError::InvalidArgument,
        _ => NativeError::AccessDenied,
    })
}
fn same_ticket(a: Ticket, b: Ticket) -> bool {
    a.id == b.id
        && a.challenge
            .iter()
            .zip(b.challenge)
            .fold(0u8, |diff, (a, b)| diff | (a ^ b))
            == 0
}
pub(crate) struct Reply {
    pub target: u64,
    pub result: Result<(), SysError>,
}
struct Entry {
    offer: Offer,
    request: Pending,
    presenter: Presenter,
}
enum Slot {
    Reserved { target: u64, bytes: usize },
    Ready(Entry),
}
impl Slot {
    fn target(&self) -> u64 {
        match self {
            Self::Reserved { target, .. } => *target,
            Self::Ready(entry) => entry.request.binding().requester.endpoint,
        }
    }
}

pub(crate) struct Registry {
    slots: Vec<Option<Slot>>,
    bytes: usize,
    byte_limit: usize,
}
impl Registry {
    pub(crate) fn new() -> Result<Self, SysError> {
        Self::with_limits(MAX_PENDING, mnu_abi::exec::MAX_CAPTURED_IMAGE_BYTES)
    }
    pub(crate) fn with_limits(count: usize, bytes: usize) -> Result<Self, SysError> {
        if count == 0
            || count > MAX_PENDING
            || count >= mnu_abi::HANDLE_WAIT_MANY_MAX_ITEMS
            || bytes == 0
            || bytes > mnu_abi::exec::MAX_CAPTURED_IMAGE_BYTES
        {
            return Err(error(NativeError::InvalidArgument));
        }
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(count)
            .map_err(|_| error(NativeError::ResourceUnavailable))?;
        slots.resize_with(count, || None);
        Ok(Self {
            slots,
            bytes: 0,
            byte_limit: bytes,
        })
    }
    pub(crate) fn len(&self) -> usize {
        self.slots.iter().flatten().count()
    }
    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }
    pub(crate) fn reserve_image(
        &mut self,
        target: u64,
        length: u64,
    ) -> Result<Reservation<'_>, SysError> {
        let bytes = usize::try_from(length)
            .ok()
            .filter(|length| *length != 0 && *length <= mnu_abi::exec::MAX_CAPTURED_IMAGE_BYTES)
            .ok_or_else(|| error(NativeError::InvalidArgument))?;
        self.reserve(target, bytes)
    }
    pub(crate) fn reserve(
        &mut self,
        target: u64,
        bytes: usize,
    ) -> Result<Reservation<'_>, SysError> {
        if target == 0 || bytes == 0 {
            return Err(error(NativeError::InvalidArgument));
        }
        if self
            .slots
            .iter()
            .flatten()
            .any(|slot| slot.target() == target)
        {
            return Err(error(NativeError::AlreadyExists));
        }
        let total = self
            .bytes
            .checked_add(bytes)
            .filter(|total| *total <= self.byte_limit)
            .ok_or_else(|| error(NativeError::ResourceUnavailable))?;
        let index = self
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or_else(|| error(NativeError::ResourceUnavailable))?;
        self.slots[index] = Some(Slot::Reserved { target, bytes });
        self.bytes = total;
        Ok(Reservation {
            owner: self,
            index,
            active: true,
        })
    }
    fn index(&self, correlation: Correlation) -> Result<usize, SysError> {
        self.slots
            .iter()
            .position(|slot| {
                matches!(slot,Some(Slot::Ready(entry))
            if entry.offer.correlation.display==correlation.display
                && same_ticket(entry.offer.correlation.ticket,correlation.ticket))
            })
            .ok_or_else(|| error(NativeError::NotFound))
    }
    pub(crate) fn contains(&self, correlation: Correlation) -> bool {
        self.index(correlation).is_ok()
    }
    fn release(&mut self, bytes: usize) {
        self.bytes = self
            .bytes
            .checked_sub(bytes)
            .expect("execution retention accounting");
    }
    /// The adapter must capture this peer from the IPC sender. A ticket alone
    /// does not disclose another presenter's source or requested permissions.
    pub(crate) fn write_prompt(
        &self,
        correlation: Correlation,
        presenter: crate::consent::Instance,
        now: u64,
        output: &mut [u8],
    ) -> Result<usize, SysError> {
        let index = self.index(correlation)?;
        let Some(Slot::Ready(entry)) = &self.slots[index] else {
            unreachable!()
        };
        if presenter != entry.presenter.instance || now >= entry.offer.deadline {
            return Err(error(NativeError::AccessDenied));
        }
        entry.request.write_prompt(entry.offer, output)
    }
    fn retire(&mut self, index: usize, controller: &mut Controller, reason: SysError) -> Reply {
        let slot = self.slots[index].take().expect("owned execution slot");
        let target = slot.target();
        let bytes = match &slot {
            Slot::Reserved { bytes, .. } => *bytes,
            Slot::Ready(entry) => {
                let _ =
                    controller.cancel(entry.request.binding().requester, entry.offer.correlation);
                entry.request.source_len()
            }
        };
        drop(slot);
        self.release(bytes);
        Reply {
            target,
            result: Err(reason),
        }
    }
    pub(crate) fn cancel(
        &mut self,
        controller: &mut Controller,
        correlation: Correlation,
        reason: NativeError,
    ) -> Result<Reply, SysError> {
        let index = self.index(correlation)?;
        Ok(self.retire(index, controller, error(reason)))
    }
    pub(crate) fn cancel_all(
        &mut self,
        controller: &mut Controller,
        reason: NativeError,
        emit: impl FnMut(Reply),
    ) {
        self.abort(controller, error(reason), emit);
    }
    pub(crate) fn abort(
        &mut self,
        controller: &mut Controller,
        reason: SysError,
        mut emit: impl FnMut(Reply),
    ) {
        for index in 0..self.slots.len() {
            if self.slots[index].is_some() {
                emit(self.retire(index, controller, reason));
            }
        }
    }
    pub(crate) fn invalidate_policy(
        &mut self,
        controller: &mut Controller,
        generation: u64,
        mut emit: impl FnMut(Reply),
    ) {
        for index in 0..self.slots.len() {
            if matches!(&self.slots[index], Some(Slot::Ready(entry))
                if entry.request.binding().policy_generation != generation)
            {
                emit(self.retire(index, controller, error(NativeError::AccessDenied)));
            }
        }
    }
    pub(crate) fn expire(
        &mut self,
        controller: &mut Controller,
        now: u64,
        mut emit: impl FnMut(Reply),
    ) -> Result<(), SysError> {
        // Other request owners retain responsibility for their own deadlines.
        controller
            .observe_time(now)
            .map_err(|_| error(NativeError::BackingFailure))?;
        for index in 0..self.slots.len() {
            if matches!(&self.slots[index],Some(Slot::Ready(entry)) if now>=entry.offer.deadline) {
                emit(self.retire(index, controller, error(NativeError::AccessDenied)));
            }
        }
        Ok(())
    }
    pub(crate) fn reap(
        &mut self,
        controller: &mut Controller,
        mut exited: impl FnMut(u32) -> Result<bool, SysError>,
        mut emit: impl FnMut(Reply),
    ) {
        for index in 0..self.slots.len() {
            let observed = match &self.slots[index] {
                Some(Slot::Ready(entry)) => exited(entry.request.process_handle()),
                _ => continue,
            };
            match observed {
                Ok(false) => {}
                Ok(true) => emit(self.retire(index, controller, error(NativeError::PeerClosed))),
                Err(reason) => emit(self.retire(index, controller, reason)),
            }
        }
    }
    pub(crate) fn finish(
        &mut self,
        controller: &mut Controller,
        correlation: Correlation,
        approval: Approval,
        current: &Peer,
        session: Session,
        policy_generation: u64,
        now: u64,
    ) -> Result<Reply, SysError> {
        controller
            .observe_time(now)
            .map_err(|_| error(NativeError::BackingFailure))?;
        let index = self.index(correlation)?;
        if approval.correlation() != correlation {
            return Err(error(NativeError::AccessDenied));
        }
        let Some(Slot::Ready(entry)) = self.slots[index].take() else {
            unreachable!()
        };
        let bytes = entry.request.source_len();
        let target = entry.request.binding().requester.endpoint;
        let result = if now >= entry.offer.deadline {
            drop(entry.request);
            Err(error(NativeError::AccessDenied))
        } else {
            entry
                .request
                .complete(approval, current, session, policy_generation)
        };
        self.release(bytes);
        Ok(Reply { target, result })
    }
    pub(crate) fn next_deadline(&self) -> Option<u64> {
        self.slots
            .iter()
            .filter_map(|slot| match slot {
                Some(Slot::Ready(entry)) => Some(entry.offer.deadline),
                _ => None,
            })
            .min()
    }
    /// The caller receives no owned Pending; all retention charges stay live
    /// until completion/cancellation has actually released the source bytes.
    pub(crate) fn wait_items(
        &self,
        endpoint: u32,
        output: &mut [HandleWaitItem],
    ) -> Result<usize, SysError> {
        if endpoint == 0 || output.len() < self.len() + 1 {
            return Err(error(NativeError::InvalidArgument));
        }
        output[0] = HandleWaitItem {
            handle: endpoint,
            interests: mnu_abi::HANDLE_SIGNAL_READABLE,
            ..Default::default()
        };
        let mut count = 1;
        for slot in &self.slots {
            if let Some(Slot::Ready(entry)) = slot {
                output[count] = HandleWaitItem {
                    handle: entry.request.process_handle(),
                    interests: mnu_abi::HANDLE_SIGNAL_TERMINATED,
                    ..Default::default()
                };
                count += 1;
            }
        }
        Ok(count)
    }
}

pub(crate) struct Reservation<'a> {
    owner: &'a mut Registry,
    index: usize,
    active: bool,
}
impl Reservation<'_> {
    pub(crate) fn begin(
        mut self,
        controller: &mut Controller,
        request: Pending,
        correlation: Correlation,
        presenter: Presenter,
        input: InputRoute,
        now: u64,
        timeout: u64,
    ) -> Result<Offer, SysError> {
        let Some(Slot::Reserved { target, bytes }) = &self.owner.slots[self.index] else {
            unreachable!()
        };
        if *target != request.binding().requester.endpoint || *bytes != request.source_len() {
            return Err(error(NativeError::InvalidArgument));
        }
        let offer = controller
            .begin_at(
                correlation,
                request.binding(),
                presenter,
                input,
                request.choices(),
                now,
                timeout,
            )
            .map_err(consent_error)?;
        self.owner.slots[self.index] = Some(Slot::Ready(Entry {
            offer,
            request,
            presenter,
        }));
        self.active = false;
        Ok(offer)
    }
}
impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        if self.active {
            let Some(Slot::Reserved { bytes, .. }) = self.owner.slots[self.index].take() else {
                unreachable!()
            };
            self.owner.release(bytes);
        }
    }
}
