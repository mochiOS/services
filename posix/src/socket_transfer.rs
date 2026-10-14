//! Staging transactions addressed by kernel-identified Provider Handles only.
use crate::{
    socket::{MAX_DESCRIPTION_ID, MAX_ENDPOINTS, Streams},
    socket_rights::{Budget, Bundle, Lease, Pending},
};
use mochios_posix_protocol::socket_transfer as wire;
const TAG: u64 = 1 << 59;
pub fn object_id(id: u64) -> Result<u64, i32> {
    if id == 0 || id > MAX_DESCRIPTION_ID {
        Err(-9)
    } else {
        Ok(TAG | id)
    }
}
pub fn job_id(object: u64) -> Result<u64, i32> {
    let id = object & MAX_DESCRIPTION_ID;
    if object & !MAX_DESCRIPTION_ID != TAG || id == 0 {
        Err(-9)
    } else {
        Ok(id)
    }
}
enum State {
    Collecting(Pending),
    Ready(Bundle),
    Complete,
}
impl State {
    fn received(&self) -> Result<usize, i32> {
        match self {
            Self::Collecting(pending) => Ok(pending.received()),
            Self::Ready(bundle) => Ok(bundle.len()),
            Self::Complete => Err(-114),
        }
    }
}
struct Stage {
    id: u64,
    socket: u64,
    source: u32,
    length: u32,
    state: State,
    close: fn(u32),
}
impl Drop for Stage {
    fn drop(&mut self) {
        (self.close)(self.source);
    }
}
pub struct Transfers {
    next: u64,
    entries: Vec<Stage>,
    budget: Budget,
}
impl Transfers {
    pub fn new(reference_limit: usize) -> Self {
        Self {
            next: 1,
            entries: Vec::new(),
            budget: Budget::new(reference_limit),
        }
    }
    /// The adapter identified socket from the attached WRITE lease. Success
    /// adopts source; failure leaves source cleanup to that adapter.
    pub fn start(
        &mut self,
        streams: &Streams,
        socket: u64,
        source: u32,
        length: u32,
        count: u16,
        close: fn(u32),
    ) -> Result<u64, i32> {
        wire::begin(length, count).map_err(|_| -22)?;
        if source == 0 {
            return Err(-9);
        }
        let kind = streams.kind(socket)?;
        if kind == mochios_posix_protocol::socket::Kind::Datagram
            && length as usize > crate::socket_record::MAX_RECORD_SIZE
        {
            return Err(-90);
        }
        if self.entries.len() == MAX_ENDPOINTS || self.next > MAX_DESCRIPTION_ID {
            return Err(-23);
        }
        let pending = Pending::new(count as usize, &self.budget)?;
        self.entries.try_reserve(1).map_err(|_| -12)?;
        let id = self.next;
        self.next += 1;
        self.entries.push(Stage {
            id,
            socket,
            source,
            length,
            state: State::Collecting(pending),
            close,
        });
        Ok(id)
    }
    pub fn append(&mut self, id: u64, offset: usize, leases: Vec<Lease>) -> Result<usize, i32> {
        let stage = self
            .entries
            .iter_mut()
            .find(|stage| stage.id == id)
            .ok_or(-9)?;
        match &mut stage.state {
            State::Collecting(pending) => {
                pending.append(offset, leases)?;
                Ok(pending.received())
            }
            State::Ready(_) => Err(-22),
            State::Complete => Err(-114),
        }
    }
    pub fn progress(&self, id: u64) -> Result<(u64, u32, usize), i32> {
        let stage = self.entries.iter().find(|stage| stage.id == id).ok_or(-9)?;
        Ok((stage.socket, stage.length, stage.state.received()?))
    }

    /// Connected datagram commitment, serialized with cycle collection.
    /// Every fallible RAM check/copy precedes the ownership move; queue errors
    /// restore the full ready bundle. A successful send stays Complete even if
    /// its reply is lost, so repeating the same transaction cannot send twice.
    pub fn commit(
        &mut self,
        streams: &mut Streams,
        id: u64,
        offset: u64,
        buffer: &mut impl crate::socket_record_io::RecordBuffer,
    ) -> Result<(usize, [u64; 2]), i32> {
        let stage = self
            .entries
            .iter_mut()
            .find(|stage| stage.id == id)
            .ok_or(-9)?;
        match &stage.state {
            State::Complete => return Err(-114),
            State::Collecting(pending) if !pending.is_complete() => return Err(-22),
            _ => (),
        }
        if streams.kind(stage.socket)? != mochios_posix_protocol::socket::Kind::Datagram {
            return Err(-95);
        }
        let end = offset.checked_add(u64::from(stage.length)).ok_or(-22)?;
        if end > buffer.extent()? {
            return Err(-22);
        }
        if !streams.record_send_ready(stage.socket, stage.length as usize)? {
            return Err(-11);
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(stage.length as usize)
            .map_err(|_| -12)?;
        bytes.resize(stage.length as usize, 0);
        buffer.read(offset, &mut bytes)?;
        let bundle = match std::mem::replace(&mut stage.state, State::Complete) {
            State::Ready(bundle) => bundle,
            State::Collecting(pending) => match pending.finish() {
                Ok(bundle) => bundle,
                Err(pending) => {
                    stage.state = State::Collecting(pending);
                    return Err(-22);
                }
            },
            State::Complete => return Err(-114),
        };
        match streams.commit_record_with_rights(stage.socket, &bytes, bundle) {
            Ok(result) => Ok(result),
            Err((error, bundle)) => {
                stage.state = State::Ready(bundle);
                Err(error)
            }
        }
    }
    pub fn release(&mut self, id: u64) -> Result<(), i32> {
        let index = self
            .entries
            .iter()
            .position(|stage| stage.id == id)
            .ok_or(-9)?;
        self.entries.swap_remove(index);
        Ok(())
    }
    pub fn reserved_references(&self) -> usize {
        self.budget.used()
    }
}
