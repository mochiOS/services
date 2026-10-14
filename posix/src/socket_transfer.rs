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
    Received {
        rights: Option<Bundle>,
        info: ReceiptInfo,
        delivered: usize,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceiptInfo {
    pub record: crate::socket_record::ReceivedRecord,
    pub total_rights: usize,
    pub available_rights: usize,
}
impl State {
    fn received(&self) -> Result<usize, i32> {
        match self {
            Self::Collecting(pending) => Ok(pending.received()),
            Self::Ready(bundle) => Ok(bundle.len()),
            Self::Complete => Err(-114),
            Self::Received { .. } => Err(-95),
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
    route: Option<u64>,
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
            route: None,
        });
        Ok(id)
    }

    /// The owned source is a WRITE lease to the route, retaining both its
    /// source socket and authorized target inode until this stage is dropped.
    pub fn start_route<H>(
        &mut self,
        streams: &Streams,
        routes: &crate::socket_route::Routes<H>,
        route: u64,
        source: u32,
        length: u32,
        count: u16,
        close: fn(u32),
    ) -> Result<u64, i32> {
        let socket = routes.source(route, length as usize)?;
        let id = self.start(streams, socket, source, length, count, close)?;
        self.entries.last_mut().unwrap().route = Some(route);
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
            State::Received { .. } => Err(-95),
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
        self.commit_using::<()>(streams, None, id, offset, buffer)
    }

    pub fn commit_with_routes<H>(
        &mut self,
        streams: &mut Streams,
        routes: &mut crate::socket_route::Routes<H>,
        id: u64,
        offset: u64,
        buffer: &mut impl crate::socket_record_io::RecordBuffer,
    ) -> Result<(usize, [u64; 2]), i32> {
        self.commit_using(streams, Some(routes), id, offset, buffer)
    }

    fn commit_using<H>(
        &mut self,
        streams: &mut Streams,
        mut routes: Option<&mut crate::socket_route::Routes<H>>,
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
            State::Received { .. } => return Err(-95),
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
        let ready = match stage.route {
            Some(route) => {
                routes
                    .as_deref()
                    .ok_or(-95)?
                    .ready(streams, route, stage.length as usize)?
            }
            None => streams.record_send_ready(stage.socket, stage.length as usize)?,
        };
        if !ready {
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
            state @ State::Complete => {
                stage.state = state;
                return Err(-114);
            }
            state @ State::Received { .. } => {
                stage.state = state;
                return Err(-95);
            }
        };
        let result = match stage.route {
            Some(route) => routes
                .as_deref_mut()
                .unwrap()
                .transfer_rights(streams, route, &bytes, bundle),
            None => streams.commit_record_with_rights(stage.socket, &bytes, bundle),
        };
        match result {
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
    /// The adapter supplies a kernel-identified READ lease. Publication receives
    /// a private ID only to mint a native receipt Handle, never to serialize it.
    /// On failure source stays owned by the adapter. On success ONLY Some(id)
    /// adopts source. No-rights receives therefore need no persistent receipt.
    pub fn receive(
        &mut self,
        streams: &mut Streams,
        socket: u64,
        source: u32,
        offset: u64,
        length: u32,
        maximum_rights: usize,
        close: fn(u32),
        mut publish: impl FnMut(Option<u64>, ReceiptInfo) -> Result<(), i32>,
        buffer: &mut impl crate::socket_record_io::RecordBuffer,
    ) -> Result<(ReceiptInfo, Option<u64>), i32> {
        if source == 0 {
            return Err(-9);
        }
        if maximum_rights > mochios_posix_protocol::socket::MAX_TRANSFERRED_DESCRIPTORS {
            return Err(-22);
        }
        let mut receipt_id = None;
        let (record, mut rights) = streams.receive_record_with_rights(
            socket,
            offset,
            length,
            buffer,
            |record, total_rights| {
                let available_rights = maximum_rights.min(total_rights);
                if available_rights != 0 {
                    if self.entries.len() == MAX_ENDPOINTS || self.next > MAX_DESCRIPTION_ID {
                        return Err(-23);
                    }
                    self.entries.try_reserve(1).map_err(|_| -12)?;
                    receipt_id = Some(self.next);
                    // Never reuse a minted ID after failed publication: closing a
                    // failed native Handle may enqueue a delayed OP_RELEASE.
                    self.next += 1;
                }
                publish(
                    receipt_id,
                    ReceiptInfo {
                        record,
                        total_rights,
                        available_rights,
                    },
                )
            },
        )?;
        let total_rights = rights.as_ref().map_or(0, |bundle| bundle.len());
        let info = ReceiptInfo {
            record,
            total_rights,
            available_rights: maximum_rights.min(total_rights),
        };
        if let Some(bundle) = &mut rights {
            bundle.truncate(maximum_rights);
        }
        if let Some(id) = receipt_id {
            self.entries.push(Stage {
                id,
                socket,
                source,
                length,
                close,
                route: None,
                state: State::Received {
                    rights,
                    info,
                    delivered: 0,
                },
            });
        }
        Ok((info, receipt_id))
    }

    /// Reply acquires independent references before service leases are closed.
    /// Failed replies retain all references and leave the cursor unchanged.
    /// The caller must abort, not blindly retry an ambiguous transport failure.
    pub fn deliver(
        &mut self,
        id: u64,
        offset: usize,
        maximum: usize,
        reply: impl FnOnce(&[Lease]) -> Result<(), i32>,
    ) -> Result<usize, i32> {
        if maximum == 0 || maximum > mnu_abi::IPC_MAX_OBJECT_HANDLES {
            return Err(-22);
        }
        let stage = self
            .entries
            .iter_mut()
            .find(|stage| stage.id == id)
            .ok_or(-9)?;
        let State::Received {
            rights,
            info,
            delivered,
        } = &mut stage.state
        else {
            return Err(-95);
        };
        if offset != *delivered {
            return Err(-22);
        }
        if *delivered == info.available_rights {
            return Err(-61);
        }
        let bundle = rights.as_mut().ok_or(-5)?;
        let count = maximum.min(bundle.len());
        reply(&bundle.leases()[..count])?;
        bundle.discard_delivered_prefix(count)?;
        *delivered += count;
        Ok(count)
    }
    pub fn reserved_references(&self) -> usize {
        self.budget.used()
    }
}
