//! Per-call sendto authority: retained source WRITE lease plus resolved target
//! inode. A route is not a writable socket and cannot impersonate its target.
use crate::{
    socket::{MAX_DESCRIPTION_ID, MAX_ENDPOINTS, Streams},
    socket_binding::DatagramTarget,
    socket_record_io::RecordBuffer,
};
use mochios_posix_protocol::socket_record::{MAX_RECORD_SIZE, Operation, Request};

const TAG: u64 = 1 << 60;
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
pub fn is_route(object: u64) -> bool {
    object & TAG != 0
}

struct Route<H> {
    id: u64,
    source: H,
    target: DatagramTarget<H>,
    length: usize,
    complete: bool,
}
pub struct Routes<H> {
    next: u64,
    entries: Vec<Route<H>>,
}
impl<H> Default for Routes<H> {
    fn default() -> Self {
        Self::new()
    }
}
impl<H> Routes<H> {
    pub const fn new() -> Self {
        Self {
            next: 1,
            entries: Vec::new(),
        }
    }

    /// Success owns both target and source. Failure returns the target to its
    /// caller and leaves source ownership there as well. No send occurs here.
    pub fn start(
        &mut self,
        streams: &Streams,
        target: DatagramTarget<H>,
        length: usize,
        source: H,
    ) -> Result<u64, (i32, DatagramTarget<H>)> {
        let result = (|| {
            if length > MAX_RECORD_SIZE {
                return Err(-90);
            }
            streams.record_send_to_ready(target.client(), target.socket(), length)?;
            if self.entries.len() == MAX_ENDPOINTS || self.next > MAX_DESCRIPTION_ID {
                return Err(-23);
            }
            self.entries.try_reserve(1).map_err(|_| -12)?;
            Ok(())
        })();
        if let Err(error) = result {
            return Err((error, target));
        }
        let id = self.next;
        self.next += 1;
        self.entries.push(Route {
            id,
            source,
            target,
            length,
            complete: false,
        });
        Ok(id)
    }

    pub fn transfer(
        &mut self,
        streams: &mut Streams,
        id: u64,
        request: Request,
        buffer: &mut impl RecordBuffer,
        response: &mut [u8],
    ) -> Result<(usize, [u64; 2]), i32> {
        let route = self
            .entries
            .iter_mut()
            .find(|route| route.id == id)
            .ok_or(-9)?;
        request.validate().map_err(|_| -22)?;
        if request.operation != Operation::SendRoute || request.length as usize != route.length {
            return Err(-22);
        }
        if route.complete {
            return Err(-114);
        }
        let count = streams.transfer_record_to(
            route.target.client(),
            route.target.socket(),
            request,
            route.target.source(),
            buffer,
            response,
        )?;
        // Exactly one commitment even if a client loses the success reply.
        route.complete = true;
        Ok((count, [route.target.client(), route.target.socket()]))
    }

    /// Only the adapter's kernel-identified route Handle may select this row.
    /// Source/target identities are internal and never accepted from wire data.
    pub fn source(&self, id: u64, length: usize) -> Result<u64, i32> {
        let route = self.entries.iter().find(|route| route.id == id).ok_or(-9)?;
        if route.complete {
            return Err(-114);
        }
        if route.length != length {
            return Err(-22);
        }
        Ok(route.target.client())
    }

    pub fn ready(&self, streams: &Streams, id: u64, length: usize) -> Result<bool, i32> {
        self.source(id, length)?;
        let route = self.entries.iter().find(|route| route.id == id).ok_or(-9)?;
        streams.record_send_to_ready(route.target.client(), route.target.socket(), length)
    }

    /// Exactly one payload+rights commitment per retained route, including when
    /// several staging jobs borrow it. Errors return all leases to their owner.
    pub fn transfer_rights(
        &mut self,
        streams: &mut Streams,
        id: u64,
        payload: &[u8],
        rights: crate::socket_rights::Bundle,
    ) -> Result<(usize, [u64; 2]), (i32, crate::socket_rights::Bundle)> {
        if let Err(error) = self.source(id, payload.len()) {
            return Err((error, rights));
        }
        let route = self
            .entries
            .iter_mut()
            .find(|route| route.id == id)
            .unwrap();
        let result = streams.commit_record_to_with_rights(
            route.target.client(),
            route.target.socket(),
            route.target.source(),
            payload,
            rights,
        );
        if result.is_ok() {
            route.complete = true;
        }
        result
    }

    /// Readiness is level-triggered for this complete message length, not for
    /// one byte of free space. Terminal results wake the client to obtain them.
    pub fn pump(&self, streams: &Streams, mut signal: impl FnMut(u64, bool)) {
        for route in &self.entries {
            let ready = route.complete
                || streams
                    .record_send_to_ready(
                        route.target.client(),
                        route.target.socket(),
                        route.length,
                    )
                    .unwrap_or(true);
            signal(route.id, ready);
        }
    }

    pub fn release(
        &mut self,
        id: u64,
        source_close: impl FnOnce(H),
        target_close: impl FnOnce(H),
    ) -> Result<(), i32> {
        let index = self
            .entries
            .iter()
            .position(|route| route.id == id)
            .ok_or(-9)?;
        let route = self.entries.swap_remove(index);
        source_close(route.source);
        route.target.release_with(target_close);
        Ok(())
    }
}
