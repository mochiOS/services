//! One-shot receive notifications. Native adapters must authenticate the socket
//! through an attached READ Handle and retain that reference for the job's life.
//! Registration and pumping run on the same worker as queue mutations.

use crate::socket::{MAX_DESCRIPTION_ID, MAX_ENDPOINTS, Streams};

const TAG: u64 = 1 << 61;

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

struct Job<H> {
    id: u64,
    socket: u64,
    source: H,
    minimum: u64,
    ready: bool,
}

pub struct ReceiveWaits<H> {
    next: u64,
    jobs: Vec<Job<H>>,
}

impl<H> Default for ReceiveWaits<H> {
    fn default() -> Self {
        Self::new()
    }
}

impl<H> ReceiveWaits<H> {
    pub const fn new() -> Self {
        Self {
            next: 1,
            jobs: Vec::new(),
        }
    }

    /// On success owns source; on error the adapter still owns it. No queue
    /// data is consumed. Evaluate before publication, including already-ready
    /// data arriving between the client's failed inspection and registration.
    pub fn start(
        &mut self,
        streams: &Streams,
        socket: u64,
        minimum: u64,
        source: H,
    ) -> Result<u64, i32> {
        let ready = streams.receive_wait_ready(socket, minimum)?;
        if self.jobs.len() == MAX_ENDPOINTS || self.next > MAX_DESCRIPTION_ID {
            return Err(-23);
        }
        self.jobs.try_reserve(1).map_err(|_| -12)?;
        let id = self.next;
        self.next += 1;
        self.jobs.push(Job {
            id,
            socket,
            source,
            minimum,
            ready,
        });
        Ok(id)
    }

    pub fn ready(&self, id: u64) -> Result<bool, i32> {
        self.jobs
            .iter()
            .find(|job| job.id == id)
            .map(|job| job.ready)
            .ok_or(-9)
    }

    /// Readiness is latched: another reader consuming the data cannot revoke
    /// a notification. The client retries its inspection after waking. Ready
    /// callbacks are repeatable so publication can signal an already-ready job.
    pub fn pump(&mut self, streams: &Streams, mut signal: impl FnMut(u64)) {
        for job in &mut self.jobs {
            job.ready |= streams
                .receive_wait_ready(job.socket, job.minimum)
                .unwrap_or(true);
            if job.ready {
                signal(job.id);
            }
        }
    }

    /// Final notification-Handle release cancels only this registration. It
    /// never changes the socket's queue, shared flags or shutdown state.
    pub fn release(&mut self, id: u64, close: impl FnOnce(H)) -> Result<(), i32> {
        let index = self.jobs.iter().position(|job| job.id == id).ok_or(-9)?;
        close(self.jobs.swap_remove(index).source);
        Ok(())
    }

    pub fn handle_provider_request(
        &mut self,
        request: &[u8],
        flags: u32,
        attachments: u32,
        close: impl FnOnce(H),
    ) -> Result<Option<usize>, i32> {
        let (header, _) = mnu_abi::provider::RequestHeader::decode(request).map_err(|_| -22)?;
        if flags != mnu_abi::IPC_DELIVERY_NATIVE_OBJECT {
            return Err(-13);
        }
        if attachments != 0 {
            return Err(-22);
        }
        if header.opcode != mnu_abi::provider::OP_RELEASE {
            return Err(-95);
        }
        self.release(job_id(header.object_id)?, close)?;
        Ok(None)
    }
}
