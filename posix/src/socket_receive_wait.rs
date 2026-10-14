//! One-shot socket notifications. Native adapters authenticate receive waits
//! through a READ Handle and record/ancillary-stream send waits through WRITE,
//! retaining that reference for the job's life.
//! Registration and pumping run on the same worker as queue mutations.

use crate::socket::{Streams, MAX_DESCRIPTION_ID, MAX_ENDPOINTS};

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
    condition: Condition,
    ready: bool,
}

#[derive(Clone, Copy)]
enum Condition {
    Receive(u64),
    SendRecord(usize),
}
impl Condition {
    fn ready(self, streams: &Streams, socket: u64) -> Result<bool, i32> {
        match self {
            Self::Receive(minimum) => streams.receive_wait_ready(socket, minimum),
            Self::SendRecord(length) => streams.ancillary_send_ready(socket, length),
        }
    }
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
        self.start_condition(streams, socket, Condition::Receive(minimum), source)
    }

    /// Source is an explicitly delegated WRITE lease, retained until final job
    /// release. No allocation or readiness registration lives on a client FD.
    pub fn start_send(
        &mut self,
        streams: &Streams,
        socket: u64,
        length: usize,
        source: H,
    ) -> Result<u64, i32> {
        self.start_condition(streams, socket, Condition::SendRecord(length), source)
    }

    fn start_condition(
        &mut self,
        streams: &Streams,
        socket: u64,
        condition: Condition,
        source: H,
    ) -> Result<u64, i32> {
        let ready = condition.ready(streams, socket)?;
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
            condition,
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
            job.ready |= job.condition.ready(streams, job.socket).unwrap_or(true);
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
