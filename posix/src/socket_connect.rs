//! Provider-worker connection jobs. A backlog wait owns the authorized target
//! and never holds up dispatch of accept/release. IDs are private: native
//! adapters must expose jobs only through explicitly delegated Handles.

use crate::{
    socket::{MAX_DESCRIPTION_ID, MAX_ENDPOINTS, Streams},
    socket_binding::{Bindings, ConnectTarget, Filesystem},
};

type Connection = Result<(u64, u64), i32>;

pub const JOB_OBJECT_TAG: u64 = 1 << 62;

pub fn object_id(job: u64) -> Result<u64, i32> {
    if job == 0 || job > MAX_DESCRIPTION_ID {
        Err(-9)
    } else {
        Ok(JOB_OBJECT_TAG | job)
    }
}

pub fn job_id(object: u64) -> Result<u64, i32> {
    if object & JOB_OBJECT_TAG == 0 || object & !(JOB_OBJECT_TAG | MAX_DESCRIPTION_ID) != 0 {
        return Err(-9);
    }
    let job = object & MAX_DESCRIPTION_ID;
    if job == 0 { Err(-9) } else { Ok(job) }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Started {
    Connected { listener: u64, accepted: u64 },
    Waiting { job: u64 },
}

struct Job<H> {
    id: u64,
    client: u64,
    target: Option<ConnectTarget<H>>,
    result: Option<Connection>,
}

pub struct Connections<H> {
    next: u64,
    jobs: Vec<Job<H>>,
}

impl<H: Copy + Default + Eq> Default for Connections<H> {
    fn default() -> Self {
        Self::new()
    }
}

impl<H: Copy + Default + Eq> Connections<H> {
    pub const fn new() -> Self {
        Self {
            next: 1,
            jobs: Vec::new(),
        }
    }

    pub fn is_pending(&self, client: u64) -> bool {
        self.jobs
            .iter()
            .any(|job| job.client == client && job.target.is_some())
    }

    /// The adapter must authenticate client through its socket Handle before
    /// this call; no client-supplied object ID is authority. Reserve storage
    /// before lookup/publication and reject duplicate in-flight connections.
    pub fn start<B: Filesystem<H>>(
        &mut self,
        streams: &mut Streams,
        bindings: &Bindings<H>,
        client: u64,
        path: &[u8],
        nonblocking: bool,
        backend: &mut B,
    ) -> Result<Started, i32> {
        streams.check_connect(client)?;
        if self.is_pending(client) {
            return Err(-114);
        }
        if !nonblocking {
            self.jobs.try_reserve(1).map_err(|_| -12)?;
        }
        let target = bindings.prepare_connect(streams, client, path, backend)?;
        match bindings.try_connect(streams, &target) {
            Ok((listener, accepted)) => {
                target.release_with(|handle| backend.close(handle));
                Ok(Started::Connected { listener, accepted })
            }
            Err(-11) if !nonblocking => {
                if self.jobs.len() == MAX_ENDPOINTS || self.next > MAX_DESCRIPTION_ID {
                    target.release_with(|handle| backend.close(handle));
                    return Err(-23);
                }
                let id = self.next;
                self.next += 1;
                self.jobs.push(Job {
                    id,
                    client,
                    target: Some(target),
                    result: None,
                });
                Ok(Started::Waiting { job: id })
            }
            Err(error) => {
                target.release_with(|handle| backend.close(handle));
                Err(error)
            }
        }
    }

    /// Run after accept, backlog changes, or final socket release. FIFO within
    /// a listener; a full listener does not stall jobs for other listeners.
    /// Callbacks run only once per completed job, after retiring its FS lease.
    pub fn pump(
        &mut self,
        streams: &mut Streams,
        bindings: &Bindings<H>,
        mut close: impl FnMut(H),
        mut completed: impl FnMut(u64, u64, Connection),
    ) {
        for job in &mut self.jobs {
            let Some(target) = job.target.as_ref() else {
                continue;
            };
            let result = bindings.try_connect(streams, target);
            if result == Err(-11) {
                continue;
            }
            if let Some(target) = job.target.take() {
                target.release_with(&mut close);
            }
            job.result = Some(result);
            completed(job.id, job.client, result);
        }
    }

    pub fn status(&self, id: u64) -> Result<Option<Connection>, i32> {
        self.jobs
            .iter()
            .find(|job| job.id == id)
            .map(|job| job.result)
            .ok_or(-9)
    }

    pub fn client(&self, id: u64) -> Result<u64, i32> {
        self.jobs
            .iter()
            .find(|job| job.id == id)
            .map(|job| job.client)
            .ok_or(-9)
    }

    /// Serialized with pump: a committed result wins the deadline race. If
    /// still pending, retire its lease exactly once before reporting timeout.
    pub fn expire(&mut self, id: u64, close: impl FnOnce(H)) -> Result<(), i32> {
        let job = self.jobs.iter_mut().find(|job| job.id == id).ok_or(-9)?;
        if let Some(result) = job.result {
            return result.map(|_| ());
        }
        if let Some(target) = job.target.take() {
            target.release_with(close);
        }
        job.result = Some(Err(-110));
        Err(-110)
    }

    /// Final job-Handle release cancels a pending connection without changing
    /// the socket. A completed connection is already committed: releasing its
    /// notification object must not tear down the connected socket.
    pub fn release(&mut self, id: u64, close: impl FnOnce(H)) -> Result<(), i32> {
        let index = self.jobs.iter().position(|job| job.id == id).ok_or(-9)?;
        let job = self.jobs.remove(index);
        if let Some(target) = job.target {
            target.release_with(close);
        }
        Ok(())
    }

    /// A native job Handle authorizes result queries and final release. Never
    /// trust an object ID in ordinary endpoint IPC, even with matching bytes.
    pub fn handle_provider_request(
        &mut self,
        request: &[u8],
        delivery_flags: u32,
        attachment_count: u32,
        response: &mut [u8],
        close: impl FnOnce(H),
    ) -> Result<Option<usize>, i32> {
        use mnu_abi::provider;
        let (header, payload) = provider::RequestHeader::decode(request).map_err(|_| -22)?;
        let authorized =
            delivery_flags == mnu_abi::IPC_DELIVERY_NATIVE_OBJECT && attachment_count == 0;
        if authorized && header.opcode == provider::OP_RELEASE {
            self.release(job_id(header.object_id)?, close)?;
            return Ok(None);
        }
        // Queries have no reply data. Validate capacity before any effects.
        if response.len() < provider::RESPONSE_HEADER_LEN {
            return Err(-22);
        }
        let result = if delivery_flags != mnu_abi::IPC_DELIVERY_NATIVE_OBJECT {
            Err(-13)
        } else if attachment_count != 0 {
            Err(-22)
        } else if header.opcode == provider::OP_CONTROL
            && matches!(
                header.basis,
                mochios_posix_protocol::socket::CONTROL_CONNECT_RESULT
                    | mochios_posix_protocol::socket::CONTROL_CONNECT_EXPIRE
            )
        {
            if header.length != 0 || !payload.is_empty() {
                Err(-22)
            } else if header.basis == mochios_posix_protocol::socket::CONTROL_CONNECT_EXPIRE {
                job_id(header.object_id).and_then(|id| self.expire(id, close))
            } else {
                job_id(header.object_id)
                    .and_then(|id| self.status(id))
                    .and_then(|result| result.unwrap_or(Err(-11)))
                    .map(|_| ())
            }
        } else {
            Err(-95)
        };
        provider::ResponseHeader {
            opcode: header.opcode,
            object_id: header.object_id,
            status: result.err().map_or(0, i64::from),
            value: 0,
            data_length: 0,
        }
        .encode(&[], response)
        .map(Some)
        .map_err(|_| -5)
    }
}
