//! Provider-worker connection jobs. A backlog wait owns the authorized target
//! and never holds up dispatch of accept/release. IDs are private: native
//! adapters must expose jobs only through explicitly delegated Handles.

use crate::{
    socket::{MAX_ENDPOINTS, Streams},
    socket_binding::{Bindings, ConnectTarget, Filesystem},
};

type Connection = Result<(u64, u64), i32>;

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
                if self.jobs.len() == MAX_ENDPOINTS || self.next > i64::MAX as u64 {
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
}
