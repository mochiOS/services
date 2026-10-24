//! One-shot FIFO waits owned by the same worker as channel mutations.
//!
//! The native adapter must identify an explicitly attached data Handle, check
//! its required READ/WRITE rights, and retain that Handle in `lease`. The local
//! object ID alone is not authority. Register and pump under the same exclusive
//! owner as open/read/write/release, after every mutation and before replying.
use crate::{
    fifo::WaitCondition,
    fifo_manager::{ChannelKey, MAX_DATA_OBJECT_ID, Manager},
};
use mnu_abi::provider;

pub const MAX_WAITS: usize = 1024;
const TAG: u64 = 1 << 62;

pub fn is_notification(object_id: u64) -> bool {
    object_id & !MAX_DATA_OBJECT_ID == TAG && object_id & MAX_DATA_OBJECT_ID != 0
}

struct Job<H> {
    id: u64,
    object: u64,
    channel: ChannelKey,
    condition: WaitCondition,
    ready: bool,
    // RAII owner of the received native data reference. Dup/transfer of the
    // notification shares this one lease until its final native OP_RELEASE.
    _lease: H,
}

pub struct Waits<H> {
    last_id: u64,
    jobs: Vec<Job<H>>,
}

impl<H> Default for Waits<H> {
    fn default() -> Self {
        Self {
            last_id: 0,
            jobs: Vec::new(),
        }
    }
}

pub struct Registered {
    pub object_id: u64,
    pub handle: u32,
    pub ready: bool,
}

impl<H> Waits<H> {
    pub fn is_empty(&self) -> bool {
        self.jobs.is_empty()
    }
    /// Takes ownership of lease on both success and failure. Its Drop must
    /// close a local reference without RPC. The adapter owns the returned
    /// notification Handle, sets its READABLE signal if ready, and transfers
    /// only WAIT/DUPLICATE/TRANSFER rights. On publication failure it must close
    /// that Handle: the resulting native release retires this job.
    /// `create` must close any partial native allocation before returning Err.
    pub fn register(
        &mut self,
        manager: &Manager,
        object: u64,
        condition: WaitCondition,
        lease: H,
        create: impl FnOnce(u64) -> Result<u32, i32>,
    ) -> Result<Registered, i32> {
        let (channel, ready) = manager.wait_target(object, condition)?;
        if self.jobs.len() == MAX_WAITS {
            return Err(-23);
        }
        self.jobs.try_reserve(1).map_err(|_| -12)?;
        let next = self
            .last_id
            .checked_add(1)
            .filter(|id| *id <= MAX_DATA_OBJECT_ID)
            .ok_or(-75)?;
        self.last_id = next; // Failed native creation must not recycle an ID.
        let id = TAG | next;
        let handle = create(id)?;
        if handle == 0 {
            return Err(-5);
        }
        self.jobs.push(Job {
            id,
            object,
            channel,
            condition,
            ready,
            _lease: lease,
        });
        Ok(Registered {
            object_id: id,
            handle,
            ready,
        })
    }

    pub fn ready(&self, id: u64) -> Result<bool, i32> {
        self.jobs
            .iter()
            .find(|job| job.id == id)
            .map(|job| job.ready)
            .ok_or(-9)
    }

    /// Inspect only waits for the mutated channel. Readiness latches until
    /// cancellation, even if another operation consumes the available bytes.
    /// A wake means retry; it never reserves bytes or grants a data operation.
    /// Failed signal delivery leaves the latch set for a later retry.
    pub fn pump(
        &mut self,
        manager: &Manager,
        changed: ChannelKey,
        mut signal: impl FnMut(u64) -> Result<(), i32>,
    ) -> Result<(), i32> {
        // Latch all transitions before invoking fallible native callbacks.
        for job in self.jobs.iter_mut().filter(|job| job.channel == changed) {
            if !job.ready {
                job.ready = manager.wait_target(job.object, job.condition)?.1;
            }
        }
        let mut failure = None;
        for job in self
            .jobs
            .iter()
            .filter(|job| job.channel == changed && job.ready)
        {
            if let Err(error) = signal(job.id) {
                failure.get_or_insert(error);
            }
        }
        failure.map_or(Ok(()), Err)
    }

    /// Only the native adapter's final notification release may cancel a job.
    /// This drops its source lease; it never directly closes the data object
    /// or modifies the queue. Native source OP_RELEASE follows if this was
    /// its last reference. Explicit abort before native publication also uses
    /// this operation, after closing any notification reference first.
    pub fn release(&mut self, id: u64) -> Result<(), i32> {
        let index = self.jobs.iter().position(|job| job.id == id).ok_or(-9)?;
        self.jobs.swap_remove(index);
        Ok(())
    }

    pub fn handle_provider_request(
        &mut self,
        request: &[u8],
        delivery: u32,
        attachments: u32,
    ) -> Result<(), i32> {
        let (header, _) = provider::RequestHeader::decode(request).map_err(|_| -22)?;
        if delivery != mnu_abi::IPC_DELIVERY_NATIVE_OBJECT {
            return Err(-13);
        }
        if attachments != 0 || !is_notification(header.object_id) {
            return Err(-22);
        }
        if header.opcode != provider::OP_RELEASE {
            return Err(-95);
        }
        self.release(header.object_id)
    }
}
