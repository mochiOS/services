//! Service-side process CPU sleeps. The native adapter owns completion
//! channels; neither POSIX signals nor client polling are used as wakeups.
use super::*;
use process_timer::Clock;
use process_timer_request::{ClockBackend, Reading};

pub const MAX_WAITS_PER_PROCESS: usize = 128;
pub const MAX_WAITS: usize = 4096;

/// A dedicated completion endpoint, never an application FD or signal slot.
/// Implementations own their endpoint and close it on Drop. All operations
/// must be nonblocking and must not call providers or application code.
pub trait Completion {
    fn peer_closed(&mut self) -> Result<bool, i32>;
    /// True means the entire terminal result was published, false means no
    /// bytes were published and a later reactor sweep may retry it.
    fn publish(&mut self, result: Result<(), i32>) -> Result<bool, i32>;
}

#[derive(Clone, Copy)]
enum Subject {
    Process(u64),
    Thread(u64),
}

struct Wait<C> {
    owner: PeerIdentity,
    image: RequestImage,
    subject: Subject,
    deadline: u128,
    result: Option<Result<(), i32>>,
    completion: C,
}

/// Owned by the serialized service dispatcher. Entries are installed only
/// after successful reply publication. Dropping the registry releases all
/// endpoints, including during failed startup or service shutdown.
pub struct Registry<C> {
    waits: Vec<Wait<C>>,
}

impl<C: Completion> Default for Registry<C> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: Completion> Registry<C> {
    /// Select a thread only through a borrowed explicit WAIT attachment.
    /// Sender identity is native endpoint metadata, never request payload.
    pub fn begin_thread_request_with_reply<H: Copy, B: ClockBackend<H>>(
        &mut self,
        service: &mut PosixService<H>,
        peer: PeerIdentity,
        image: RequestImage,
        sender: Option<mnu_abi::ExecutionIdentity>,
        header: protocol::Header,
        payload: &[u8],
        attachments: &[AttachedObject<H>],
        completion: C,
        backend: &mut B,
        reply: impl FnOnce(u128) -> bool,
    ) -> Result<bool, i32> {
        if header.opcode != protocol::OP_THREAD_CPU_SLEEP {
            return Err(protocol::STATUS_ENOSYS);
        }
        if header.flags != 0
            || header.status != 0
            || header.payload_len as usize != payload.len()
            || attachments.len() != 1
            || attachments[0].rights != mnu_abi::HANDLE_RIGHT_WAIT
        {
            return Err(STATUS_EINVAL);
        }
        let request =
            protocol::cpu_sleep::decode_thread_request(payload).map_err(|_| STATUS_EINVAL)?;
        let sender = sender
            .filter(|sender| sender.process_id == peer.process_id && sender.thread_id != 0)
            .ok_or(protocol::STATUS_EPERM)?;
        service.validate_request_image(peer, image, backend)?;
        let process = service.process_clock_target(peer, peer.process_id, backend)?;
        let thread = backend.timer_thread_target(process, attachments[0].handle)?;
        if thread == 0 {
            return Err(protocol::STATUS_EIO);
        }
        if thread == sender.thread_id {
            return Err(STATUS_EINVAL);
        }
        self.admit(
            service,
            peer,
            image,
            Subject::Thread(thread),
            request.absolute,
            request.nanoseconds,
            completion,
            backend,
            reply,
        )
    }

    /// IPC admission keeps the channel rollback-owned even for malformed
    /// frames or unexpected attachments. No request byte supplies the owner.
    pub fn begin_request_with_reply<H: Copy, B: ClockBackend<H>>(
        &mut self,
        service: &mut PosixService<H>,
        peer: PeerIdentity,
        image: RequestImage,
        header: protocol::Header,
        payload: &[u8],
        attachments: &[AttachedObject<H>],
        completion: C,
        backend: &mut B,
        reply: impl FnOnce(u128) -> bool,
    ) -> Result<bool, i32> {
        if header.opcode != protocol::OP_PROCESS_CPU_SLEEP {
            return Err(protocol::STATUS_ENOSYS);
        }
        if header.flags != 0
            || header.status != 0
            || header.payload_len as usize != payload.len()
            || !attachments.is_empty()
        {
            return Err(STATUS_EINVAL);
        }
        let request = protocol::cpu_sleep::decode_request(payload).map_err(|_| STATUS_EINVAL)?;
        self.begin_with_reply(
            service,
            peer,
            image,
            request.process,
            request.absolute,
            request.nanoseconds,
            completion,
            backend,
            reply,
        )
    }

    pub const fn new() -> Self {
        Self { waits: Vec::new() }
    }

    pub fn len(&self) -> usize {
        self.waits.len()
    }

    pub fn is_empty(&self) -> bool {
        self.waits.is_empty()
    }

    /// `peer` and `image` must originate in authenticated request admission.
    /// `subject == 0` selects that owner; another PID is only a selection,
    /// never authority to acquire a new native process object.
    ///
    /// The reply receives the sampled absolute deadline for relative-sleep
    /// remainder calculation after a caught signal. False means no successful
    /// reply was enqueued. No fallible operation follows a true publication.
    pub fn begin_with_reply<H: Copy, B: ClockBackend<H>>(
        &mut self,
        service: &mut PosixService<H>,
        peer: PeerIdentity,
        image: RequestImage,
        subject: u64,
        absolute: bool,
        nanoseconds: u128,
        completion: C,
        backend: &mut B,
        reply: impl FnOnce(u128) -> bool,
    ) -> Result<bool, i32> {
        if subject > i32::MAX as u64 || nanoseconds > protocol::process_timer::MAX_DURATION_NS {
            return Err(STATUS_EINVAL);
        }
        let subject = if subject == 0 {
            peer.process_id
        } else {
            subject
        };
        self.admit(
            service,
            peer,
            image,
            Subject::Process(subject),
            absolute,
            nanoseconds,
            completion,
            backend,
            reply,
        )
    }

    fn admit<H: Copy, B: ClockBackend<H>>(
        &mut self,
        service: &mut PosixService<H>,
        peer: PeerIdentity,
        image: RequestImage,
        subject: Subject,
        absolute: bool,
        nanoseconds: u128,
        completion: C,
        backend: &mut B,
        reply: impl FnOnce(u128) -> bool,
    ) -> Result<bool, i32> {
        if self.waits.len() >= MAX_WAITS
            || self
                .waits
                .iter()
                .filter(|wait| wait.owner.process_id == peer.process_id)
                .count()
                >= MAX_WAITS_PER_PROCESS
        {
            return Err(protocol::STATUS_EAGAIN);
        }
        self.waits
            .try_reserve(1)
            .map_err(|_| protocol::STATUS_ENOMEM)?;
        let now = read(service, peer, image, subject, backend)?;
        // Unlike timer_settime, zero is an immediately satisfied sleep,
        // including an absolute deadline at the CPU clock's epoch.
        let deadline = if absolute {
            nanoseconds
        } else {
            now.checked_add(nanoseconds).ok_or(STATUS_EOVERFLOW)?
        };
        if !reply(deadline) {
            return Ok(false);
        }
        self.waits.push(Wait {
            owner: peer,
            image,
            subject,
            deadline,
            result: (now >= deadline).then_some(Ok(())),
            completion,
        });
        Ok(true)
    }

    /// One nonblocking attempt per entry per sweep. Native failures become a
    /// terminal error rather than a fabricated timestamp or an infinite wait.
    /// Backpressure retains the result and the endpoint, not the timer quota
    /// of a separate POSIX timer. A disconnected client needs no cancel RPC.
    pub fn observe<H: Copy, B: ClockBackend<H>>(
        &mut self,
        service: &mut PosixService<H>,
        backend: &mut B,
    ) -> Result<usize, i32> {
        let mut completed = 0;
        let mut failure = None;
        self.waits.retain_mut(|wait| {
            match wait.completion.peer_closed() {
                Ok(true) => return false,
                Err(error) => {
                    failure.get_or_insert(error);
                    return false;
                }
                Ok(false) => {}
            }
            if wait.result.is_none() {
                wait.result = match read(service, wait.owner, wait.image, wait.subject, backend) {
                    Ok(now) => (now >= wait.deadline).then_some(Ok(())),
                    Err(error) => Some(Err(error)),
                };
            }
            let Some(result) = wait.result else {
                return true;
            };
            // Check after observation, including its failure paths, and on
            // retries. An old image must not publish into a new exec image.
            if let Err(error) = service.validate_request_image(wait.owner, wait.image, backend) {
                failure.get_or_insert(error);
                return false;
            }
            match wait.completion.publish(result) {
                Ok(true) => {
                    completed += 1;
                    false
                }
                Ok(false) => true,
                Err(error) => {
                    failure.get_or_insert(error);
                    false
                }
            }
        });
        failure.map_or(Ok(completed), Err)
    }
}

fn read<H: Copy, B: ClockBackend<H>>(
    service: &mut PosixService<H>,
    peer: PeerIdentity,
    image: RequestImage,
    subject: Subject,
    backend: &mut B,
) -> Result<u128, i32> {
    service.validate_request_image(peer, image, backend)?;
    let process = service.process_clock_target(
        peer,
        match subject {
            Subject::Process(pid) => pid,
            Subject::Thread(_) => peer.process_id,
        },
        backend,
    )?;
    let reading = match subject {
        Subject::Process(_) => backend.timer_clock(process, Clock::ProcessCpu),
        Subject::Thread(thread) => backend.timer_thread_clock(process, thread),
    };
    service.validate_request_image(peer, image, backend)?;
    // Revalidate visibility and subject liveness after native observation.
    service.process_clock_target(
        peer,
        match subject {
            Subject::Process(pid) => pid,
            Subject::Thread(_) => peer.process_id,
        },
        backend,
    )?;
    match reading? {
        Reading::Counter(now) => Ok(now),
        _ => Err(protocol::STATUS_EIO),
    }
}
