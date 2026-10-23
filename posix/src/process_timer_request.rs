//! Timer IPC. No caller-supplied identity or transferred object selects an
//! owner. A WAIT Thread Handle may select a clock in the authenticated owner.
//! Backends perform native observations only, never provider RPC.
use super::*;
use process_timer::{Clock, Samples, Target};
use protocol::process_timer as wire;

#[derive(Clone, Copy, Debug)]
pub enum Reading {
    Realtime(i128),
    Counter(u128),
}

pub trait ClockBackend<H: Copy>: ProcessBackend<H> {
    fn timer_clock(&mut self, process: H, clock: Clock) -> Result<Reading, i32>;
    /// Validate the attached native Thread Handle against the retained process
    /// and its registered threads. The returned identity is native observation,
    /// not request data. Do not retain ownership of the borrowed attachment.
    fn timer_thread_target(&mut self, _process: H, _thread: H) -> Result<u64, i32> {
        Err(protocol::STATUS_ENOTSUP)
    }
    /// Select only a registered native Thread Handle belonging to `process`.
    /// IDs are service-internal bindings, never client-supplied authority.
    fn timer_thread_clock(&mut self, _process: H, _thread: u64) -> Result<Reading, i32> {
        Err(protocol::STATUS_ENOTSUP)
    }
}

pub fn cpu_nanoseconds(usage: mnu_abi::ProcessExecutionUsage) -> Result<u128, i32> {
    if usage.reserved != 0 || usage.ticks_per_second == 0 {
        return Err(protocol::STATUS_EIO);
    }
    Ok(
        (u128::from(usage.user_ticks) + u128::from(usage.kernel_ticks)) * 1_000_000_000
            / u128::from(usage.ticks_per_second),
    )
}

#[derive(Clone, Copy)]
enum Request {
    Create(Clock, wire::Notification, Option<u64>),
    Delete(u64),
    Get(u64),
    Set(u64, bool, wire::Value),
    Overrun(u64),
}

fn decode(header: protocol::Header, payload: &[u8]) -> Result<Request, i32> {
    if !matches!(
        header.opcode,
        protocol::OP_TIMER_CREATE
            | protocol::OP_TIMER_CREATE_PROCESS_CPU
            | protocol::OP_TIMER_DELETE
            | protocol::OP_TIMER_GET
            | protocol::OP_TIMER_SET
            | protocol::OP_TIMER_OVERRUN
    ) {
        return Err(protocol::STATUS_ENOSYS);
    }
    if header.flags != 0 || header.status != 0 || header.payload_len as usize != payload.len() {
        return Err(STATUS_EINVAL);
    }
    let invalid = |_| STATUS_EINVAL;
    Ok(match header.opcode {
        protocol::OP_TIMER_CREATE => {
            let (clock, notification) = wire::decode_create(payload).map_err(invalid)?;
            Request::Create(clock, notification, None)
        }
        protocol::OP_TIMER_CREATE_PROCESS_CPU => {
            let (pid, notification) = wire::decode_process_create(payload).map_err(invalid)?;
            Request::Create(Clock::ProcessCpu, notification, Some(pid))
        }
        protocol::OP_TIMER_SET => {
            let (id, absolute, value) = wire::decode_set(payload).map_err(invalid)?;
            Request::Set(id, absolute, value)
        }
        protocol::OP_TIMER_DELETE => Request::Delete(wire::decode_id(payload).map_err(invalid)?),
        protocol::OP_TIMER_GET => Request::Get(wire::decode_id(payload).map_err(invalid)?),
        _ => Request::Overrun(wire::decode_id(payload).map_err(invalid)?),
    })
}

impl<H: Copy> PosixService<H> {
    /// Atomic native-dispatch entry for creation. Retain the new object only
    /// after an encoded success reply was synchronously enqueued. A false
    /// reply or unwind retires the tentative ID without reusing its identity.
    pub fn create_process_timer_with_reply<B: ClockBackend<H>>(
        &mut self,
        peer: PeerIdentity,
        image: RequestImage,
        sender: Option<mnu_abi::ExecutionIdentity>,
        header: protocol::Header,
        payload: &[u8],
        attachments: &[AttachedObject<H>],
        backend: &mut B,
        reply: impl FnOnce(u64) -> bool,
    ) -> Result<bool, i32> {
        let Request::Create(clock, notification, selected_process) = decode(header, payload)?
        else {
            return Err(protocol::STATUS_ENOSYS);
        };
        if !attachments.is_empty()
            && (clock != Clock::ThreadCpu
                || attachments.len() != 1
                || attachments[0].rights != mnu_abi::HANDLE_RIGHT_WAIT)
        {
            return Err(STATUS_EINVAL);
        }
        let thread = self.timer_creation_target(
            peer,
            image,
            sender,
            clock,
            notification,
            selected_process,
            attachments.first(),
            backend,
        )?;
        self.process_timers(peer)?
            .create_with_reply(clock, notification, thread, reply)
    }

    fn timer_creation_target<B: ClockBackend<H>>(
        &mut self,
        peer: PeerIdentity,
        image: RequestImage,
        sender: Option<mnu_abi::ExecutionIdentity>,
        clock: Clock,
        _notification: wire::Notification,
        selected_process: Option<u64>,
        attachment: Option<&AttachedObject<H>>,
        backend: &mut B,
    ) -> Result<Target, i32> {
        self.validate_request_image(peer, image, backend)?;
        if let Some(pid) = selected_process {
            let process = self.process_clock_target(peer, pid, backend)?;
            if !matches!(
                backend.timer_clock(process, Clock::ProcessCpu)?,
                Reading::Counter(_)
            ) {
                return Err(protocol::STATUS_EIO);
            }
            self.validate_request_image(peer, image, backend)?;
            return Ok(if pid == peer.process_id {
                Target::Owner
            } else {
                Target::Process(pid)
            });
        }
        if clock != Clock::ThreadCpu {
            return Ok(Target::Owner);
        }
        let process = *self
            .processes
            .get(&peer.process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        let sender = sender
            .filter(|sender| sender.process_id == peer.process_id && sender.thread_id != 0)
            .ok_or(protocol::STATUS_EPERM)?;
        let target = match attachment {
            Some(attachment) => backend.timer_thread_target(process, attachment.handle)?,
            None => sender.thread_id,
        };
        if target == 0 {
            return Err(protocol::STATUS_EIO);
        }
        if !matches!(
            backend.timer_thread_clock(process, target)?,
            Reading::Counter(_)
        ) {
            return Err(protocol::STATUS_EIO);
        }
        self.validate_request_image(peer, image, backend)?;
        Ok(Target::Thread(target))
    }

    /// Every clock read uses a retained service object. A selected process
    /// shares its CPU lifetime across exec; it never becomes the timer owner.
    pub(super) fn read_timer_clock<B: ClockBackend<H>>(
        &self,
        peer: PeerIdentity,
        process: H,
        clock: Clock,
        target: Target,
        backend: &mut B,
    ) -> Result<Reading, i32> {
        match (clock, target) {
            (Clock::ThreadCpu, Target::Thread(thread)) => {
                backend.timer_thread_clock(process, thread)
            }
            (Clock::ProcessCpu, Target::Process(pid)) => {
                let subject = self.process_clock_target(peer, pid, backend)?;
                backend.timer_clock(subject, Clock::ProcessCpu)
            }
            (Clock::Realtime | Clock::Monotonic | Clock::ProcessCpu, Target::Owner) => {
                backend.timer_clock(process, clock)
            }
            _ => Err(protocol::STATUS_EIO),
        }
    }

    /// Non-creating controls. Creation requires synchronous publication through
    /// `create_process_timer_with_reply`, never a detached response builder.
    pub fn handle_process_timer_request<B: ClockBackend<H>>(
        &mut self,
        peer: PeerIdentity,
        image: RequestImage,
        header: protocol::Header,
        payload: &[u8],
        attachments: &[AttachedObject<H>],
        backend: &mut B,
    ) -> ObjectResponse<H> {
        let result = (|| {
            let request = decode(header, payload)?;
            if !attachments.is_empty() {
                return Err(STATUS_EINVAL);
            }
            if matches!(request, Request::Create(..)) {
                return Err(protocol::STATUS_ENOSYS);
            }
            self.validate_request_image(peer, image, backend)?;
            let process = *self
                .processes
                .get(&peer.process_id)
                .ok_or(protocol::STATUS_ESRCH)?;
            let mut output = Vec::new();
            // Allocate before any policy mutation.
            output
                .try_reserve_exact(wire::VALUE_LEN)
                .map_err(|_| protocol::STATUS_ENOMEM)?;
            let mut samples = Samples {
                realtime_ns: 0,
                monotonic_ns: 0,
                process_cpu_ns: 0,
                thread_cpu_ns: 0,
            };
            let query = match request {
                Request::Get(id) => Some((id, None)),
                Request::Set(id, absolute, _) => Some((id, Some(absolute))),
                _ => None,
            };
            if let Some((raw, replacement)) = query {
                let (clocks, target) = {
                    let timers = self.process_timers(peer)?;
                    let id = timers.resolve(raw)?;
                    (
                        timers.clocks_for(id, replacement)?,
                        timers.clock_target(id)?,
                    )
                };
                for clock in clocks.into_iter().flatten() {
                    let reading = self.read_timer_clock(peer, process, clock, target, backend)?;
                    match (clock, reading) {
                        (Clock::Realtime, Reading::Realtime(value)) => samples.realtime_ns = value,
                        (Clock::Monotonic, Reading::Counter(value)) => samples.monotonic_ns = value,
                        (Clock::ProcessCpu, Reading::Counter(value)) => {
                            samples.process_cpu_ns = value
                        }
                        (Clock::ThreadCpu, Reading::Counter(value)) => {
                            samples.thread_cpu_ns = value
                        }
                        _ => return Err(protocol::STATUS_EIO),
                    }
                }
                // A native exec during observation deletes old image timers.
                // Reject this request instead of creating/modifying new state.
                self.validate_request_image(peer, image, backend)?;
            }
            let mut generated = None;
            let mut timers = self.process_timers(peer)?;
            match request {
                Request::Create(..) => return Err(protocol::STATUS_ENOSYS),
                Request::Delete(raw) => {
                    let id = timers.resolve(raw)?;
                    timers.delete(id)?;
                }
                Request::Overrun(raw) => {
                    let id = timers.resolve(raw)?;
                    output.extend_from_slice(&timers.overrun(id)?.to_le_bytes());
                }
                Request::Get(raw) | Request::Set(raw, _, _) => {
                    let id = timers.resolve(raw)?;
                    // An unrepresentable old value cannot turn a failed set
                    // into a committed replacement with an error response.
                    let previous = timers.preview_value(id, samples)?;
                    output.resize(wire::VALUE_LEN, 0);
                    wire::encode_value(previous, &mut output).map_err(|_| STATUS_EOVERFLOW)?;
                    match request {
                        Request::Set(_, absolute, value) => {
                            timers.set(
                                id,
                                samples,
                                value.remaining_ns,
                                value.interval_ns,
                                absolute,
                            )?;
                        }
                        _ => {
                            generated = timers.observe_new_signal(id, samples)?;
                        }
                    }
                }
            }
            if let Some(signal) = generated {
                self.notify_timer_signal(peer.process_id, signal)?;
            }
            self.remove_empty_signal_notification(peer.process_id);
            Ok(output)
        })();
        match result {
            Ok(payload) => ObjectResponse {
                response: Response {
                    header: protocol::Header {
                        opcode: protocol::OP_STATUS,
                        request_id: header.request_id,
                        payload_len: payload.len() as u32,
                        ..Default::default()
                    },
                    payload,
                },
                handles: Vec::new(),
            },
            Err(status) => object_error(header.request_id, status),
        }
    }
}
