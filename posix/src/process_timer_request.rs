//! Scalar timer IPC. No caller-supplied identity or transferred object selects
//! an owner. Backends perform native observations only, never provider RPC.
use super::*;
use process_timer::{Clock, Samples};
use protocol::process_timer as wire;

#[derive(Clone, Copy, Debug)]
pub enum Reading {
    Realtime(i128),
    Counter(u128),
}

pub trait ClockBackend<H: Copy>: ProcessBackend<H> {
    fn timer_clock(&mut self, process: H, clock: Clock) -> Result<Reading, i32>;
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
    Create(Clock, wire::Notification),
    Delete(u64),
    Get(u64),
    Set(u64, bool, wire::Value),
    Overrun(u64),
}

fn decode(header: protocol::Header, payload: &[u8]) -> Result<Request, i32> {
    if !matches!(
        header.opcode,
        protocol::OP_TIMER_CREATE
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
            Request::Create(clock, notification)
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
            // Thread callback creation still needs its own callback lifecycle.
            // Signal/default notifications use the joint signal dispatcher.
            if matches!(
                request,
                Request::Create(_, wire::Notification::Thread { .. })
            ) {
                return Err(protocol::STATUS_ENOSYS);
            }
            self.validate_request_image(peer, image, backend)?;
            let process = *self
                .processes
                .get(&peer.process_id)
                .ok_or(protocol::STATUS_ESRCH)?;
            let mut output = Vec::new();
            // Allocate before any policy mutation, including timer creation.
            output
                .try_reserve_exact(wire::VALUE_LEN)
                .map_err(|_| protocol::STATUS_ENOMEM)?;
            let mut samples = Samples {
                realtime_ns: 0,
                monotonic_ns: 0,
                process_cpu_ns: 0,
            };
            let query = match request {
                Request::Get(id) => Some((id, None)),
                Request::Set(id, absolute, _) => Some((id, Some(absolute))),
                _ => None,
            };
            if let Some((raw, replacement)) = query {
                let clocks = {
                    let timers = self.process_timers(peer)?;
                    let id = timers.resolve(raw)?;
                    timers.clocks_for(id, replacement)?
                };
                for clock in clocks.into_iter().flatten() {
                    match (clock, backend.timer_clock(process, clock)?) {
                        (Clock::Realtime, Reading::Realtime(value)) => samples.realtime_ns = value,
                        (Clock::Monotonic, Reading::Counter(value)) => samples.monotonic_ns = value,
                        (Clock::ProcessCpu, Reading::Counter(value)) => {
                            samples.process_cpu_ns = value
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
                Request::Create(clock, notification) => {
                    let id = timers.create(clock, notification)?;
                    output.extend_from_slice(&id.raw().to_le_bytes());
                }
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
