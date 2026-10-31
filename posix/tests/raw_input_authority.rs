extern crate mochi_user_platform as real;
extern crate self as mochi_user_platform;
pub use real::{input, syscall};
use std::cell::RefCell;
use syscall::{ExecutionIdentity, NativeError, SysError};

#[path = "../../service-manager/src/input_endpoint.rs"]
mod input_endpoint;
#[path = "../../input/src/raw_input.rs"]
mod raw_input;

struct State {
    events: Vec<&'static str>,
    closed: Vec<u32>,
    fail: Option<usize>,
    before: ExecutionIdentity,
    after: ExecutionIdentity,
    message: u64,
    status: u64,
    handles: ipc::IpcObjectHandles,
}
impl Default for State {
    fn default() -> Self {
        let identity = ExecutionIdentity {
            process_id: 42,
            thread_id: 43,
        };
        let mut handles = ipc::IpcObjectHandles::default();
        handles.count = 1;
        handles.handles[0] = real::ipc::IpcObjectHandle {
            handle: 19,
            reserved: 0,
            rights: input_endpoint::RIGHTS,
        };
        Self {
            events: Vec::new(),
            closed: Vec::new(),
            fail: None,
            before: identity,
            after: identity,
            message: (700 << 32) | 8,
            status: 0,
            handles,
        }
    }
}
thread_local! { static STATE: RefCell<State> = RefCell::new(State::default()); }
fn failure() -> SysError {
    SysError::from_raw(NativeError::BackingFailure.into_raw() as i64)
}
fn event(label: &'static str) -> Result<(), SysError> {
    STATE.with_borrow_mut(|state| {
        let step = state.events.len();
        state.events.push(label);
        if state.fail == Some(step) {
            Err(failure())
        } else {
            Ok(())
        }
    })
}
pub mod handle {
    pub use super::real::handle::*;
    pub fn close(handle: u32) -> Result<(), super::SysError> {
        super::STATE.with_borrow_mut(|state| state.closed.push(handle));
        Ok(())
    }
}
pub mod process {
    pub fn find_by_name(name: &str) -> Result<u64, super::SysError> {
        assert_eq!(name, "input.service");
        super::event("discover")?;
        Ok(700)
    }
}
pub mod ipc {
    pub use super::real::ipc::{IPC_DELIVERY_ENDPOINT_HANDLE, IpcObjectHandles};
    use super::*;
    pub fn endpoint_execution_identity(endpoint: u64) -> Result<ExecutionIdentity, SysError> {
        assert_eq!(endpoint, 700);
        event("identity")?;
        Ok(STATE.with_borrow(|state| {
            if state.events.len() == 2 {
                state.before
            } else {
                state.after
            }
        }))
    }
    pub fn call_object_handles(
        endpoint: u32,
        request: &[u8],
        reply: &mut [u8],
        handles: &mut IpcObjectHandles,
    ) -> Result<u64, SysError> {
        assert_eq!(endpoint, 700);
        assert_eq!(request, input::RAW_ENDPOINT_REQUEST);
        assert_eq!(*handles, IpcObjectHandles::default());
        event("call")?;
        Ok(STATE.with_borrow(|state| {
            reply.copy_from_slice(&state.status.to_le_bytes());
            *handles = state.handles;
            state.message
        }))
    }
}

fn proof() -> ipc::IpcObjectHandles {
    ipc::IpcObjectHandles {
        delivery_flags: ipc::IPC_DELIVERY_ENDPOINT_HANDLE,
        ..Default::default()
    }
}

#[test]
fn raw_packets_require_kernel_proof_of_the_delegated_send_handle() {
    let bytes = [input::RAW_KIND_KEYBOARD, 0, 0, 0, 0x15, 0, 0, 0];
    assert_eq!(
        raw_input::decode(&bytes, &proof()),
        Some(raw_input::Packet::Keyboard {
            byte: 0x15,
            synthetic: false
        })
    );
    for flags in [0, mnu_abi::IPC_DELIVERY_NATIVE_OBJECT, 3, 4, u32::MAX] {
        let mut handles = proof();
        handles.delivery_flags = flags;
        assert_eq!(raw_input::decode(&bytes, &handles), None);
    }
    for count in [1, 2, u32::MAX] {
        let mut handles = proof();
        handles.count = count;
        assert_eq!(raw_input::decode(&bytes, &handles), None);
    }
}

#[test]
fn serial_origin_cannot_be_confused_with_a_physical_key() {
    let packet = [
        input::RAW_KIND_KEYBOARD,
        input::RAW_FLAG_SYNTHETIC,
        0,
        0,
        0x15,
        0,
        0,
        0,
    ];
    assert_eq!(
        raw_input::decode(&packet, &proof()),
        Some(raw_input::Packet::Keyboard {
            byte: 0x15,
            synthetic: true
        })
    );
    for flag in 2..=u8::MAX {
        let mut invalid = packet;
        invalid[1] = flag;
        assert_eq!(raw_input::decode(&invalid, &proof()), None);
    }
}

#[test]
fn malformed_raw_packets_have_no_prefix_or_unknown_field_fallback() {
    let packets = [
        vec![input::RAW_KIND_KEYBOARD, 0, 0, 0, 0x15, 0, 0, 0],
        vec![input::RAW_KIND_MOUSE_PACKET, 0, 0, 0, 9, 1, 2, 0],
        vec![
            input::RAW_KIND_POINTER_ABSOLUTE,
            0,
            0,
            0,
            1,
            0,
            2,
            3,
            4,
            5,
            0,
            0,
        ],
    ];
    for packet in packets {
        assert!(raw_input::decode(&packet, &proof()).is_some());
        for length in 0..packet.len() {
            assert_eq!(raw_input::decode(&packet[..length], &proof()), None);
        }
        let mut extra = packet.clone();
        extra.push(0);
        assert_eq!(raw_input::decode(&extra, &proof()), None);
        for index in [0, 2, 3] {
            let mut invalid = packet.clone();
            invalid[index] = u8::MAX;
            assert_eq!(raw_input::decode(&invalid, &proof()), None);
        }
    }
}

#[test]
fn acquired_ingress_is_owned_and_closed_exactly_once() {
    STATE.set(State::default());
    let endpoint = input_endpoint::acquire(42).unwrap();
    assert_eq!(endpoint.0, 19);
    STATE.with_borrow(|state| assert!(state.closed.is_empty()));
    drop(endpoint);
    STATE.with_borrow(|state| assert_eq!(state.closed, [19]));
}

#[test]
fn discovery_cannot_replace_the_retained_process_identity() {
    for expected in [0, 41, 43] {
        STATE.set(State::default());
        assert!(input_endpoint::acquire(expected).is_err());
        STATE.with_borrow(|state| {
            assert_eq!(state.events, ["discover", "identity"]);
            assert!(state.closed.is_empty());
        });
    }
    STATE.set(State::default());
    STATE.with_borrow_mut(|state| state.after.thread_id += 1);
    assert!(input_endpoint::acquire(42).is_err());
    STATE.with_borrow(|state| assert_eq!(state.closed, [19]));
}

#[test]
fn failed_observations_do_not_fall_back_and_release_received_references() {
    for step in 0..4 {
        STATE.set(State {
            fail: Some(step),
            ..Default::default()
        });
        assert_eq!(input_endpoint::acquire(42).err().unwrap(), failure());
        STATE.with_borrow(|state| {
            assert_eq!(state.events.len(), step + 1);
            assert_eq!(state.closed, if step == 3 { vec![19] } else { vec![] });
        });
    }
}

#[test]
fn malformed_replies_cannot_publish_or_leak_an_endpoint() {
    for case in 0..10 {
        STATE.set(State::default());
        STATE.with_borrow_mut(|state| match case {
            0 => state.message = (701 << 32) | 8,
            1 => state.message -= 1,
            2 => state.status = 13,
            3 => state.handles.count = 0,
            4 => {
                state.handles.count = 2;
                state.handles.handles[1] = state.handles.handles[0];
                state.handles.handles[1].handle = 20;
            }
            5 => state.handles.handles[0].reserved = 1,
            6 => state.handles.handles[0].rights |= handle::HANDLE_RIGHT_RECEIVE,
            7 => state.handles.handles[0].rights &= !handle::HANDLE_RIGHT_TRANSFER,
            8 => state.handles.handles[0].handle = 0,
            _ => state.handles.delivery_flags = mnu_abi::IPC_DELIVERY_NATIVE_OBJECT,
        });
        assert!(input_endpoint::acquire(42).is_err(), "case {case}");
        STATE.with_borrow(|state| {
            let expected: Vec<_> = state
                .handles
                .handles
                .iter()
                .take(state.handles.count as usize)
                .filter_map(|h| (h.handle != 0).then_some(h.handle))
                .collect();
            assert_eq!(state.closed, expected, "case {case}");
        });
    }
}
