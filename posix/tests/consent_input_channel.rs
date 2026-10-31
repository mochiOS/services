//! Exercise the real broker channel; peer capture itself is independently
//! covered by trusted_broker_images and native IPC tests.
extern crate self as mochi_user_platform;
pub use mochi_user_syscall as syscall;
pub mod capability {
    pub use mochios_capability_protocol::*;
}
use capability::{
    consent::{Correlation, Ticket},
    input_authority as w,
};
use std::cell::RefCell;
#[allow(dead_code)]
#[path = "../../capability/src/consent.rs"]
mod consent;
#[path = "../../capability/src/consent_input.rs"]
mod production;
fn instance() -> consent::Instance {
    consent::Instance {
        endpoint: 700,
        process: 42,
        thread: 43,
        revision: 0,
        digest: [1; 32],
    }
}
struct State {
    captures: u32,
    closed: Vec<u32>,
    calls: usize,
    trusted: bool,
    changed: bool,
    same: bool,
    bad_reply: u8,
    active: bool,
    serial: u64,
}
impl Default for State {
    fn default() -> Self {
        Self {
            captures: 0,
            closed: Vec::new(),
            calls: 0,
            trusted: true,
            changed: false,
            same: true,
            bad_reply: 0,
            active: false,
            serial: 10,
        }
    }
}
thread_local! { static STATE:RefCell<State>=RefCell::new(State::default()); }
fn denied() -> syscall::SysError {
    syscall::SysError::from_raw(syscall::NativeError::AccessDenied.into_raw() as i64)
}
mod consent_peer {
    use super::*;
    pub struct ProcessReference(pub u32);
    impl Drop for ProcessReference {
        fn drop(&mut self) {
            let _ = handle::close(self.0);
        }
    }
    pub struct Peer {
        pub instance: consent::Instance,
        pub process: ProcessReference,
    }
    pub fn capture(endpoint: u64) -> Result<Peer, syscall::SysError> {
        assert_eq!(endpoint, 700);
        Ok(STATE.with_borrow_mut(|s| {
            s.captures += 1;
            let mut instance = instance();
            if s.changed {
                instance.revision += 1;
            }
            Peer {
                instance,
                process: ProcessReference(100 + s.captures),
            }
        }))
    }
}
mod trusted_images {
    use super::*;
    #[derive(PartialEq, Eq)]
    pub enum Role {
        Input,
    }
    pub struct TrustedImages;
    impl TrustedImages {
        pub fn role(&self, _: &consent_peer::Peer) -> Result<Option<Role>, syscall::SysError> {
            Ok(STATE.with_borrow(|s| s.trusted.then_some(Role::Input)))
        }
    }
}
pub mod handle {
    use super::*;
    pub fn close(value: u32) -> Result<(), syscall::SysError> {
        STATE.with_borrow_mut(|s| s.closed.push(value));
        Ok(())
    }
    pub fn same_object(first: u32, second: u32) -> Result<bool, syscall::SysError> {
        assert_ne!(first, second);
        Ok(STATE.with_borrow(|s| s.same))
    }
}
pub mod process {
    use super::*;
    pub fn find_by_name(name: &str) -> Result<u64, syscall::SysError> {
        assert_eq!(name, "input.service");
        Ok(700)
    }
}
pub mod ipc {
    use super::*;
    pub use mnu_abi::IpcObjectHandles;
    pub fn call_object_handles(
        destination: u32,
        bytes: &[u8],
        reply: &mut [u8],
        handles: &mut IpcObjectHandles,
    ) -> Result<u64, syscall::SysError> {
        assert_eq!(destination, 700);
        assert_eq!(*handles, IpcObjectHandles::default());
        let command = w::decode_command(bytes).unwrap();
        STATE.with_borrow_mut(|s| {
            s.calls += 1;
            let mut value = w::Reply {
                status: 0,
                generation: 2,
                serial: s.serial,
                all_released: true,
            };
            match command {
                w::Command::Register => {}
                w::Command::Arm { .. } => s.active = true,
                w::Command::Status { .. } => {
                    if !s.active {
                        value = w::Reply::failure(2);
                    }
                }
                w::Command::Cancel { .. } => s.active = false,
            }
            if s.bad_reply == 3 {
                value = w::Reply::failure(13);
            }
            reply.copy_from_slice(&w::encode_reply(value).unwrap());
            if s.bad_reply == 4 || s.bad_reply == 5 {
                handles.count = 2;
                handles.handles[0].handle = 501;
                handles.handles[1].handle = 501;
                if s.bad_reply == 5 {
                    return Err(denied());
                }
            }
            Ok(((if s.bad_reply == 1 { 701u64 } else { 700u64 }) << 32)
                | if s.bad_reply == 2 {
                    39
                } else {
                    w::REPLY_BYTES as u64
                })
        })
    }
}
fn reset() {
    STATE.with_borrow_mut(|s| *s = State::default());
}
fn correlation() -> Correlation {
    Correlation {
        ticket: Ticket {
            id: 1,
            challenge: [8; 32],
        },
        display: 1,
    }
}
fn connected() -> production::Channel {
    production::Channel::connect(&trusted_images::TrustedImages).unwrap()
}
fn event(serial: u64) -> [u8; w::EVENT_BYTES] {
    w::encode_event(w::Event {
        generation: 2,
        correlation: correlation(),
        observation: w::Observation {
            serial,
            transition: w::Transition::PhysicalPress,
            control: 0x15,
        },
    })
    .unwrap()
}
#[test]
fn untrusted_roots_bad_replies_and_failed_ipc_never_leave_owned_references() {
    for mode in 0..6 {
        reset();
        STATE.with_borrow_mut(|s| {
            if mode == 0 {
                s.trusted = false;
            } else {
                s.bad_reply = mode;
            }
        });
        assert!(production::Channel::connect(&trusted_images::TrustedImages).is_err());
        STATE.with_borrow(|s| {
            for reference in 101..=100 + s.captures {
                assert_eq!(s.closed.iter().filter(|h| **h == reference).count(), 1);
            }
            assert_eq!(
                s.closed.iter().filter(|h| **h == 501).count(),
                usize::from(mode == 4 || mode == 5)
            );
            if mode == 0 {
                assert_eq!(s.calls, 0);
            }
        });
    }
}
#[test]
fn only_the_current_measured_peer_and_exact_active_generation_can_produce_evidence() {
    reset();
    let mut channel = connected();
    assert!(channel.receive(700, &event(11)).is_err());
    let snapshot = channel.arm(correlation()).unwrap();
    assert_eq!(snapshot.serial, 10);
    assert!(channel.receive(701, &event(11)).is_err());
    let mut stale = event(11);
    stale[8] = 3;
    assert!(channel.receive(700, &stale).is_err());
    assert_eq!(
        channel.receive(700, &event(11)).unwrap().observation.serial,
        11
    );
    assert!(channel.receive(700, &event(11)).is_err());
    STATE.with_borrow_mut(|s| s.serial = 11);
    assert_eq!(channel.status().unwrap().serial, 11);
    STATE.with_borrow_mut(|s| s.changed = true);
    assert!(channel.receive(700, &event(12)).is_err());
    assert!(channel.status().is_err());
}
#[test]
fn native_object_replacement_and_snapshot_rollback_cannot_reuse_a_registration() {
    reset();
    let mut channel = connected();
    channel.arm(correlation()).unwrap();
    STATE.with_borrow_mut(|s| s.same = false);
    assert!(channel.receive(700, &event(11)).is_err());
    STATE.with_borrow_mut(|s| {
        s.same = true;
        s.serial = 9;
    });
    assert!(channel.status().is_err());
    STATE.with_borrow_mut(|s| s.serial = 10);
    channel.cancel().unwrap();
    assert!(channel.receive(700, &event(11)).is_err());
    assert!(channel.status().is_err());
    drop(channel);
    STATE.with_borrow(|s| assert_eq!(s.closed.iter().filter(|h| **h == 101).count(), 1));
}
