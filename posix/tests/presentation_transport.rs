//! Exercise the shared transport's strict replies and borrowed/owned Handles.
#![allow(dead_code)]
use std::cell::RefCell;
mod syscall {
    pub use mochi_user_syscall::{NativeError, SysError, SysResult};
}
mod capability {
    pub use mochios_capability_protocol::presentation;
}
use capability::presentation as w;
#[derive(Default)]
struct State {
    mode: u8,
    calls: u32,
    closed: Vec<u32>,
}
thread_local! {static STATE:RefCell<State>=RefCell::new(State::default());}
mod handle {
    pub const HANDLE_RIGHT_WAIT: u64 = mnu_abi::HANDLE_RIGHT_WAIT;
    pub const HANDLE_RIGHT_TRANSFER: u64 = mnu_abi::HANDLE_RIGHT_TRANSFER;
    pub fn close(value: u32) -> super::syscall::SysResult<()> {
        super::STATE.with_borrow_mut(|s| s.closed.push(value));
        Ok(())
    }
}
mod ipc {
    use super::*;
    pub use mnu_abi::{IpcObjectHandle, IpcObjectHandles};
    pub fn call_object_handles(
        destination: u32,
        bytes: &[u8],
        reply: &mut [u8],
        handles: &mut IpcObjectHandles,
    ) -> syscall::SysResult<u64> {
        assert_eq!(destination, 88);
        let mode = STATE.with_borrow_mut(|s| {
            s.calls += 1;
            s.mode
        });
        if mode == 1 {
            return Err(syscall::SysError::from_raw(-5));
        }
        if bytes.len() == w::SESSION_BYTES {
            w::decode_session(bytes).unwrap();
            if handles.count != 0 {
                assert_eq!(handles.count, 1);
                assert_eq!(handles.handles[0].handle, 7);
                assert_eq!(handles.handles[0].rights, handle::HANDLE_RIGHT_TRANSFER);
            }
            reply.copy_from_slice(
                &(if mode == 7 {
                    13u64
                } else if mode == 8 {
                    4096
                } else {
                    0
                })
                .to_le_bytes(),
            );
        } else {
            let command = w::decode_command(bytes).unwrap();
            assert_eq!(handles.count, 1);
            assert_eq!(handles.handles[0].handle, 7);
            assert_eq!(handles.handles[0].rights, handle::HANDLE_RIGHT_WAIT);
            let w::Command::Register { context, .. } = command else {
                panic!("unexpected request")
            };
            let value = if mode == 7 {
                w::Receipt::failure(13)
            } else {
                w::Receipt {
                    status: 0,
                    stage: w::Stage::Pending,
                    registration: 11,
                    context: if mode == 8 {
                        w::Context {
                            generation: context.generation + 1,
                            ..context
                        }
                    } else {
                        context
                    },
                    focus_generation: 0,
                    surface: 0,
                    content_generation: 0,
                    renderer: w::Image {
                        process: 17,
                        revision: 0,
                        digest: [9; 32],
                    },
                }
            };
            reply.copy_from_slice(&w::encode_receipt(value).unwrap());
        }
        *handles = IpcObjectHandles::default();
        if mode == 2 || mode == 3 {
            handles.count = 3;
            for (entry, value) in handles.handles.iter_mut().zip([67, 67, 7]) {
                entry.handle = value;
            }
            if mode == 3 {
                return Err(syscall::SysError::from_raw(-5));
            }
        }
        if mode == 6 {
            handles.delivery_flags = mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE;
        }
        Ok(((if mode == 4 { 89u64 } else { 88u64 }) << 32)
            | if mode == 5 {
                reply.len() as u64 - 1
            } else {
                reply.len() as u64
            })
    }
}
#[path = "../../../user/crates/platform/src/presentation.rs"]
mod production;
fn context() -> w::Context {
    w::Context {
        session: 3,
        generation: 5,
        active: true,
    }
}
fn invoke() -> syscall::SysResult<w::Receipt> {
    production::command(
        88,
        w::Command::Register {
            context: context(),
            correlation: mochios_capability_protocol::consent::Correlation {
                ticket: mochios_capability_protocol::consent::Ticket {
                    id: 1,
                    challenge: [2; 32],
                },
                display: 3,
            },
            kind: w::Kind::SecureOverlay,
        },
        Some(ipc::IpcObjectHandle {
            handle: 7,
            reserved: 0,
            rights: handle::HANDLE_RIGHT_WAIT,
        }),
    )
}
#[test]
fn bad_envelopes_errors_and_duplicate_owned_references_cannot_consume_borrowed_handles() {
    for mode in 0..=8 {
        STATE.with_borrow_mut(|s| {
            *s = State {
                mode,
                ..State::default()
            }
        });
        let result = invoke();
        assert_eq!(result.is_ok(), mode == 0, "mode {mode}");
        if mode == 7 {
            assert_eq!(result.unwrap_err().raw(), -13);
        }
        STATE.with_borrow(|s| {
            assert_eq!(s.calls, 1);
            assert_eq!(
                s.closed,
                if mode == 2 || mode == 3 {
                    vec![67]
                } else {
                    vec![]
                }
            );
        });
    }
    for mode in [0, 1, 4, 5, 6, 7, 8] {
        STATE.with_borrow_mut(|s| {
            *s = State {
                mode,
                ..State::default()
            }
        });
        let result = production::session(88, context());
        assert_eq!(result.is_ok(), mode == 0, "session mode {mode}");
        if mode == 7 {
            assert_eq!(result.unwrap_err().raw(), -13);
        }
        STATE.with_borrow(|s| assert!(s.closed.is_empty()));
    }
}

#[test]
fn session_domain_attachment_is_borrowed_and_only_transfer_is_delegated() {
    for mode in 0..=8 {
        STATE.with_borrow_mut(|s| {
            *s = State {
                mode,
                ..State::default()
            }
        });
        let result = production::session_with_domain(
            88,
            context(),
            Some(ipc::IpcObjectHandle {
                handle: 7,
                reserved: 0,
                rights: handle::HANDLE_RIGHT_TRANSFER,
            }),
        );
        assert_eq!(result.is_ok(), mode == 0);
        STATE.with_borrow(|s| {
            assert_eq!(
                s.closed,
                if mode == 2 || mode == 3 {
                    vec![67]
                } else {
                    vec![]
                }
            )
        });
    }
    STATE.with_borrow_mut(|s| *s = State::default());
    assert!(production::session_with_domain(88, context(), None).is_err());
    assert!(
        production::session_with_domain(
            88,
            w::Context {
                active: false,
                ..context()
            },
            Some(ipc::IpcObjectHandle {
                handle: 7,
                reserved: 0,
                rights: handle::HANDLE_RIGHT_TRANSFER,
            })
        )
        .is_err()
    );
    STATE.with_borrow(|s| assert_eq!(s.calls, 0));
}
