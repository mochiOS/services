#[path = "../../../user/crates/platform/src/memory_object.rs"]
mod memory_object;

use crate as platform;
#[path = "../../compositor/src/frame_buffer.rs"]
mod compositor_frame_buffer;
#[path = "../../display/src/shared_buffer.rs"]
mod display_shared_buffer;

use memory_object::MemoryObject;
use std::cell::RefCell;

#[derive(Default)]
struct State {
    calls: Vec<(syscall::SyscallNumber, Vec<u64>)>,
    fail_create: bool,
    fail_map: bool,
    fail_unmap: bool,
    fail_close: bool,
    fail_length: bool,
    fail_send: bool,
    extra_rights: u64,
    offers: Vec<(u64, Vec<u8>, mnu_abi::IpcObjectHandles)>,
}
thread_local! { static STATE: RefCell<State> = RefCell::new(State::default()); }

fn reset() {
    STATE.with(|state| *state.borrow_mut() = State::default());
}

#[test]
fn compositor_frame_owns_backing_and_offers_once_per_endpoint() {
    use compositor_frame_buffer::FrameBuffer;
    reset();
    let mut frame = FrameBuffer::new(8192).unwrap();
    assert_eq!(frame.address(), 0x10000);
    assert_eq!(frame.capacity(), 8192);
    assert!(frame.offer(0).is_err());
    frame.offer(9).unwrap();
    frame.offer(9).unwrap();
    frame.invalidate_offer();
    frame.offer(9).unwrap();
    frame.offer(10).unwrap();
    STATE.with(|state| {
        let state = state.borrow();
        assert_eq!(state.offers.len(), 3);
        assert_eq!(state.offers[0].0, 9);
        assert_eq!(state.offers[1].0, 9);
        assert_eq!(state.offers[2].0, 10);
        for (_, bytes, handles) in &state.offers {
            assert_eq!(
                memory_object::ReadOnlyOffer::decode(bytes).unwrap().length,
                8192
            );
            assert_eq!(handles.count, 1);
            assert_eq!(
                handles.handles[0].rights,
                memory_object::READONLY_BUFFER_RIGHTS
            );
        }
        assert!(
            state
                .calls
                .contains(&(syscall::SyscallNumber::MemoryMap, vec![0, 8192, 3, 2, 7, 0]))
        );
        assert!(!state.calls.iter().any(|call| matches!(
            call.0,
            syscall::SyscallNumber::MemoryUnmap | syscall::SyscallNumber::HandleClose
        )));
    });
    drop(frame);
    STATE.with(|state| {
        let state = state.borrow();
        assert_eq!(
            &state.calls[state.calls.len() - 2..],
            &[
                (syscall::SyscallNumber::MemoryUnmap, vec![0x10000, 8192]),
                (syscall::SyscallNumber::HandleClose, vec![7]),
            ]
        );
    });
}

#[test]
fn compositor_frame_failed_offer_is_retried_without_reallocation() {
    reset();
    let mut frame = compositor_frame_buffer::FrameBuffer::new(4096).unwrap();
    STATE.with(|state| state.borrow_mut().fail_send = true);
    assert_eq!(frame.offer(9).unwrap_err().raw(), -11);
    STATE.with(|state| state.borrow_mut().fail_send = false);
    frame.offer(9).unwrap();
    frame.offer(9).unwrap();
    STATE.with(|state| {
        let state = state.borrow();
        assert_eq!(state.offers.len(), 1);
        assert_eq!(
            state
                .calls
                .iter()
                .filter(|call| call.0 == syscall::SyscallNumber::MemoryObjectCreate)
                .count(),
            1
        );
    });
}

#[test]
fn compositor_frame_failed_replacement_preserves_previous_mapping() {
    use compositor_frame_buffer::FrameBuffer;
    reset();
    let mut frame = FrameBuffer::new(4096).unwrap();
    frame.offer(9).unwrap();
    STATE.with(|state| state.borrow_mut().fail_map = true);
    assert!(FrameBuffer::new(8192).is_err());
    assert_eq!(frame.capacity(), 4096);
    assert_eq!(frame.address(), 0x10000);
    STATE.with(|state| {
        let state = state.borrow();
        assert!(
            !state
                .calls
                .iter()
                .any(|call| call.0 == syscall::SyscallNumber::MemoryUnmap)
        );
        assert_eq!(
            state.calls.last().unwrap().0,
            syscall::SyscallNumber::HandleClose
        );
    });
    STATE.with(|state| state.borrow_mut().fail_map = false);
    frame = FrameBuffer::new(8192).unwrap();
    frame.offer(9).unwrap();
    STATE.with(|state| {
        let state = state.borrow();
        assert_eq!(state.offers.len(), 2);
        assert!(
            state
                .calls
                .contains(&(syscall::SyscallNumber::MemoryUnmap, vec![0x10000, 4096]))
        );
    });
}

#[test]
fn native_display_offer_probe_matches_current_abi_and_userspace_wire_format() {
    let source = include_str!("native_display_buffer_offer.c");
    for (name, number) in [
        ("FIND_PROCESS", mnu_abi::SyscallNumber::FindProcessByName),
        ("IPC_CALL", mnu_abi::SyscallNumber::IpcCall),
        (
            "IPC_SEND_HANDLES",
            mnu_abi::SyscallNumber::IpcSendObjectHandles,
        ),
        ("MEMORY_MAP", mnu_abi::SyscallNumber::MemoryMap),
        ("MEMORY_UNMAP", mnu_abi::SyscallNumber::MemoryUnmap),
        ("HANDLE_CLOSE", mnu_abi::SyscallNumber::HandleClose),
        ("MEMORY_CREATE", mnu_abi::SyscallNumber::MemoryObjectCreate),
        ("DEBUG_WRITE", mnu_abi::SyscallNumber::DebugWrite),
    ] {
        assert!(source.contains(&format!("{name} = {}", number as u64)));
    }
    assert_eq!(memory_object::ReadOnlyOffer::MAGIC, *b"MRAM");
    assert_eq!(memory_object::ReadOnlyOffer::WIRE_LENGTH, 32);
    assert_eq!(memory_object::READONLY_BUFFER_RIGHTS, 65);
}

#[test]
fn native_compositor_gate_uses_current_ipc_abi() {
    let source = include_str!("native_compositor_buffer_gate.c");
    for (name, number) in [
        ("IPC_SEND", mnu_abi::SyscallNumber::IpcSend),
        ("IPC_CREATE", mnu_abi::SyscallNumber::IpcCreate),
        ("IPC_CALL", mnu_abi::SyscallNumber::IpcCall),
        ("IPC_REPLY", mnu_abi::SyscallNumber::IpcReply),
        ("IPC_WAIT", mnu_abi::SyscallNumber::IpcWait),
        ("DEBUG_WRITE", mnu_abi::SyscallNumber::DebugWrite),
    ] {
        assert!(source.contains(&format!("{name} = {}", number as u64)));
    }
}

mod syscall {
    pub use mnu_abi::{
        EACCES, EINVAL, EIO, HANDLE_RIGHT_MAP, HANDLE_RIGHT_READ, MEMORY_ACCESS_ALL,
        MEMORY_ACCESS_READ, MEMORY_ACCESS_WRITE, MEMORY_MAP_SHARED, SyscallNumber,
    };
    pub use mochi_user_platform::syscall::{SysError, SysResult};
    fn call(number: SyscallNumber, args: &[u64]) -> SysResult<u64> {
        super::STATE.with(|state| {
            let mut state = state.borrow_mut();
            state.calls.push((number, args.to_vec()));
            match number {
                SyscallNumber::MemoryObjectCreate if state.fail_create => {
                    Err(SysError::from_raw(-12))
                }
                SyscallNumber::MemoryObjectCreate => Ok(7),
                SyscallNumber::MemoryMap if state.fail_map => Err(SysError::from_raw(-13)),
                SyscallNumber::MemoryMap => Ok(0x10000),
                SyscallNumber::MemoryObjectLength if state.fail_length => {
                    Err(SysError::from_raw(-22))
                }
                SyscallNumber::MemoryObjectLength => Ok(8192),
                SyscallNumber::MemoryUnmap if state.fail_unmap => Err(SysError::from_raw(-5)),
                SyscallNumber::HandleClose if state.fail_close => Err(SysError::from_raw(-5)),
                _ => Ok(0),
            }
        })
    }
    pub fn call1(number: SyscallNumber, a: u64) -> SysResult<u64> {
        call(number, &[a])
    }
    pub fn call2(number: SyscallNumber, a: u64, b: u64) -> SysResult<u64> {
        call(number, &[a, b])
    }
    pub fn call6(
        number: SyscallNumber,
        a: u64,
        b: u64,
        c: u64,
        d: u64,
        e: u64,
        f: u64,
    ) -> SysResult<u64> {
        call(number, &[a, b, c, d, e, f])
    }
}
mod handle {
    pub type Handle = u32;
    pub fn close(handle: Handle) -> super::syscall::SysResult<()> {
        super::syscall::call1(super::syscall::SyscallNumber::HandleClose, handle as u64).map(|_| ())
    }
    pub fn rights(_: Handle) -> super::syscall::SysResult<u64> {
        super::STATE.with(|state| {
            Ok(
                mnu_abi::HANDLE_RIGHT_READ
                    | mnu_abi::HANDLE_RIGHT_MAP
                    | state.borrow().extra_rights,
            )
        })
    }
}

mod ipc {
    pub use mnu_abi::IpcObjectHandles;
    pub fn send_object_handles(
        endpoint: u64,
        bytes: &[u8],
        handles: &IpcObjectHandles,
    ) -> super::syscall::SysResult<u64> {
        super::STATE.with(|state| {
            let mut state = state.borrow_mut();
            if state.fail_send {
                return Err(super::syscall::SysError::from_raw(-11));
            }
            state.offers.push((endpoint, bytes.to_vec(), *handles));
            Ok(0)
        })
    }
}

#[test]
fn display_receiver_retains_mapping_until_buffer_replacement_and_drains_bad_attachments() {
    use display_shared_buffer::SharedBuffer;
    use memory_object::ReadOnlyOffer;
    let bytes = ReadOnlyOffer {
        offset: 0,
        length: 4096,
    }
    .encode()
    .unwrap();
    reset();
    let mut attachments = mnu_abi::IpcObjectHandles::default();
    attachments.count = 1;
    attachments.handles[0].handle = 19;
    let buffer = SharedBuffer::receive(9, 9, &bytes, &mut attachments).unwrap();
    assert_eq!(buffer.view(), (9, 0x10000, 4096));
    assert_eq!(attachments.count, 0);
    STATE.with(|state| {
        assert!(
            !state
                .borrow()
                .calls
                .iter()
                .any(|call| call.0 == syscall::SyscallNumber::MemoryUnmap)
        )
    });
    drop(buffer);
    STATE.with(|state| {
        assert_eq!(
            state.borrow().calls.last().unwrap().0,
            syscall::SyscallNumber::MemoryUnmap
        )
    });
    for mode in 0..3 {
        reset();
        let mut attachments = mnu_abi::IpcObjectHandles::default();
        attachments.count = if mode == 1 { 2 } else { 1 };
        attachments.handles[0].handle = 19;
        if mode == 1 {
            attachments.handles[1].handle = 20;
        }
        assert!(
            SharedBuffer::receive(
                9,
                if mode == 0 { 8 } else { 9 },
                if mode == 2 { &bytes[..31] } else { &bytes },
                &mut attachments
            )
            .is_err()
        );
        assert_eq!(attachments.count, 0);
        assert!(attachments.handles.iter().all(|entry| entry.handle == 0));
        STATE.with(|state| {
            let state = state.borrow();
            assert!(
                !state
                    .calls
                    .iter()
                    .any(|call| call.0 == syscall::SyscallNumber::MemoryMap)
            );
            assert_eq!(
                state
                    .calls
                    .iter()
                    .filter(|call| call.0 == syscall::SyscallNumber::HandleClose)
                    .count(),
                if mode == 1 { 2 } else { 1 }
            );
        });
    }
    assert_eq!(
        SharedBuffer::legacy(9, 0x20000, 8192).view(),
        (9, 0x20000, 8192)
    );
}

#[test]
fn readonly_offers_attach_only_read_map_and_receiver_owns_a_local_mapping() {
    use memory_object::{READONLY_BUFFER_RIGHTS, ReadOnlyOffer, receive_readonly_offer};
    reset();
    let source = MemoryObject::create(8192).unwrap();
    source.send_readonly(9, 4096, 4096).unwrap();
    let bytes = STATE.with(|state| {
        let state = state.borrow();
        let (endpoint, bytes, handles) = &state.offers[0];
        assert_eq!(*endpoint, 9);
        assert_eq!(handles.count, 1);
        assert_eq!(handles.delivery_flags, 0);
        assert_eq!(handles.handles[0].handle, 7);
        assert_eq!(handles.handles[0].rights, READONLY_BUFFER_RIGHTS);
        bytes.clone()
    });
    assert_eq!(
        ReadOnlyOffer::decode(&bytes).unwrap(),
        ReadOnlyOffer {
            offset: 4096,
            length: 4096
        }
    );
    // SAFETY: a single simulated received reference is relinquished here.
    let received = unsafe { MemoryObject::from_owned_handle(19) };
    let view = receive_readonly_offer(&bytes, received, 4096).unwrap();
    assert_eq!(view.address(), 0x10000);
    STATE.with(|state| {
        assert!(state.borrow().calls.contains(&(
            syscall::SyscallNumber::MemoryMap,
            vec![0, 4096, 1, 2, 19, 4096]
        )))
    });
    drop(view);
    drop(source);
}

#[test]
fn malformed_or_overprivileged_received_offers_are_closed_without_mapping() {
    use memory_object::{ReadOnlyOffer, receive_readonly_offer};
    let wire = ReadOnlyOffer {
        offset: 4096,
        length: 4096,
    }
    .encode()
    .unwrap();
    for index in [0, 4, 6, 8] {
        let mut corrupted = wire;
        corrupted[index] ^= 1;
        assert!(ReadOnlyOffer::decode(&corrupted).is_err());
    }
    assert!(ReadOnlyOffer::decode(&wire[..31]).is_err());
    for offer in [
        ReadOnlyOffer {
            offset: 1,
            length: 1,
        },
        ReadOnlyOffer {
            offset: 0,
            length: 0,
        },
        ReadOnlyOffer {
            offset: u64::MAX - 4095,
            length: 4096,
        },
    ] {
        assert!(offer.encode().is_err());
    }
    for mode in 0..6 {
        reset();
        if mode == 1 {
            STATE.with(|state| state.borrow_mut().extra_rights = mnu_abi::HANDLE_RIGHT_WRITE);
        }
        if mode == 4 {
            STATE.with(|state| state.borrow_mut().fail_length = true);
        }
        if mode == 5 {
            STATE.with(|state| state.borrow_mut().fail_map = true);
        }
        let bytes = if mode == 2 {
            ReadOnlyOffer {
                offset: 8192,
                length: 1,
            }
            .encode()
            .unwrap()
        } else {
            wire
        };
        // SAFETY: each iteration owns one simulated received reference.
        let received = unsafe { MemoryObject::from_owned_handle(19) };
        assert!(
            receive_readonly_offer(
                if mode == 3 { &bytes[..31] } else { &bytes },
                received,
                if mode == 0 { 1 } else { 8192 }
            )
            .is_err()
        );
        STATE.with(|state| {
            let state = state.borrow();
            assert_eq!(
                state
                    .calls
                    .iter()
                    .any(|call| call.0 == syscall::SyscallNumber::MemoryMap),
                mode == 5
            );
            assert_eq!(
                state.calls.last().unwrap(),
                &(syscall::SyscallNumber::HandleClose, vec![19])
            );
        });
    }
}

#[test]
fn rejected_or_failed_sends_leave_source_ownership_intact() {
    reset();
    let source = MemoryObject::create(8192).unwrap();
    assert!(source.send_readonly(9, 8192, 1).is_err());
    assert!(source.send_readonly(9, 1, 4096).is_err());
    STATE.with(|state| state.borrow_mut().fail_send = true);
    assert_eq!(source.send_readonly(9, 0, 4096).unwrap_err().raw(), -11);
    assert_eq!(source.handle(), 7);
    STATE.with(|state| {
        let state = state.borrow();
        assert!(state.offers.is_empty());
        assert!(
            !state
                .calls
                .iter()
                .any(|call| call.0 == syscall::SyscallNumber::HandleClose)
        );
    });
    drop(source);
    STATE.with(|state| {
        assert_eq!(
            state.borrow().calls.last().unwrap(),
            &(syscall::SyscallNumber::HandleClose, vec![7])
        )
    });
}

#[test]
fn object_close_and_mapping_unmap_have_independent_ownership() {
    reset();
    let object = MemoryObject::create(8192).unwrap();
    assert_eq!(object.handle(), 7);
    assert_eq!(object.length().unwrap(), 8192);
    assert_eq!(
        object.rights().unwrap(),
        mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_MAP
    );
    let mut mapping = object.map(4096, 1, mnu_abi::MEMORY_ACCESS_READ).unwrap();
    assert_eq!(mapping.address(), 0x10000);
    assert_eq!(mapping.capacity(), 4096);
    assert_eq!(mapping.as_ptr() as u64, 0x10000);
    assert_eq!(mapping.as_mut_ptr() as u64, 0x10000);
    drop(object);
    STATE.with(|state| {
        assert_eq!(
            state.borrow().calls.last().unwrap().0,
            syscall::SyscallNumber::HandleClose
        )
    });
    drop(mapping);
    STATE.with(|state| {
        let state = state.borrow();
        assert!(state.calls.contains(&(
            syscall::SyscallNumber::MemoryMap,
            vec![0, 4096, 1, 2, 7, 4096]
        )));
        assert_eq!(
            state.calls.last().unwrap(),
            &(syscall::SyscallNumber::MemoryUnmap, vec![0x10000, 4096])
        );
        assert_eq!(
            state
                .calls
                .iter()
                .filter(|call| call.0 == syscall::SyscallNumber::HandleClose)
                .count(),
            1
        );
    });
}

#[test]
fn invalid_geometry_and_failed_mapping_never_unmap_or_close_unowned_resources() {
    reset();
    assert!(MemoryObject::create(0).is_err());
    assert!(MemoryObject::create(1).is_err());
    let object = MemoryObject::create(8192).unwrap();
    for (offset, length, access) in [
        (1, 4096, 1),
        (0, 0, 1),
        (0, u64::MAX, 1),
        (u64::MAX - 4095, 4096, 1),
        (0, 4096, 8),
    ] {
        assert!(object.map(offset, length, access).is_err());
    }
    STATE.with(|state| state.borrow_mut().fail_map = true);
    assert!(object.map(0, 4096, 1).is_err());
    drop(object);
    STATE.with(|state| {
        assert!(
            !state
                .borrow()
                .calls
                .iter()
                .any(|call| call.0 == syscall::SyscallNumber::MemoryUnmap)
        )
    });
}

#[test]
fn failed_creation_and_received_handle_ownership_close_only_valid_owned_handles() {
    reset();
    STATE.with(|state| state.borrow_mut().fail_create = true);
    assert!(MemoryObject::create(4096).is_err());
    // SAFETY: this test relinquishes its single simulated received reference.
    let received = unsafe { MemoryObject::from_owned_handle(19) };
    assert_eq!(received.handle(), 19);
    drop(received);
    STATE.with(|state| {
        let state = state.borrow();
        assert_eq!(
            state
                .calls
                .iter()
                .filter(|call| call.0 == syscall::SyscallNumber::HandleClose)
                .count(),
            1
        );
        assert_eq!(state.calls.last().unwrap().1, [19]);
    });
}

#[test]
fn explicit_release_failures_return_ownership_and_success_does_not_drop_twice() {
    reset();
    let object = MemoryObject::create(4096).unwrap();
    let mapping = object.map(0, 4096, mnu_abi::MEMORY_ACCESS_READ).unwrap();
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.fail_unmap = true;
        state.fail_close = true;
    });
    let (mapping, error) = match mapping.unmap() {
        Err(error) => error,
        Ok(()) => panic!("must retain failed mapping"),
    };
    assert_eq!(error.raw(), -5);
    assert_eq!(mapping.address(), 0x10000);
    let (object, error) = match object.close() {
        Err(error) => error,
        Ok(()) => panic!("must retain failed handle"),
    };
    assert_eq!(error.raw(), -5);
    assert_eq!(object.handle(), 7);
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.fail_unmap = false;
        state.fail_close = false;
    });
    assert!(mapping.unmap().is_ok());
    assert!(object.close().is_ok());
    STATE.with(|state| {
        let state = state.borrow();
        for number in [
            syscall::SyscallNumber::MemoryUnmap,
            syscall::SyscallNumber::HandleClose,
        ] {
            assert_eq!(
                state.calls.iter().filter(|call| call.0 == number).count(),
                2
            );
        }
    });
}
