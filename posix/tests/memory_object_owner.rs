extern crate alloc;

#[path = "../../../user/crates/platform/src/memory_object.rs"]
mod memory_object;

use crate as platform;
#[path = "../../compositor/src/frame_buffer.rs"]
mod compositor_frame_buffer;
#[path = "../../compositor/src/received_buffer.rs"]
mod compositor_received_buffer;
#[path = "../../display/src/shared_buffer.rs"]
mod display_shared_buffer;
#[path = "../../linux/src/compositor_buffer.rs"]
mod linux_compositor_buffer;
#[path = "../../linux/src/stage_buffer.rs"]
mod linux_stage_buffer;
#[path = "../../mboot-agent/src/stage_mapping.rs"]
mod agent_stage_mapping;
#[path = "../../../applications/binder/src/platform/mochios/decoration_buffer.rs"]
mod binder_decoration_buffer;
#[path = "../../../binaries/coreutils/src/gui_buffer.rs"]
mod coreutils_gui_buffer;
#[derive(Debug)]
struct DecorationError(u64);
type HostError = CompositorError;
#[path = "../../../libraries/viewkit/src/platform/mochios/buffer.rs"]
mod viewkit_buffer;

#[derive(Debug)]
enum CompositorError {
    Unavailable,
    InvalidSize,
}

const PAGE_SIZE: usize = 4096;
const PIXEL_FORMAT_ARGB8888_PREMULTIPLIED: u32 = 2;

#[derive(Debug, PartialEq, Eq)]
enum MochiOsBackendError {
    ArithmeticOverflow,
    InvalidWindowSize,
    InvalidReply,
    Syscall(u64),
}

#[derive(Clone, Copy)]
struct Color {
    red: u8,
    green: u8,
    blue: u8,
}

// Only the tiny-skia input interface is simulated; buffer ownership, syscalls,
// wire encoding and the actual ViewKit copy implementation are under test.
struct Pixmap {
    width: u32,
    height: u32,
    bytes: Vec<u8>,
}
impl Pixmap {
    fn width(&self) -> u32 {
        self.width
    }
    fn height(&self) -> u32 {
        self.height
    }
    fn data(&self) -> &[u8] {
        &self.bytes
    }
}
mod connection {
    pub(super) fn syscall_result<T>(
        result: super::syscall::SysResult<T>,
    ) -> Result<T, super::MochiOsBackendError> {
        result.map_err(|error| super::MochiOsBackendError::Syscall(error.errno().unwrap_or(5)))
    }
}

use memory_object::MemoryObject;
use std::cell::RefCell;

#[derive(Default)]
struct State {
    calls: Vec<(syscall::SyscallNumber, Vec<u64>)>,
    fail_create: bool,
    fail_resize: bool,
    fail_map: bool,
    fail_unmap: bool,
    fail_close: bool,
    fail_length: bool,
    fail_send: bool,
    extra_rights: u64,
    map_address: Option<u64>,
    offers: Vec<(u64, Vec<u8>, mnu_abi::IpcObjectHandles)>,
}
thread_local! { static STATE: RefCell<State> = RefCell::new(State::default()); }

fn reset() {
    STATE.with(|state| *state.borrow_mut() = State::default());
}

#[test]
fn coreutils_gui_buffer_paints_owned_ram_and_offers_only_read_map() {
    reset();
    let mut pixels = vec![0u32; 1024];
    STATE.with(|state| state.borrow_mut().map_address = Some(pixels.as_mut_ptr() as u64));
    let buffer = coreutils_gui_buffer::GuiBuffer::new(16, 16, |x, y| (y * 16 + x) as u32).unwrap();
    assert_eq!(&pixels[..256], &(0..256).collect::<Vec<u32>>()[..]);
    buffer.offer(9).unwrap();
    STATE.with(|state| {
        assert_eq!(
            state.borrow().offers[0].2.handles[0].rights,
            memory_object::READONLY_BUFFER_RIGHTS
        )
    });
    drop(buffer);
    STATE.with(|state| {
        let state = state.borrow();
        assert_eq!(
            state.calls[state.calls.len() - 2].0,
            syscall::SyscallNumber::MemoryUnmap
        );
        assert_eq!(
            state.calls.last().unwrap().0,
            syscall::SyscallNumber::HandleClose
        );
    });
    assert!(coreutils_gui_buffer::GuiBuffer::new(0, 16, |_, _| panic!()).is_err());
    assert!(coreutils_gui_buffer::GuiBuffer::new(usize::MAX, 16, |_, _| panic!()).is_err());
}

#[test]
fn binder_decoration_owns_ram_copies_pixels_and_attenuates_offers() {
    reset();
    let mut storage = vec![0u32; 1024];
    STATE.with(|state| state.borrow_mut().map_address = Some(storage.as_mut_ptr() as u64));
    let mut buffer = binder_decoration_buffer::TitleBarBuffer::new(256).unwrap();
    buffer.write(&[0xff123456; 256]).unwrap();
    assert!(storage[..256].iter().all(|&pixel| pixel == 0xff123456));
    assert!(buffer.write(&[0; 257]).is_err());
    buffer.offer(9).unwrap();
    STATE.with(|state| {
        let state = state.borrow();
        assert_eq!(
            state.offers[0].2.handles[0].rights,
            memory_object::READONLY_BUFFER_RIGHTS
        );
    });
    drop(buffer);
    STATE.with(|state| {
        let state = state.borrow();
        assert_eq!(
            state.calls[state.calls.len() - 2].0,
            syscall::SyscallNumber::MemoryUnmap
        );
        assert_eq!(
            state.calls.last().unwrap().0,
            syscall::SyscallNumber::HandleClose
        );
    });
    assert!(binder_decoration_buffer::TitleBarBuffer::new(0).is_err());
    assert!(binder_decoration_buffer::TitleBarBuffer::new(usize::MAX).is_err());
    reset();
    STATE.with(|state| state.borrow_mut().fail_map = true);
    assert!(binder_decoration_buffer::TitleBarBuffer::new(256).is_err());
    STATE.with(|state| {
        assert_eq!(
            state.borrow().calls.last().unwrap().0,
            syscall::SyscallNumber::HandleClose
        )
    });
}

#[test]
fn stage_sender_and_receiver_own_only_authorized_bounded_ram() {
    reset();
    let mut storage = vec![0x71u8; 8192];
    STATE.with(|state| state.borrow_mut().map_address = Some(storage.as_mut_ptr() as u64));
    let sender = linux_stage_buffer::SharedStageBuffer::new(9, 4096).unwrap();
    assert_eq!(sender.address, storage.as_mut_ptr() as u64);
    assert_eq!(sender.capacity, 4096);
    let wire = STATE.with(|state| state.borrow().offers[0].1.clone());
    let mut attachments = agent_stage_mapping::Attachments::default();
    attachments.handles.count = 1;
    attachments.handles.handles[0].handle = 19;
    let receiver =
        agent_stage_mapping::SharedStageMapping::receive(9, true, &wire, &mut attachments, 4096)
            .unwrap();
    assert!(attachments.is_empty());
    assert_eq!(receiver.snapshot(9, 32).unwrap(), vec![0x71; 32]);
    assert!(receiver.snapshot(10, 32).is_err());
    assert!(receiver.snapshot(9, 0).is_err());
    assert!(receiver.snapshot(9, 4097).is_err());
    drop(sender);
    assert_eq!(receiver.snapshot(9, 1).unwrap(), vec![0x71]);
    drop(receiver);
    drop(attachments);
    for mode in 0..7 {
        reset();
        let mut attachments = agent_stage_mapping::Attachments::default();
        attachments.handles.count = if mode == 1 { 2 } else { 1 };
        attachments.handles.handles[0].handle = 19;
        if mode == 1 {
            attachments.handles.handles[1].handle = 20;
        }
        if mode == 2 {
            STATE.with(|state| state.borrow_mut().extra_rights = mnu_abi::HANDLE_RIGHT_WRITE);
        }
        if mode == 5 {
            STATE.with(|state| state.borrow_mut().fail_length = true);
        }
        if mode == 6 {
            attachments.handles.delivery_flags = 1;
        }
        assert!(
            agent_stage_mapping::SharedStageMapping::receive(
                9,
                mode != 0,
                if mode == 4 { &wire[..31] } else { &wire },
                &mut attachments,
                if mode == 3 { 1 } else { 4096 }
            )
            .is_err()
        );
        drop(attachments);
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
    reset();
    STATE.with(|state| state.borrow_mut().fail_send = true);
    assert!(linux_stage_buffer::SharedStageBuffer::new(9, 4096).is_err());
    STATE.with(|state| {
        let state = state.borrow();
        assert_eq!(
            state.calls[state.calls.len() - 2].0,
            syscall::SyscallNumber::MemoryUnmap
        );
        assert_eq!(
            state.calls.last().unwrap().0,
            syscall::SyscallNumber::HandleClose
        );
    });
}

#[test]
fn linux_buffer_owns_ram_and_retries_attenuated_offers() {
    reset();
    let mut storage = vec![0u8; 4096];
    STATE.with(|state| state.borrow_mut().map_address = Some(storage.as_mut_ptr() as u64));
    let mut buffer = linux_compositor_buffer::SharedBuffer::allocate(16, 16).unwrap();
    buffer.copy_from(&[77; 1024]).unwrap();
    assert!(storage[..1024].iter().all(|&byte| byte == 77));
    assert!(buffer.copy_from(&[0; 4097]).is_err());
    STATE.with(|state| state.borrow_mut().fail_send = true);
    assert!(buffer.send_to(9).is_err());
    STATE.with(|state| state.borrow_mut().fail_send = false);
    buffer.send_to(9).unwrap();
    buffer.send_to(9).unwrap();
    buffer.send_to(10).unwrap();
    STATE.with(|state| {
        let state = state.borrow();
        assert_eq!(state.offers.len(), 2);
        for (_, bytes, handles) in &state.offers {
            assert_eq!(
                memory_object::ReadOnlyOffer::decode(bytes).unwrap().length,
                4096
            );
            assert_eq!(handles.count, 1);
            assert_eq!(
                handles.handles[0].rights,
                memory_object::READONLY_BUFFER_RIGHTS
            );
        }
    });
    drop(buffer);
    STATE.with(|state| {
        let state = state.borrow();
        let last = &state.calls[state.calls.len() - 2..];
        assert_eq!(last[0].0, syscall::SyscallNumber::MemoryUnmap);
        assert_eq!(last[1].0, syscall::SyscallNumber::HandleClose);
    });
    reset();
    STATE.with(|state| state.borrow_mut().fail_map = true);
    assert!(linux_compositor_buffer::SharedBuffer::allocate(16, 16).is_err());
    STATE.with(|state| {
        assert_eq!(
            state.borrow().calls.last().unwrap().0,
            syscall::SyscallNumber::HandleClose
        )
    });
    assert!(linux_compositor_buffer::SharedBuffer::allocate(0, 16).is_err());
}

#[test]
fn viewkit_buffer_owns_mapping_and_retries_readonly_scene_offers() {
    reset();
    let mut bytes = vec![0u8; 4096];
    STATE.with(|state| state.borrow_mut().map_address = Some(bytes.as_mut_ptr() as u64));
    let mut buffer = viewkit_buffer::SharedBuffer::new(16, 16).unwrap();
    assert!(!buffer.is_attached());
    buffer.mark_attached();
    assert!(buffer.is_attached());
    STATE.with(|state| state.borrow_mut().fail_send = true);
    assert_eq!(
        buffer.send_scene_to(9, &[1, 2, 3]),
        Err(MochiOsBackendError::Syscall(11))
    );
    STATE.with(|state| state.borrow_mut().fail_send = false);
    buffer.send_scene_to(9, &[4, 5, 6]).unwrap();
    buffer.send_scene_to(9, &[7, 8, 9]).unwrap();
    assert_eq!(&bytes[..3], &[7, 8, 9]);
    buffer.send_scene_to(10, &[1, 2, 3]).unwrap();
    STATE.with(|state| {
        let state = state.borrow();
        assert_eq!(state.offers.len(), 2);
        for (_, wire, handles) in &state.offers {
            assert_eq!(
                memory_object::ReadOnlyOffer::decode(wire).unwrap().length,
                4096
            );
            assert_eq!(
                handles.handles[0].rights,
                memory_object::READONLY_BUFFER_RIGHTS
            );
        }
    });
    drop(buffer);
    STATE.with(|state| {
        let state = state.borrow();
        assert_eq!(
            state
                .calls
                .iter()
                .filter(|call| call.0 == syscall::SyscallNumber::MemoryUnmap)
                .count(),
            1
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
fn viewkit_pixmap_copy_is_full_for_new_endpoint_and_partial_after_offer() {
    reset();
    let mut bytes = vec![0u8; 4096];
    STATE.with(|state| state.borrow_mut().map_address = Some(bytes.as_mut_ptr() as u64));
    let mut buffer = viewkit_buffer::SharedBuffer::new(2, 1).unwrap();
    let mut pixmap = Pixmap {
        width: 2,
        height: 1,
        bytes: vec![10, 20, 30, 255, 40, 50, 60, 255],
    };
    let background = Color {
        red: 0,
        green: 0,
        blue: 0,
    };
    let dirty = viewkit_buffer::PhysicalDirtyRect {
        x: 0,
        y: 0,
        width: 1,
        height: 1,
    };
    buffer
        .send_pixmap_to(9, &pixmap, background, dirty, 2)
        .unwrap();
    assert_eq!(&bytes[..8], &[30, 20, 10, 255, 60, 50, 40, 255]);
    pixmap.bytes.fill(255);
    buffer
        .send_pixmap_to(9, &pixmap, background, dirty, 2)
        .unwrap();
    assert_eq!(&bytes[..8], &[255, 255, 255, 255, 60, 50, 40, 255]);
    buffer
        .send_pixmap_to(10, &pixmap, background, dirty, 2)
        .unwrap();
    assert_eq!(&bytes[..8], &[255; 8]);
    STATE.with(|state| assert_eq!(state.borrow().offers.len(), 2));
}

#[test]
fn viewkit_buffer_rejects_overflow_and_failed_map_closes_new_object() {
    reset();
    assert!(matches!(
        viewkit_buffer::SharedBuffer::new(usize::MAX, 2),
        Err(MochiOsBackendError::ArithmeticOverflow)
    ));
    STATE.with(|state| state.borrow_mut().fail_map = true);
    assert!(matches!(
        viewkit_buffer::SharedBuffer::new(1, 1),
        Err(MochiOsBackendError::Syscall(13))
    ));
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
}

#[test]
fn compositor_pending_and_current_views_keep_mapping_until_last_reference() {
    use compositor_received_buffer::{ReceivedBuffer, ReceivedHandles};
    reset();
    let bytes = memory_object::ReadOnlyOffer {
        offset: 0,
        length: 4096,
    }
    .encode()
    .unwrap();
    let mut handles = ReceivedHandles::default();
    handles.0.count = 1;
    handles.0.handles[0].handle = 19;
    let pending = ReceivedBuffer::receive(&bytes, &mut handles, 8192).unwrap();
    let current = pending.clone();
    assert_eq!(current.view(), (0x10000, 4096));
    drop(handles);
    drop(pending);
    STATE.with(|state| {
        assert!(
            !state
                .borrow()
                .calls
                .iter()
                .any(|call| call.0 == syscall::SyscallNumber::MemoryUnmap)
        )
    });
    drop(current);
    STATE.with(|state| {
        let state = state.borrow();
        for number in [
            syscall::SyscallNumber::MemoryUnmap,
            syscall::SyscallNumber::HandleClose,
        ] {
            assert_eq!(
                state.calls.iter().filter(|call| call.0 == number).count(),
                1
            );
        }
    });
}

#[test]
fn compositor_deferred_attachments_and_failed_offers_are_drained() {
    use compositor_received_buffer::{ReceivedBuffer, ReceivedHandles};
    let bytes = memory_object::ReadOnlyOffer {
        offset: 0,
        length: 4096,
    }
    .encode()
    .unwrap();
    for mode in 0..4 {
        reset();
        let mut pending = ReceivedHandles::default();
        pending.0.count = if mode == 0 { 2 } else { 1 };
        pending.0.handles[0].handle = 19;
        if mode == 0 {
            pending.0.handles[1].handle = 20;
        }
        if mode == 2 {
            STATE.with(|state| state.borrow_mut().fail_map = true);
        }
        let mut received = core::mem::take(&mut pending);
        drop(pending);
        assert!(
            ReceivedBuffer::receive(
                if mode == 1 { &bytes[..31] } else { &bytes },
                &mut received,
                if mode == 3 { 1 } else { 8192 },
            )
            .is_err()
        );
        drop(received);
        STATE.with(|state| {
            let state = state.borrow();
            assert_eq!(
                state
                    .calls
                    .iter()
                    .filter(|call| call.0 == syscall::SyscallNumber::HandleClose)
                    .count(),
                if mode == 0 { 2 } else { 1 }
            );
            assert!(
                !state
                    .calls
                    .iter()
                    .any(|call| call.0 == syscall::SyscallNumber::MemoryUnmap)
            );
        });
    }
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
        ("MEMORY_MAP", mnu_abi::SyscallNumber::MemoryMap),
        ("MEMORY_UNMAP", mnu_abi::SyscallNumber::MemoryUnmap),
        ("HANDLE_CLOSE", mnu_abi::SyscallNumber::HandleClose),
        (
            "IPC_SEND_HANDLES",
            mnu_abi::SyscallNumber::IpcSendObjectHandles,
        ),
        ("MEMORY_CREATE", mnu_abi::SyscallNumber::MemoryObjectCreate),
    ] {
        assert!(source.contains(&format!("{name} = {}", number as u64)));
    }
}

mod syscall {
    pub use mnu_abi::{
        EACCES, EINVAL, EIO, ENOMEM, HANDLE_RIGHT_MAP, HANDLE_RIGHT_READ, MEMORY_ACCESS_ALL,
        MEMORY_ACCESS_READ, MEMORY_ACCESS_WRITE, MEMORY_MAP_SHARED, MEMORY_OBJECT_RESIZABLE,
        SyscallNumber,
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
                SyscallNumber::MemoryObjectResize if state.fail_resize => {
                    Err(SysError::from_raw(-13))
                }
                SyscallNumber::MemoryMap if state.fail_map => Err(SysError::from_raw(-13)),
                SyscallNumber::MemoryMap => Ok(state.map_address.unwrap_or(0x10000)),
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
fn resizable_owner_requests_explicit_control_creation_and_propagates_resize_errors() {
    reset();
    let object = MemoryObject::create_resizable(0).unwrap();
    object.resize(4097).unwrap();
    STATE.with(|state| state.borrow_mut().fail_resize = true);
    assert_eq!(object.resize(0).unwrap_err().errno(), Some(13));
    assert_eq!(object.handle(), 7);
    STATE.with(|state| {
        let state = state.borrow();
        assert_eq!(
            state.calls[0],
            (syscall::SyscallNumber::MemoryObjectCreate, vec![0, 1])
        );
        assert_eq!(
            state.calls[1],
            (syscall::SyscallNumber::MemoryObjectResize, vec![7, 4097])
        );
        assert_eq!(
            state.calls[2],
            (syscall::SyscallNumber::MemoryObjectResize, vec![7, 0])
        );
    });
    drop(object);
    STATE.with(|state| {
        assert_eq!(
            state.borrow().calls.last().unwrap().0,
            syscall::SyscallNumber::HandleClose
        )
    });
}

#[test]
fn raw_namespace_ownership_transfer_does_not_close_the_returned_reference() {
    reset();
    let raw = MemoryObject::create_resizable(0).unwrap().into_handle();
    assert_eq!(raw, 7);
    STATE.with(|state| assert_eq!(state.borrow().calls.len(), 1));
    handle::close(raw).unwrap();
    STATE.with(|state| assert_eq!(state.borrow().calls.last().unwrap().0, syscall::SyscallNumber::HandleClose));
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
