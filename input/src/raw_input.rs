//! Only the kernel's endpoint-Handle delivery proof admits raw driver packets.
//! A packet's own fields cannot assert that its sender holds that authority.
use mochi_user_platform::{input, ipc};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Packet {
    Keyboard { byte: u8, synthetic: bool },
    Mouse([u8; 4]),
    Absolute([u8; 8]),
}

pub(crate) fn decode(bytes: &[u8], handles: &ipc::IpcObjectHandles) -> Option<Packet> {
    if handles.delivery_flags != ipc::IPC_DELIVERY_ENDPOINT_HANDLE || handles.count != 0 {
        return None;
    }
    let header = bytes.get(..4)?;
    if header[2..4] != [0; 2] {
        return None;
    }
    match header[0] {
        input::RAW_KIND_KEYBOARD
            if bytes.len() == 8
                && header[1] & !input::RAW_FLAG_SYNTHETIC == 0
                && bytes[5..8] == [0; 3] =>
        {
            Some(Packet::Keyboard {
                byte: bytes[4],
                synthetic: header[1] & input::RAW_FLAG_SYNTHETIC != 0,
            })
        }
        input::RAW_KIND_MOUSE_PACKET if bytes.len() == 8 && header[1] == 0 => {
            Some(Packet::Mouse(bytes[4..8].try_into().ok()?))
        }
        input::RAW_KIND_POINTER_ABSOLUTE
            if bytes.len() == 12 && header[1] == 0 && bytes[5] == 0 && bytes[10..12] == [0; 2] =>
        {
            Some(Packet::Absolute(bytes[4..12].try_into().ok()?))
        }
        _ => None,
    }
}

pub(crate) fn close_handles(handles: &ipc::IpcObjectHandles) {
    for entry in handles.handles.iter().take(handles.count as usize) {
        if entry.handle != 0 {
            let _ = mochi_user_platform::handle::close(entry.handle);
        }
    }
}
