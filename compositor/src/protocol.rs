pub(crate) const OP_CREATE_SURFACE: u32 = 1;
pub(crate) const OP_ATTACH_BUFFER: u32 = 2;
pub(crate) const OP_DAMAGE: u32 = 3;
pub(crate) const OP_COMMIT: u32 = 4;
pub(crate) const OP_SET_POSITION: u32 = 5;
pub(crate) const OP_DESTROY_SURFACE: u32 = 6;
pub(crate) const OP_SET_CURSOR_POSITION: u32 = 7;
pub(crate) const OP_SET_CURSOR_IMAGE: u32 = 8;
pub(crate) const OP_DECOR_SUBSCRIBE: u32 = 100;
pub(crate) const OP_DECOR_CREATE_SURFACE: u32 = 101;
pub(crate) const OP_DECOR_ATTACH: u32 = 102;
pub(crate) const OP_DECOR_DETACH: u32 = 103;
pub(crate) const OP_DECOR_UPDATE_INSETS: u32 = 104;
pub(crate) const OP_DECOR_BEGIN_MOVE: u32 = 105;
pub(crate) const OP_DECOR_BEGIN_RESIZE: u32 = 106;
pub(crate) const OP_DECOR_MINIMIZE: u32 = 107;
pub(crate) const OP_DECOR_TOGGLE_MAXIMIZE: u32 = 108;
pub(crate) const OP_DECOR_CLOSE_REQUEST: u32 = 109;
pub(crate) const OP_DISPLAY_GET_INFO: u32 = 1;
pub(crate) const OP_DISPLAY_PRESENT: u32 = 2;
pub(crate) const OP_DISPLAY_CLAIM_PRESENT_OWNER: u32 = 3;
pub(crate) const OP_DISPLAY_PRESENT_RECT: u32 = 4;
pub(crate) const DECOR_EVENT_WINDOW: u32 = 0x5749_4e44;
pub(crate) const DECOR_EVENT_POINTER_BUTTON: u32 = 0x4e54_4244;
pub(crate) const EVENT_POINTER_ENTER: u32 = 2;
pub(crate) const EVENT_POINTER_LEAVE: u32 = 3;
pub(crate) const EVENT_POINTER_MOTION: u32 = 4;
pub(crate) const EVENT_POINTER_BUTTON: u32 = 5;
pub(crate) const EVENT_KEY: u32 = 6;
pub(crate) const EVENT_FOCUS_GAINED: u32 = 8;
pub(crate) const EVENT_FOCUS_LOST: u32 = 9;
pub(crate) const EVENT_FRAME_DONE: u32 = 10;
pub(crate) const EVENT_CONFIGURE: u32 = 11;
pub(crate) const ROLE_TOPLEVEL: u32 = 1;
pub(crate) const ROLE_POPUP: u32 = 2;
pub(crate) const ROLE_BACKGROUND: u32 = 3;
pub(crate) const ROLE_PANEL: u32 = 4;
pub(crate) const ROLE_SECURE_OVERLAY: u32 = 5;
pub(crate) const PIXEL_FORMAT_XRGB8888: u32 = 1;
pub(crate) const PIXEL_FORMAT_ARGB8888_PREMULTIPLIED: u32 = 2;
pub(crate) const WINDOW_STATE_NORMAL: u32 = 0;
pub(crate) const WINDOW_STATE_MINIMIZED: u32 = 1;
pub(crate) const WINDOW_STATE_MAXIMIZED: u32 = 2;

pub(crate) fn read_u32(buf: &[u8], offset: usize) -> Option<u32> {
    let bytes = buf.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

pub(crate) fn read_pixel(buf: &[u8], offset: usize) -> Option<u32> {
    let bytes = buf.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

pub(crate) fn read_u64(buf: &[u8], offset: usize) -> Option<u64> {
    let bytes = buf.get(offset..offset + 8)?;
    Some(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

pub(crate) fn put_u32(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

pub(crate) fn put_u64(out: &mut [u8], offset: usize, value: u64) {
    out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

pub(crate) fn errno_status(errno: u64) -> u32 {
    let signed = errno as i64;
    if signed < 0 {
        signed.wrapping_neg() as u32
    } else {
        errno as u32
    }
}

pub(crate) fn put_i32(out: &mut [u8], offset: usize, value: i32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
