use alloc::vec;
use alloc::vec::Vec;

use crate::client::Client;
use crate::cursor::CursorImage;
use crate::input::{PointerGrab, PointerSerial};
use crate::renderer::PresentFrame;
use crate::surface::Surface;
use crate::window::Window;

pub(crate) const MAX_SURFACES: usize = 16;
pub(crate) const MAX_WINDOWS: usize = 8;
pub(crate) const MAX_CLIENTS: usize = 16;
pub(crate) const PAGE_SIZE: usize = 4096;
pub(crate) const MAX_SHARED_PAGES: usize = 262_144;
pub(crate) const MAX_SHARED_BYTES: usize = MAX_SHARED_PAGES * PAGE_SIZE;
pub(crate) const MAX_SHARED_PIXELS: usize = MAX_SHARED_BYTES / 4;
pub(crate) const MAX_DIMENSION: u32 = 16_384;

static mut TOKEN_RANDOM_BUF: [u8; 8] = [0; 8];

pub(crate) fn getrandom_u64() -> Option<u64> {
    let bytes = unsafe {
        core::slice::from_raw_parts_mut(core::ptr::addr_of_mut!(TOKEN_RANDOM_BUF).cast::<u8>(), 8)
    };
    let len = match mochi_user_syscall::call3(
        mochi_user_syscall::SyscallNumber::Getrandom,
        bytes.as_mut_ptr() as u64,
        bytes.len() as u64,
        0,
    ) {
        Ok(len) => len,
        Err(err) => {
            mochi_user_platform::println!(
                "compositor.service: getrandom failed errno={}",
                err.errno().unwrap_or(0)
            );
            return None;
        }
    };
    if len == bytes.len() as u64 {
        Some(u64::from_ne_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    } else {
        mochi_user_platform::println!("compositor.service: getrandom short read len={}", len);
        None
    }
}

pub(crate) struct CompositorState {
    pub(crate) clients: [Client; MAX_CLIENTS],
    pub(crate) next_client_id: u64,
    pub(crate) surfaces: Vec<Surface>,
    pub(crate) windows: [Window; MAX_WINDOWS],
    pub(crate) next_z: u32,
    pub(crate) next_window_index: u32,
    pub(crate) next_window_id: u64,
    pub(crate) next_pointer_serial: u64,
    pub(crate) pointer_serials: [PointerSerial; 32],
    pub(crate) pointer_x: i32,
    pub(crate) pointer_y: i32,
    pub(crate) cursor_x: i32,
    pub(crate) cursor_y: i32,
    pub(crate) cursor_visible: bool,
    pub(crate) cursor_image: CursorImage,
    pub(crate) hardware_cursor: bool,
    pub(crate) pointer_focus: Option<usize>,
    pub(crate) pointer_grab: Option<PointerGrab>,
    pub(crate) keyboard_focus: Option<usize>,
    pub(crate) idle_cleanup_ticks: u32,
    pub(crate) input_subscribe_retry_ticks: u32,
    pub(crate) present_frame: PresentFrame,
    pub(crate) display_tid: u64,
    pub(crate) display_width: u32,
    pub(crate) display_height: u32,
    pub(crate) display_stride: u32,
    pub(crate) display_format: u32,
    pub(crate) input_subscribed: bool,
    pub(crate) renderer_caps: u32,
}

impl CompositorState {
    pub(crate) fn new(
        display_tid: u64,
        display_width: u32,
        display_height: u32,
        display_stride: u32,
        display_format: u32,
        input_subscribed: bool,
        renderer_caps: u32,
    ) -> Self {
        Self {
            clients: [Client::default(); MAX_CLIENTS],
            next_client_id: 0,
            surfaces: vec![Surface::empty(); MAX_SURFACES],
            windows: [Window::empty(); MAX_WINDOWS],
            next_z: 0,
            next_window_index: 0,
            next_window_id: 0,
            next_pointer_serial: 0,
            pointer_serials: [PointerSerial::default(); 32],
            pointer_x: (display_width / 2).min(display_width.saturating_sub(1)) as i32,
            pointer_y: (display_height / 2).min(display_height.saturating_sub(1)) as i32,
            cursor_x: 0,
            cursor_y: 0,
            cursor_visible: false,
            cursor_image: CursorImage::default(),
            hardware_cursor: false,
            pointer_focus: None,
            pointer_grab: None,
            keyboard_focus: None,
            idle_cleanup_ticks: 0,
            input_subscribe_retry_ticks: 0,
            present_frame: PresentFrame::default(),
            display_tid,
            display_width,
            display_height,
            display_stride,
            display_format,
            input_subscribed,
            renderer_caps,
        }
    }
}
