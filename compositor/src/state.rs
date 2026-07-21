use alloc::vec;
use alloc::vec::Vec;

use crate::client::Client;
use crate::input::PointerSerial;
use crate::renderer::PresentFrame;
use crate::surface::Surface;
use crate::window::Window;
use crate::{MAX_CLIENTS, MAX_SURFACES, MAX_WINDOWS};

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
    pub(crate) pointer_focus: Option<usize>,
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
}

impl CompositorState {
    pub(crate) fn new(
        display_tid: u64,
        display_width: u32,
        display_height: u32,
        display_stride: u32,
        display_format: u32,
        input_subscribed: bool,
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
            pointer_focus: None,
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
        }
    }
}
