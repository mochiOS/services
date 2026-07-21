use mochi_user_platform as platform;

use crate::client::{Client, ClientId};
use crate::protocol::{DECOR_EVENT_WINDOW, WINDOW_STATE_NORMAL, errno_status, put_u32, put_u64};
use crate::surface::{Surface, SurfaceHandle};
use crate::{getrandom_u64, surface_extent, surface_index_by_handle};

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct WindowId(pub(crate) u64);

#[derive(Clone, Copy, Default)]
pub(crate) struct Insets {
    pub(crate) left: u32,
    pub(crate) top: u32,
    pub(crate) right: u32,
    pub(crate) bottom: u32,
}

#[derive(Clone, Copy, Default)]
pub(crate) struct Window {
    pub(crate) live: bool,
    pub(crate) id: WindowId,
    pub(crate) token: u64,
    pub(crate) content: SurfaceHandle,
    pub(crate) decoration: Option<SurfaceHandle>,
    pub(crate) decorator: ClientId,
    pub(crate) decorator_endpoint: u64,
    pub(crate) insets: Insets,
    pub(crate) state: u32,
    pub(crate) resizable: bool,
    pub(crate) close_requested: bool,
    pub(crate) metadata_sent: bool,
}

impl Window {
    pub(crate) const fn empty() -> Self {
        Self {
            live: false,
            id: WindowId(0),
            token: 0,
            content: SurfaceHandle(0),
            decoration: None,
            decorator: ClientId(0),
            decorator_endpoint: 0,
            insets: Insets {
                left: 0,
                top: 0,
                right: 0,
                bottom: 0,
            },
            state: WINDOW_STATE_NORMAL,
            resizable: true,
            close_requested: false,
            metadata_sent: false,
        }
    }
}

pub(crate) fn generate_window_token(windows: &[Window]) -> Result<u64, u32> {
    for _ in 0..16 {
        let Some(token) = getrandom_u64() else {
            return Err(errno_status(mochi_user_syscall::EIO));
        };
        if token != 0
            && windows
                .iter()
                .all(|window| !window.live || window.token != token)
        {
            return Ok(token);
        }
    }
    Err(errno_status(mochi_user_syscall::EAGAIN))
}

pub(crate) fn window_index_by_token(windows: &[Window], token: u64) -> Option<usize> {
    windows
        .iter()
        .position(|window| window.live && window.token == token)
}

pub(crate) fn window_index_by_id(windows: &[Window], id: WindowId) -> Option<usize> {
    windows
        .iter()
        .position(|window| window.live && window.id == id)
}

pub(crate) fn content_surface_index_for_window(
    surfaces: &[Surface],
    window: &Window,
) -> Option<usize> {
    surface_index_by_handle(surfaces, window.content)
}

pub(crate) fn decoration_surface_index_for_window(
    surfaces: &[Surface],
    window: &Window,
) -> Option<usize> {
    surface_index_by_handle(surfaces, window.decoration?)
}

pub(crate) fn send_window_metadata(window: &Window, surfaces: &[Surface], endpoint: u64) {
    if endpoint == 0 || !window.live {
        return;
    }
    let Some(content_index) = content_surface_index_for_window(surfaces, window) else {
        return;
    };
    let content = &surfaces[content_index];
    let (content_width, content_height) = surface_extent(content);
    if content_width == 0 || content_height == 0 {
        return;
    }
    let mut event = [0u8; 80];
    put_u32(&mut event, 0, DECOR_EVENT_WINDOW);
    put_u64(&mut event, 4, window.token);
    put_u32(&mut event, 12, content_width);
    put_u32(&mut event, 16, content_height);
    put_u32(&mut event, 20, u32::from(window.resizable));
    put_u32(&mut event, 24, window.state);
    put_u32(&mut event, 28, window.insets.left);
    put_u32(&mut event, 32, window.insets.top);
    put_u32(&mut event, 36, window.insets.right);
    put_u32(&mut event, 40, window.insets.bottom);
    let title = b"mochiOS window";
    put_u32(&mut event, 44, title.len() as u32);
    event[48..48 + title.len()].copy_from_slice(title);
    let _ = platform::ipc::send(endpoint, &event);
}

pub(crate) fn notify_decorators(
    clients: &[Client],
    windows: &[Window],
    surfaces: &[Surface],
    window_index: usize,
) {
    let Some(window) = windows.get(window_index) else {
        return;
    };
    for client in clients
        .iter()
        .filter(|client| client.live && client.decoration_endpoint != 0)
    {
        send_window_metadata(window, surfaces, client.decoration_endpoint);
    }
}

pub(crate) fn reposition_window_surfaces(surfaces: &mut [Surface], window: &Window) {
    let Some(content_index) = content_surface_index_for_window(surfaces, window) else {
        return;
    };
    let content_x = surfaces[content_index].x;
    let content_y = surfaces[content_index].y;
    if let Some(decor_index) = decoration_surface_index_for_window(surfaces, window) {
        surfaces[decor_index].x = content_x.saturating_sub(window.insets.left as i32);
        surfaces[decor_index].y = content_y.saturating_sub(window.insets.top as i32);
    }
}
