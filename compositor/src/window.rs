use mochi_user_platform as platform;
use mochios_viewkit_gpu_protocol::window_decoration as metrics;

use crate::client::{Client, ClientId};
use crate::geometry::{Rect, rounded_rect_contains};
use crate::protocol::{
    DECOR_EVENT_WINDOW, EVENT_CONFIGURE, WINDOW_STATE_NORMAL, errno_status, put_i32, put_u32,
    put_u64,
};
use crate::state::getrandom_u64;
use crate::surface::{Surface, SurfaceHandle, SurfaceRole};
use crate::surface::{surface_extent, surface_index_by_handle};

pub(crate) const WINDOW_CORNER_RADIUS: f32 = crate::window_elevation::CORNER_RADIUS;
pub(crate) const WINDOW_SHADOW_MARGIN: u32 = 20;
pub(crate) const ACTIVE_WINDOW_BORDER_ALPHA: u8 = crate::window_elevation::BORDER_ALPHA;
pub(crate) const MAX_WINDOW_TITLE_BYTES: usize = 64;

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct WindowId(pub(crate) u64);

#[derive(Clone, Copy, Default)]
pub(crate) struct Insets {
    pub(crate) left: u32,
    pub(crate) top: u32,
    pub(crate) right: u32,
    pub(crate) bottom: u32,
}

#[derive(Clone, Copy)]
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
    pub(crate) integrated: bool,
    pub(crate) titlebar_height: u32,
    pub(crate) controls_width: u32,
    pub(crate) decoration_scale: u32,
    pub(crate) titlebar_background: u32,
    pub(crate) titlebar_separator: bool,
    pub(crate) metadata_sent: bool,
    pub(crate) configured_width: u32,
    pub(crate) configured_height: u32,
    pub(crate) normal_x: i32,
    pub(crate) normal_y: i32,
    pub(crate) normal_width: u32,
    pub(crate) normal_height: u32,
    pub(crate) title_len: u8,
    pub(crate) title: [u8; MAX_WINDOW_TITLE_BYTES],
    pub(crate) presentation: Option<crate::window_management::Presentation>,
    pub(crate) opening: mochios_viewkit_gpu_protocol::window_motion::Opening,
}

impl Default for Window {
    fn default() -> Self {
        Self::empty()
    }
}

impl Window {
    pub(crate) fn scale_factor(&self) -> f32 {
        self.decoration_scale.clamp(metrics::MIN_SCALE, metrics::MAX_SCALE) as f32 / metrics::SCALE_UNIT as f32
    }
    pub(crate) fn shadow_margin(&self) -> u32 {
        (WINDOW_SHADOW_MARGIN as f32 * self.scale_factor()).ceil() as u32
    }
    pub(crate) fn reveal_travel(&self) -> u32 {
        (metrics::TITLE_BAR_HEIGHT as f32 * self.scale_factor()).round() as u32
    }
    pub(crate) fn reveal_offset_y(&self) -> i32 {
        let remaining = u32::from(255 - self.opening.opacity());
        ((self.reveal_travel() * remaining + 127) / 255) as i32
    }
    pub(crate) fn restore_for_activation(&mut self) {
        if self.state != crate::protocol::WINDOW_STATE_MINIMIZED {
            return;
        }
        if self.presentation.is_none() {
            self.opening = mochios_viewkit_gpu_protocol::window_motion::Opening::pending();
        }
        self.state = if self.presentation.is_some() {
            crate::protocol::WINDOW_STATE_MAXIMIZED
        } else {
            WINDOW_STATE_NORMAL
        };
    }
    pub(crate) fn corner_radius(&self) -> f32 {
        if self.state == crate::protocol::WINDOW_STATE_MAXIMIZED {
            0.0
        } else {
            WINDOW_CORNER_RADIUS * self.scale_factor()
        }
    }
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
            integrated: false,
            titlebar_height: metrics::TITLE_BAR_HEIGHT,
            controls_width: metrics::CONTROLS_WIDTH,
            decoration_scale: metrics::SCALE_UNIT,
            titlebar_background: 0,
            titlebar_separator: true,
            metadata_sent: false,
            configured_width: 0,
            configured_height: 0,
            normal_x: 0,
            normal_y: 0,
            normal_width: 0,
            normal_height: 0,
            title_len: 0,
            title: [0; MAX_WINDOW_TITLE_BYTES],
            presentation: None,
            opening: mochios_viewkit_gpu_protocol::window_motion::Opening::visible(),
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
    let (current_width, current_height) = surface_extent(content);
    let content_width = if window.configured_width == 0 {
        current_width
    } else {
        window.configured_width
    };
    let content_height = if window.configured_height == 0 {
        current_height
    } else {
        window.configured_height
    };
    if content_width == 0 || content_height == 0 {
        return;
    }
    let mut event = [0u8; 136];
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
    let configured_title = &window.title[..usize::from(window.title_len)];
    let title = if configured_title.is_empty() {
        b"mochiOS window".as_slice()
    } else {
        configured_title
    };
    put_u32(&mut event, 44, title.len() as u32);
    event[48..48 + title.len()].copy_from_slice(title);
    put_u32(&mut event, 112, u32::from(window.integrated));
    put_u32(&mut event, 116, window.titlebar_height);
    put_u32(&mut event, 120, window.controls_width);
    put_u32(&mut event, 124, window.titlebar_background);
    put_u32(&mut event, 128, u32::from(window.titlebar_separator));
    put_u32(&mut event, 132, window.decoration_scale);
    let _ = platform::ipc::send(endpoint, &event);
}

pub(crate) fn send_window_configure(surface: &Surface, width: u32, height: u32) {
    if surface.event_endpoint == 0 || width == 0 || height == 0 {
        return;
    }
    let mut event = [0u8; 24];
    put_u32(&mut event, 0, EVENT_CONFIGURE);
    put_i32(&mut event, 4, width as i32);
    put_i32(&mut event, 8, height as i32);
    put_u64(&mut event, 16, surface.token);
    let _ = platform::ipc::send(surface.event_endpoint, &event);
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
    let Some(content_index) = content_surface_index_for_window(surfaces, window) else {
        return;
    };
    if surfaces[content_index].role != SurfaceRole::Toplevel {
        return;
    }
    let mut event = [0u8; 24];
    put_u32(&mut event, 0, crate::protocol::EVENT_WINDOW_DECORATION);
    put_u32(
        &mut event,
        4,
        if window.integrated && window.presentation.is_none() {
            window.titlebar_height
        } else {
            0
        },
    );
    put_u32(
        &mut event,
        8,
        if window.integrated && window.presentation.is_none() {
            window.controls_width
        } else {
            0
        },
    );
    put_u32(&mut event, 12, window.state);
    put_u64(&mut event, 16, surfaces[content_index].token);
    if surfaces[content_index].event_endpoint != 0 {
        let _ = platform::ipc::send(surfaces[content_index].event_endpoint, &event);
    }
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
        if window.integrated {
            let width = if window.configured_width == 0 {
                surface_extent(&surfaces[content_index]).0
            } else {
                window.configured_width
            };
            surfaces[decor_index].x =
                content_x.saturating_add(width.saturating_sub(window.controls_width) as i32);
        }
    }
}

pub(crate) fn point_inside_window_frame(
    surfaces: &[Surface],
    windows: &[Window],
    surface: &Surface,
    x: i32,
    y: i32,
) -> bool {
    let Some(window_index) = window_index_by_id(windows, surface.window) else {
        return true;
    };
    let window = &windows[window_index];
    if window.decoration.is_none() {
        return true;
    }
    let Some(content_index) = content_surface_index_for_window(surfaces, window) else {
        return true;
    };
    let frame = window_frame_rect(&surfaces[content_index], window);
    rounded_rect_contains(frame, window.corner_radius(), x, y)
}

pub(crate) fn window_reveal_source_clip(mut viewport: Rect) -> Rect {
    let travel = (metrics::TITLE_BAR_HEIGHT * metrics::MAX_SCALE).div_ceil(metrics::SCALE_UNIT);
    viewport.y = viewport.y.saturating_sub(travel as i32);
    viewport.height = viewport.height.saturating_add(travel);
    viewport
}

pub(crate) fn window_frame_rect(content: &Surface, window: &Window) -> Rect {
    let (width, height) = surface_extent(content);
    // The client buffer cannot erase or move protected controls by presenting
    // a smaller frame or delaying its response to an interactive configure.
    let (width, height) = if window.integrated {
        (
            if window.configured_width != 0 {
                window.configured_width
            } else {
                width
            }
            .max(window.controls_width),
            if window.configured_height != 0 {
                window.configured_height
            } else {
                height
            }
            .max(window.titlebar_height),
        )
    } else {
        (width, height)
    };
    Rect {
        x: content.x.saturating_sub(window.insets.left as i32),
        y: content.y.saturating_sub(window.insets.top as i32),
        width: width
            .saturating_add(window.insets.left)
            .saturating_add(window.insets.right),
        height: height
            .saturating_add(window.insets.top)
            .saturating_add(window.insets.bottom),
    }
}

/// Control targets of visible maximized windows, including the screen's top
/// and right edges. Panel reveal must not intercept these decoration targets.
pub(crate) fn maximized_controls_overlap(
    surfaces: &[Surface],
    windows: &[Window],
    area: Rect,
) -> bool {
    windows.iter().any(|window| {
        if !window.live
            || window.presentation.is_some()
            || window.state != crate::protocol::WINDOW_STATE_MAXIMIZED
        {
            return false;
        }
        let Some(index) = content_surface_index_for_window(surfaces, window) else {
            return false;
        };
        let content = &surfaces[index];
        if !content.live
            || !content.visible
            || content.role != SurfaceRole::Toplevel
            || window.decoration.is_none()
        {
            return false;
        }
        let frame = window_frame_rect(content, window);
        let width = frame.width.min(window.controls_width.saturating_add(
            metrics::physical_pixels(metrics::CONTROL_REVEAL_MARGIN, window.decoration_scale),
        ));
        let controls = Rect {
            x: frame
                .x
                .saturating_add(frame.width.saturating_sub(width) as i32),
            y: frame.y,
            width,
            height: if window.integrated {
                window.titlebar_height
            } else {
                window.insets.top
            }
            .min(frame.height),
        };
        controls.height > 0
            && i64::from(area.x) < i64::from(controls.x) + i64::from(controls.width)
            && i64::from(controls.x) < i64::from(area.x) + i64::from(area.width)
            && i64::from(area.y) < i64::from(controls.y) + i64::from(controls.height)
            && i64::from(controls.y) < i64::from(area.y) + i64::from(area.height)
    })
}

#[cfg(test)]
mod integrated_frame_tests {
    use super::*;
    #[test]
    fn client_buffers_cannot_shrink_away_protected_controls() {
        let mut content = Surface::empty();
        content.width = 10;
        content.height = 10;
        let mut window = Window::empty();
        window.integrated = true;
        window.controls_width = 224;
        window.titlebar_height = 88;
        let frame = window_frame_rect(&content, &window);
        assert_eq!((frame.width, frame.height), (224, 88));
        window.configured_width = 640;
        window.configured_height = 480;
        let frame = window_frame_rect(&content, &window);
        assert_eq!((frame.width, frame.height), (640, 480));
    }
}

#[cfg(test)]
mod dpi_geometry_tests {
    use super::*;
    #[test]
    fn window_geometry_uses_the_same_scale_as_decoration() {
        for percent in [75, 100, 125, 150, 200] {
            let mut window=Window::empty();
            window.decoration_scale=metrics::SCALE_UNIT*percent/100;
            let scale=window.scale_factor();
            assert!((window.corner_radius()-WINDOW_CORNER_RADIUS*scale).abs()<0.0001);
            assert!(window.shadow_margin() as f32 >= 20.0*scale);
            window.state=crate::protocol::WINDOW_STATE_MAXIMIZED;
            assert_eq!(window.corner_radius(),0.0);
        }
    }
}
