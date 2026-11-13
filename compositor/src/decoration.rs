use mochi_user_platform as platform;

use crate::client::{Client, ClientId};
use crate::geometry::Rect;
use crate::input::{PointerGrab, PointerSerial, send_event};
use crate::protocol::*;
use crate::state::MAX_DIMENSION;
use crate::surface::{
    Surface, SurfaceHandle, SurfaceRights, SurfaceRole, generate_surface_token, surface_index_for,
};
use crate::window::{
    Insets, Window, content_surface_index_for_window, decoration_surface_index_for_window,
    notify_decorators, reposition_window_surfaces, send_window_configure, send_window_metadata,
    window_index_by_token,
};

const DECORATE_CAPABILITY: &str = "window.decorate";
const DECORATE_COMPAT_CAPABILITY: &str = "window.overlay";
const SECURE_OVERLAY_CAPABILITY: &str = "window.secure-overlay";
const DECOR_TITLE_BAR_HEIGHT: u32 = 40;

fn sender_has_decorate_capability(sender: u64) -> bool {
    matches!(
        platform::capability::check_thread(sender, DECORATE_CAPABILITY),
        Ok(1)
    ) || matches!(
        platform::capability::check_thread(sender, DECORATE_COMPAT_CAPABILITY),
        Ok(1)
    )
}

pub(crate) fn sender_has_overlay_compat_capability(sender: u64) -> bool {
    matches!(
        platform::capability::check_thread(sender, DECORATE_COMPAT_CAPABILITY),
        Ok(1)
    )
}

pub(crate) fn sender_has_secure_overlay_capability(sender: u64) -> bool {
    matches!(
        platform::capability::check_thread(sender, SECURE_OVERLAY_CAPABILITY),
        Ok(1)
    )
}

pub(crate) fn sender_can_control_cursor(sender: u64) -> bool {
    sender_has_overlay_compat_capability(sender) || sender_has_secure_overlay_capability(sender)
}

fn rectangles_overlap(first: Rect, second: Rect) -> bool {
    let left = i64::from(first.x).max(i64::from(second.x));
    let top = i64::from(first.y).max(i64::from(second.y));
    let right = (i64::from(first.x) + i64::from(first.width))
        .min(i64::from(second.x) + i64::from(second.width));
    let bottom = (i64::from(first.y) + i64::from(first.height))
        .min(i64::from(second.y) + i64::from(second.height));
    right > left && bottom > top
}

fn native_window_overlaps(windows: &[Window], surfaces: &[Surface], area: Rect) -> bool {
    windows.iter().any(|window| {
        if !window.live || window.state == WINDOW_STATE_MINIMIZED {
            return false;
        }
        let Some(content_index) = content_surface_index_for_window(surfaces, window) else {
            return false;
        };
        let content = &surfaces[content_index];
        if content.role != SurfaceRole::Toplevel || !content.visible {
            return false;
        }
        if window.state == WINDOW_STATE_MAXIMIZED {
            return true;
        }
        rectangles_overlap(crate::window::window_frame_rect(content, window), area)
    })
}

pub(crate) fn handle_request(
    clients: &mut [Client],
    surfaces: &mut [Surface],
    windows: &mut [Window],
    next_z: &mut u32,
    pointer_serials: &mut [PointerSerial],
    _pointer_focus: &mut Option<usize>,
    keyboard_focus: &mut Option<usize>,
    pointer_grab: &mut Option<PointerGrab>,
    pointer_x: i32,
    pointer_y: i32,
    client: ClientId,
    sender: u64,
    request: &[u8],
    needs_present: &mut bool,
    display_width: u32,
    display_height: u32,
) -> [u8; 16] {
    let mut reply = [0u8; 16];
    let Some(opcode) = read_u32(request, 0) else {
        put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EINVAL));
        return reply;
    };
    match opcode {
        OP_SET_DECORATION => {
            let surface_token = read_u64(request, 4).unwrap_or(0);
            let mode = read_u32(request, 12).unwrap_or(u32::MAX);
            let height = read_u32(request, 16).unwrap_or(0);
            let scale = read_u32(request, 24).unwrap_or(0);
            if request.len() != 32
                || mode > 1
                || !(256..=8192).contains(&scale)
                || height > MAX_DIMENSION
            {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EINVAL));
                return reply;
            }
            let Some(content_index) = surface_index_for(
                surfaces,
                client,
                SurfaceHandle(surface_token),
                SurfaceRights::COMMIT,
            ) else {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            };
            if surfaces[content_index].is_decoration
                || surfaces[content_index].role != SurfaceRole::Toplevel
            {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            }
            let Some(index) =
                crate::window::window_index_by_id(windows, surfaces[content_index].window)
            else {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            };
            let flags = read_u32(request, 28).unwrap_or(u32::MAX);
            if flags & !3 != 0 {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EINVAL));
                return reply;
            }
            windows[index].titlebar_separator = flags & 1 != 0;
            windows[index].resizable = flags & 2 != 0;
            windows[index].integrated = mode == 1;
            windows[index].titlebar_height = height.max((40 * scale + 1023) / 1024);
            windows[index].controls_width = (112 * scale + 1023) / 1024;
            windows[index].titlebar_background = read_u32(request, 20).unwrap_or(0) | 0xff;
            windows[index].insets.top = if mode == 1 {
                0
            } else {
                windows[index].titlebar_height
            };
            let (width, height) = crate::surface::surface_extent(&surfaces[content_index]);
            let next_width = width.max(windows[index].controls_width);
            let next_height = height.max(windows[index].titlebar_height);
            if mode == 1
                && (width != next_width || height != next_height)
                && width != 0
                && height != 0
            {
                windows[index].configured_width = next_width;
                windows[index].configured_height = next_height;
                send_window_configure(&surfaces[content_index], next_width, next_height);
            }
            reposition_window_surfaces(surfaces, &windows[index]);
            notify_decorators(clients, windows, surfaces, index);
            *needs_present = true;
            put_u32(
                &mut reply,
                4,
                if mode == 1 {
                    windows[index].titlebar_height
                } else {
                    0
                },
            );
            put_u32(
                &mut reply,
                8,
                if mode == 1 {
                    windows[index].controls_width
                } else {
                    0
                },
            );
            put_u32(&mut reply, 12, windows[index].state);
        }
        OP_DECOR_QUERY_OVERLAP | OP_DECOR_SAMPLE_BACKGROUND => {
            if !sender_has_decorate_capability(sender) {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            }
            let area = Rect {
                x: read_u32(request, 4).unwrap_or(0) as i32,
                y: read_u32(request, 8).unwrap_or(0) as i32,
                width: read_u32(request, 12).unwrap_or(0),
                height: read_u32(request, 16).unwrap_or(0),
            };
            if request.len() != 20
                || area.width == 0
                || area.height == 0
                || area.width > MAX_DIMENSION
                || area.height > MAX_DIMENSION
            {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EINVAL));
                return reply;
            }
            put_u32(&mut reply, 0, 0);
            if opcode == OP_DECOR_SAMPLE_BACKGROUND {
                if let Some(color) = crate::backdrop::sample_background(surfaces, windows, area) {
                    put_u32(&mut reply, 4, 1);
                    put_u32(&mut reply, 8, color);
                }
            } else {
                put_u32(
                    &mut reply,
                    4,
                    u32::from(native_window_overlaps(windows, surfaces, area)),
                );
                // Existing clients read offset 4; the reserved word at 8 adds
                // control exclusion without changing the request or reply size.
                put_u32(
                    &mut reply,
                    8,
                    u32::from(crate::window::maximized_controls_overlap(
                        surfaces, windows, area,
                    )),
                );
            }
        }
        OP_DECOR_SUBSCRIBE => {
            if !sender_has_decorate_capability(sender) {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            }
            let endpoint = read_u64(request, 4).unwrap_or(0);
            if endpoint == 0 {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EINVAL));
                return reply;
            }
            if let Some(record) = clients
                .iter_mut()
                .find(|record| record.live && record.id == client)
            {
                record.decoration_endpoint = endpoint;
            }
            for window in windows
                .iter()
                .filter(|window| window.live && window.metadata_sent)
            {
                send_window_metadata(window, surfaces, endpoint);
            }
            put_u32(&mut reply, 0, 0);
        }
        OP_DECOR_CREATE_SURFACE => {
            if !sender_has_decorate_capability(sender) {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            }
            let window_token = read_u64(request, 4).unwrap_or(0);
            let width = read_u32(request, 12).unwrap_or(0);
            let height = read_u32(request, 16).unwrap_or(0);
            let event_endpoint = read_u64(request, 20).unwrap_or(0);
            if width == 0 || height == 0 || width > MAX_DIMENSION || height > MAX_DIMENSION {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EINVAL));
                return reply;
            }
            let Some(window_index) = window_index_by_token(windows, window_token) else {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            };
            let Some(content_index) =
                content_surface_index_for_window(surfaces, &windows[window_index])
            else {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            };
            let Some(index) = surfaces.iter().position(|surface| !surface.live) else {
                put_u32(&mut reply, 0, STATUS_CAPACITY_EXCEEDED);
                return reply;
            };
            let token = match generate_surface_token(surfaces) {
                Ok(token) => token,
                Err(status) => {
                    put_u32(&mut reply, 0, status);
                    return reply;
                }
            };
            *next_z = next_z.wrapping_add(1);
            let handle = SurfaceHandle(token);
            surfaces[index].reset();
            surfaces[index].live = true;
            surfaces[index].owner = client;
            surfaces[index].event_endpoint = event_endpoint;
            surfaces[index].handle = handle;
            surfaces[index].token = token;
            surfaces[index].role = SurfaceRole::Popup;
            surfaces[index].rights = SurfaceRights::GENERAL_CLIENT;
            surfaces[index].window = windows[window_index].id;
            surfaces[index].is_decoration = true;
            surfaces[index].visible = true;
            surfaces[index].x = surfaces[content_index].x;
            surfaces[index].y = surfaces[content_index]
                .y
                .saturating_sub(DECOR_TITLE_BAR_HEIGHT as i32);
            surfaces[index].width = width;
            surfaces[index].height = height;
            surfaces[index].z = *next_z;
            put_u32(&mut reply, 0, 0);
            reply[4..12].copy_from_slice(&token.to_le_bytes());
        }
        OP_DECOR_ATTACH => {
            if !sender_has_decorate_capability(sender) {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            }
            let window_token = read_u64(request, 4).unwrap_or(0);
            let decoration_token = read_u64(request, 12).unwrap_or(0);
            let insets = Insets {
                left: read_u32(request, 20).unwrap_or(0),
                top: read_u32(request, 24).unwrap_or(0),
                right: read_u32(request, 28).unwrap_or(0),
                bottom: read_u32(request, 32).unwrap_or(0),
            };
            if insets.left > MAX_DIMENSION
                || insets.top > MAX_DIMENSION
                || insets.right > MAX_DIMENSION
                || insets.bottom > MAX_DIMENSION
            {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EINVAL));
                return reply;
            }
            let Some(window_index) = window_index_by_token(windows, window_token) else {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            };
            let handle = SurfaceHandle(decoration_token);
            let Some(decoration_index) =
                surface_index_for(surfaces, client, handle, SurfaceRights::COMMIT)
            else {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            };
            if !surfaces[decoration_index].is_decoration
                || surfaces[decoration_index].window != windows[window_index].id
            {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            }
            if surfaces[decoration_index].current_buffer.is_none()
                && surfaces[decoration_index].current.is_empty()
                && (surfaces[decoration_index].pending_buffer.is_some()
                    || !surfaces[decoration_index].pending.is_empty())
                && surfaces[decoration_index].pending_width != 0
                && surfaces[decoration_index].pending_height != 0
            {
                let surface = &mut surfaces[decoration_index];
                let pending_width = surface.pending_width;
                let pending_height = surface.pending_height;
                let pending_stride = surface.pending_stride;
                surface.current_buffer = surface.pending_buffer.take();
                if surface.current_buffer.is_some() {
                    surface.current.clear();
                } else {
                    core::mem::swap(&mut surface.current, &mut surface.pending);
                }
                surface.current_width = pending_width;
                surface.current_height = pending_height;
                surface.current_stride = pending_stride;
                surface.current_format = surface.pending_format;
                surface.pending_width = 0;
                surface.pending_height = 0;
                surface.pending_stride = 0;
                surface.pending_format = PIXEL_FORMAT_XRGB8888;
                surface.pending_len = 0;
                surface.pending_damage = None;
                surface.pending_buffer = None;
                surface.awaiting_buffer = false;
            }
            windows[window_index].decoration = Some(handle);
            windows[window_index].decorator = client;
            *needs_present = true;
            windows[window_index].decorator_endpoint = surfaces[decoration_index].event_endpoint;
            windows[window_index].insets = insets;
            if windows[window_index].integrated {
                windows[window_index].insets = Insets::default();
            }
            if let Some(content_index) =
                content_surface_index_for_window(surfaces, &windows[window_index])
            {
                surfaces[content_index].y = surfaces[content_index]
                    .y
                    .max(40i32.saturating_add(insets.top as i32));
            }
            reposition_window_surfaces(surfaces, &windows[window_index]);
            let active = content_surface_index_for_window(surfaces, &windows[window_index])
                .is_some_and(|index| *keyboard_focus == Some(index));
            send_event(
                surfaces[decoration_index].event_endpoint,
                surfaces[decoration_index].token,
                if active {
                    EVENT_FOCUS_GAINED
                } else {
                    EVENT_FOCUS_LOST
                },
                0,
                0,
                0,
            );
            put_u32(&mut reply, 0, 0);
        }
        OP_DECOR_DETACH => {
            if !sender_has_decorate_capability(sender) {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            }
            let window_token = read_u64(request, 4).unwrap_or(0);
            let Some(window_index) = window_index_by_token(windows, window_token) else {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            };
            if windows[window_index].decorator != client {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            }
            windows[window_index].decoration = None;
            windows[window_index].decorator = ClientId(0);
            windows[window_index].decorator_endpoint = 0;
            put_u32(&mut reply, 0, 0);
        }
        OP_DECOR_UPDATE_INSETS => {
            if !sender_has_decorate_capability(sender) {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            }
            let window_token = read_u64(request, 4).unwrap_or(0);
            let Some(window_index) = window_index_by_token(windows, window_token) else {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            };
            if windows[window_index].decorator != client {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            }
            windows[window_index].insets = Insets {
                left: read_u32(request, 12).unwrap_or(0).min(MAX_DIMENSION),
                top: read_u32(request, 16).unwrap_or(0).min(MAX_DIMENSION),
                right: read_u32(request, 20).unwrap_or(0).min(MAX_DIMENSION),
                bottom: read_u32(request, 24).unwrap_or(0).min(MAX_DIMENSION),
            };
            if windows[window_index].integrated {
                windows[window_index].insets = Insets::default();
            }
            reposition_window_surfaces(surfaces, &windows[window_index]);
            put_u32(&mut reply, 0, 0);
        }
        OP_DECOR_BEGIN_MOVE | OP_DECOR_BEGIN_RESIZE => {
            if request.len() != 28 {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EINVAL));
                return reply;
            }
            let token = read_u64(request, 4).unwrap_or(0);
            let serial = read_u64(request, 12).unwrap_or(0);
            let owner_surface = surface_index_for(
                surfaces,
                client,
                SurfaceHandle(token),
                SurfaceRights::COMMIT,
            )
            .filter(|&i| !surfaces[i].is_decoration && surfaces[i].role == SurfaceRole::Toplevel);
            let index = owner_surface
                .and_then(|i| crate::window::window_index_by_id(windows, surfaces[i].window))
                .or_else(|| {
                    window_index_by_token(windows, token).filter(|&i| {
                        windows[i].decorator == client && sender_has_decorate_capability(sender)
                    })
                });
            let Some(index) = index else {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            };
            let expected = owner_surface
                .map(|i| surfaces[i].handle)
                .or(windows[index].decoration);
            let Some(serial_index) = pointer_serials.iter().position(|r| {
                serial != 0
                    && r.serial == serial
                    && r.window == windows[index].id
                    && !r.used
                    && Some(r.decoration) == expected
            }) else {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            };
            let edges = if opcode == OP_DECOR_BEGIN_RESIZE {
                read_u32(request, 20).unwrap_or(0)
            } else {
                0
            };
            if opcode == OP_DECOR_BEGIN_RESIZE
                && (!windows[index].resizable || !matches!(edges, 1 | 2 | 4 | 8 | 5 | 6 | 9 | 10))
            {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EINVAL));
                return reply;
            }
            if windows[index].state != WINDOW_STATE_NORMAL {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EINVAL));
                return reply;
            }
            let Some(content) = content_surface_index_for_window(surfaces, &windows[index]) else {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            };
            pointer_serials[serial_index].used = true;
            let (width, height) = crate::surface::surface_extent(&surfaces[content]);
            let (dx, dy) = if owner_surface.is_none() && opcode == OP_DECOR_BEGIN_MOVE {
                (
                    read_u32(request, 20).unwrap_or(0) as i32,
                    read_u32(request, 24).unwrap_or(0) as i32,
                )
            } else {
                (0, 0)
            };
            *pointer_grab = Some(PointerGrab {
                window: windows[index].id,
                pointer_x: pointer_x.saturating_sub(dx),
                pointer_y: pointer_y.saturating_sub(dy),
                content_x: surfaces[content].x,
                content_y: surfaces[content].y,
                resize_edges: edges,
                width,
                height,
            });
        }
        OP_DECOR_MINIMIZE | OP_DECOR_TOGGLE_MAXIMIZE => {
            if !sender_has_decorate_capability(sender) {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            }
            let window_token = read_u64(request, 4).unwrap_or(0);
            let Some(window_index) = window_index_by_token(windows, window_token) else {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            };
            if windows[window_index].decorator != client {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            }
            if opcode == OP_DECOR_MINIMIZE {
                windows[window_index].state = WINDOW_STATE_MINIMIZED;
            } else {
                let maximizing = windows[window_index].state != WINDOW_STATE_MAXIMIZED;
                if let Some(content_index) =
                    content_surface_index_for_window(surfaces, &windows[window_index])
                {
                    let (current_width, current_height) =
                        crate::surface::surface_extent(&surfaces[content_index]);
                    if maximizing {
                        windows[window_index].normal_x = surfaces[content_index].x;
                        windows[window_index].normal_y = surfaces[content_index].y;
                        windows[window_index].normal_width = current_width;
                        windows[window_index].normal_height = current_height;
                        let insets = windows[window_index].insets;
                        let width = display_width
                            .saturating_sub(insets.left)
                            .saturating_sub(insets.right)
                            .max(1);
                        let height = display_height
                            .saturating_sub(insets.top)
                            .saturating_sub(insets.bottom)
                            .max(1);
                        surfaces[content_index].x = insets.left as i32;
                        surfaces[content_index].y = insets.top as i32;
                        windows[window_index].configured_width = width;
                        windows[window_index].configured_height = height;
                        send_window_configure(&surfaces[content_index], width, height);
                        windows[window_index].state = WINDOW_STATE_MAXIMIZED;
                    } else {
                        let width = windows[window_index].normal_width.max(1);
                        let height = windows[window_index].normal_height.max(1);
                        surfaces[content_index].x = windows[window_index].normal_x;
                        surfaces[content_index].y = windows[window_index].normal_y;
                        windows[window_index].configured_width = width;
                        windows[window_index].configured_height = height;
                        send_window_configure(&surfaces[content_index], width, height);
                        windows[window_index].state = WINDOW_STATE_NORMAL;
                    }
                    reposition_window_surfaces(surfaces, &windows[window_index]);
                    notify_decorators(clients, windows, surfaces, window_index);
                }
            }
            let visible = windows[window_index].state != WINDOW_STATE_MINIMIZED;
            if let Some(content_index) =
                content_surface_index_for_window(surfaces, &windows[window_index])
            {
                surfaces[content_index].visible = visible;
            }
            if let Some(decoration_index) =
                decoration_surface_index_for_window(surfaces, &windows[window_index])
            {
                surfaces[decoration_index].visible = visible;
            }
            *needs_present = true;
            put_u32(&mut reply, 0, 0);
        }
        OP_DECOR_CLOSE_REQUEST => {
            if !sender_has_decorate_capability(sender) {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            }
            let window_token = read_u64(request, 4).unwrap_or(0);
            let Some(window_index) = window_index_by_token(windows, window_token) else {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            };
            if windows[window_index].decorator != client {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            }
            if let Some(content_index) =
                content_surface_index_for_window(surfaces, &windows[window_index])
            {
                send_event(
                    surfaces[content_index].event_endpoint,
                    surfaces[content_index].token,
                    EVENT_CLOSE_REQUESTED,
                    0,
                    0,
                    0,
                );
            }
            put_u32(&mut reply, 0, 0);
        }
        _ => put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EINVAL)),
    }
    reply
}

#[cfg(test)]
#[path = "decoration_tests.rs"]
mod integrated_tests;
