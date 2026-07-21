use mochi_user_platform as platform;

use crate::client::{Client, ClientId};
use crate::input::PointerSerial;
use crate::protocol::*;
use crate::state::MAX_DIMENSION;
use crate::surface::{
    Surface, SurfaceHandle, SurfaceRights, SurfaceRole, destroy_surface_tree,
    generate_surface_token, surface_index_for,
};
use crate::window::{
    Insets, Window, content_surface_index_for_window, decoration_surface_index_for_window,
    reposition_window_surfaces, send_window_metadata, window_index_by_token,
};

const DECORATE_CAPABILITY: &str = "window.decorate";
const DECORATE_COMPAT_CAPABILITY: &str = "window.overlay";
const DECOR_TITLE_BAR_HEIGHT: u32 = 28;

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

pub(crate) fn handle_request(
    clients: &mut [Client],
    surfaces: &mut [Surface],
    windows: &mut [Window],
    next_z: &mut u32,
    pointer_serials: &mut [PointerSerial],
    pointer_focus: &mut Option<usize>,
    keyboard_focus: &mut Option<usize>,
    client: ClientId,
    sender: u64,
    request: &[u8],
    needs_present: &mut bool,
) -> [u8; 16] {
    let mut reply = [0u8; 16];
    let Some(opcode) = read_u32(request, 0) else {
        put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EINVAL));
        return reply;
    };
    match opcode {
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
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::ENOSPC));
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
                surface.pending_width = 0;
                surface.pending_height = 0;
                surface.pending_stride = 0;
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
            reposition_window_surfaces(surfaces, &windows[window_index]);
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
            reposition_window_surfaces(surfaces, &windows[window_index]);
            put_u32(&mut reply, 0, 0);
        }
        OP_DECOR_BEGIN_MOVE | OP_DECOR_BEGIN_RESIZE => {
            if !sender_has_decorate_capability(sender) {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            }
            let window_token = read_u64(request, 4).unwrap_or(0);
            let serial = read_u64(request, 12).unwrap_or(0);
            let dx = read_u32(request, 20).unwrap_or(0) as i32;
            let dy = read_u32(request, 24).unwrap_or(0) as i32;
            let Some(window_index) = window_index_by_token(windows, window_token) else {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            };
            if windows[window_index].decorator != client {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            }
            let Some(serial_index) = pointer_serials.iter().position(|record| {
                record.serial == serial
                    && record.window == windows[window_index].id
                    && !record.used
                    && Some(record.decoration) == windows[window_index].decoration
            }) else {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            };
            pointer_serials[serial_index].used = true;
            if opcode == OP_DECOR_BEGIN_MOVE {
                if let Some(content_index) =
                    content_surface_index_for_window(surfaces, &windows[window_index])
                {
                    surfaces[content_index].x = surfaces[content_index].x.saturating_add(dx);
                    surfaces[content_index].y = surfaces[content_index].y.saturating_add(dy);
                }
                reposition_window_surfaces(surfaces, &windows[window_index]);
                *needs_present = true;
                put_u32(&mut reply, 0, 0);
            } else {
                put_u32(&mut reply, 0, 0);
            }
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
                windows[window_index].state =
                    if windows[window_index].state == WINDOW_STATE_MAXIMIZED {
                        WINDOW_STATE_NORMAL
                    } else {
                        WINDOW_STATE_MAXIMIZED
                    };
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
            windows[window_index].close_requested = true;
            if let Some(content_index) =
                content_surface_index_for_window(surfaces, &windows[window_index])
            {
                destroy_surface_tree(
                    surfaces,
                    windows,
                    content_index,
                    pointer_focus,
                    keyboard_focus,
                );
            }
            *needs_present = true;
            put_u32(&mut reply, 0, 0);
        }
        _ => put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EINVAL)),
    }
    reply
}
