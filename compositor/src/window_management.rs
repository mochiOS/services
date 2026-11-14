//! Capability-checked, reversible presentation of existing application windows.
//! The compositor knows geometry and focus, not shell modes or applications.
use mochi_user_platform as platform;
use mochios_viewkit_gpu_protocol::window_management as wire;

use crate::{
    client::{Client, ClientId},
    input::{PointerGrab, raise_window, restore_keyboard_focus, send_event, update_keyboard_focus},
    protocol::*,
    state::ModalSession,
    surface::{Surface, SurfaceRole, surface_extent},
    window::{
        Insets, Window, content_surface_index_for_window, decoration_surface_index_for_window,
        notify_decorators, reposition_window_surfaces, send_window_configure,
        window_index_by_token,
    },
};

#[derive(Clone, Copy)]
pub(crate) struct Presentation {
    pub owner: ClientId,
    pub bounds: wire::Bounds,
    restore: wire::Bounds,
    state: u32,
    insets: Insets,
}

impl Presentation {
    pub(crate) fn decoration_changed(&mut self, integrated: bool, height: u32) {
        self.insets = if integrated {
            Insets::default()
        } else {
            Insets {
                top: height,
                ..self.insets
            }
        };
    }
}

fn authorized(clients: &[Client], client: ClientId, sender: u64) -> bool {
    let Some(record) = clients
        .iter()
        .find(|record| record.live && record.id == client && record.sender == sender)
    else {
        return false;
    };
    let process = platform::ipc::endpoint_owner_process(sender).unwrap_or(0);
    process != 0
        && record.decoration_endpoint != 0
        && platform::ipc::endpoint_alive(record.decoration_endpoint)
        && platform::ipc::endpoint_owner_process(record.decoration_endpoint) == Ok(process)
        && crate::decoration::sender_has_decorate_capability(sender)
}

fn protected(surface: &Surface) -> bool {
    surface.protected_presentation
        || matches!(
            surface.role,
            SurfaceRole::SecureOverlay | SurfaceRole::SystemModal
        )
}

pub(crate) fn snapshot(
    clients: &[Client],
    surfaces: &[Surface],
    windows: &[Window],
    focus: Option<usize>,
    client: ClientId,
    sender: u64,
    request: &[u8],
    reply: &mut [u8; wire::MAX_REPLY],
) -> usize {
    if request.len() != 4 || !authorized(clients, client, sender) {
        put_u32(reply, 0, errno_status(mochi_user_syscall::EACCES));
        return 16;
    }
    let mut count = 0;
    for window in windows.iter().filter(|window| window.live) {
        let Some(index) = content_surface_index_for_window(surfaces, window) else {
            continue;
        };
        let surface = &surfaces[index];
        if surface.role != SurfaceRole::Toplevel || surface.owner_process == 0 {
            continue;
        }
        if count == wire::MAX_WINDOWS {
            break;
        }
        let (width, height) = surface_extent(surface);
        let width = if window.configured_width > 0 {
            window.configured_width
        } else {
            width.max(1)
        };
        let height = if window.configured_height > 0 {
            window.configured_height
        } else {
            height.max(1)
        };
        let title =
            core::str::from_utf8(&window.title[..usize::from(window.title_len)]).unwrap_or("");
        let flags = u32::from(window.state == WINDOW_STATE_MINIMIZED) * wire::MINIMIZED
            | u32::from(focus == Some(index)) * wire::FOCUSED
            | u32::from(window.resizable) * wire::RESIZABLE
            | u32::from(protected(surface)) * wire::PROTECTED
            | u32::from(window.presentation.is_some()) * wire::MANAGED;
        let info = wire::WindowInfo {
            token: window.token,
            process: surface.owner_process,
            bounds: wire::Bounds {
                x: surface.x,
                y: surface.y,
                width,
                height,
            },
            flags,
            title,
        };
        let start = wire::HEADER_LEN + count * wire::RECORD_LEN;
        if info
            .encode(&mut reply[start..start + wire::RECORD_LEN])
            .is_some()
        {
            count += 1;
        }
    }
    let len = wire::HEADER_LEN + count * wire::RECORD_LEN;
    let _ = wire::snapshot_header(&mut reply[..len], count);
    len
}

fn valid_bounds(bounds: wire::Bounds, width: u32, height: u32) -> bool {
    bounds.x >= 0
        && bounds.y >= 0
        && bounds.width > 0
        && bounds.height > 0
        && u64::from(bounds.x as u32) + u64::from(bounds.width) <= u64::from(width)
        && u64::from(bounds.y as u32) + u64::from(bounds.height) <= u64::from(height)
}

pub(crate) fn handle_request(
    clients: &[Client],
    surfaces: &mut [Surface],
    windows: &mut [Window],
    next_z: &mut u32,
    pointer_focus: &mut Option<usize>,
    keyboard_focus: &mut Option<usize>,
    pointer_grab: &mut Option<PointerGrab>,
    sessions: &[ModalSession],
    client: ClientId,
    sender: u64,
    request: &[u8],
    needs_present: &mut bool,
    display_width: u32,
    display_height: u32,
) -> [u8; 16] {
    let result = (|| {
        if !authorized(clients, client, sender) {
            return Err(mochi_user_syscall::EACCES);
        }
        let token = read_u64(request, 4).ok_or(mochi_user_syscall::EINVAL)?;
        let index = window_index_by_token(windows, token).ok_or(mochi_user_syscall::ENOENT)?;
        let content = content_surface_index_for_window(surfaces, &windows[index])
            .ok_or(mochi_user_syscall::ENOENT)?;
        if surfaces[content].role != SurfaceRole::Toplevel || protected(&surfaces[content]) {
            return Err(mochi_user_syscall::EACCES);
        }
        if windows[index]
            .presentation
            .is_some_and(|lease| lease.owner != client)
        {
            return Err(mochi_user_syscall::EACCES);
        }
        // A shell gesture must not hide, preempt or close a permission prompt,
        // or its blocked owner. Keep the existing modal focus rules authoritative.
        if !sessions.is_empty()
            || surfaces
                .iter()
                .any(|surface| surface.live && surface.visible && protected(surface))
        {
            return Err(mochi_user_syscall::EAGAIN);
        }
        if read_u32(request, 0) == Some(wire::CLOSE) {
            if request.len() != 12 || windows[index].presentation.is_none() {
                return Err(mochi_user_syscall::EINVAL);
            }
            send_event(
                surfaces[content].event_endpoint,
                surfaces[content].token,
                EVENT_CLOSE_REQUESTED,
                0,
                0,
                0,
            );
            return Ok(());
        }
        let command = wire::Present::decode(request).ok_or(mochi_user_syscall::EINVAL)?;
        if pointer_grab
            .as_ref()
            .is_some_and(|grab| grab.window == windows[index].id)
        {
            *pointer_grab = None;
        }
        if command.flags == 0 {
            release(clients, surfaces, windows, index);
            restore_keyboard_focus(surfaces, keyboard_focus);
        } else {
            if !valid_bounds(command.bounds, display_width, display_height) {
                return Err(mochi_user_syscall::EINVAL);
            }
            present(surfaces, &mut windows[index], content, client, command);
            if command.flags & wire::VISIBLE == 0 {
                if *pointer_focus == Some(content) {
                    *pointer_focus = None;
                }
                if *keyboard_focus == Some(content) {
                    update_keyboard_focus(surfaces, keyboard_focus, None);
                }
                restore_keyboard_focus(surfaces, keyboard_focus);
            } else if command.flags & wire::ACTIVATE != 0 {
                raise_window(surfaces, windows, next_z, windows[index].id);
                update_keyboard_focus(surfaces, keyboard_focus, Some(content));
            }
            notify_decorators(clients, windows, surfaces, index);
        }
        *needs_present = true;
        Ok(())
    })();
    let mut reply = [0; 16];
    put_u32(&mut reply, 0, result.err().map(errno_status).unwrap_or(0));
    reply
}

fn present(
    surfaces: &mut [Surface],
    window: &mut Window,
    content: usize,
    client: ClientId,
    command: wire::Present,
) {
    let (width, height) = surface_extent(&surfaces[content]);
    let previous = window.presentation;
    let mut lease = previous.unwrap_or(Presentation {
        owner: client,
        bounds: command.bounds,
        restore: wire::Bounds {
            x: surfaces[content].x,
            y: surfaces[content].y,
            width: if window.configured_width > 0 {
                window.configured_width
            } else {
                width.max(1)
            },
            height: if window.configured_height > 0 {
                window.configured_height
            } else {
                height.max(1)
            },
        },
        state: window.state,
        insets: window.insets,
    });
    lease.bounds = command.bounds;
    window.presentation = Some(lease);
    window.insets = Insets::default();
    let visible = command.flags & wire::VISIBLE != 0;
    window.state = if visible {
        WINDOW_STATE_MAXIMIZED
    } else {
        WINDOW_STATE_MINIMIZED
    };
    translate_children(surfaces, content, command.bounds.x, command.bounds.y);
    surfaces[content].x = command.bounds.x;
    surfaces[content].y = command.bounds.y;
    surfaces[content].visible = visible;
    window.configured_width = command.bounds.width;
    window.configured_height = command.bounds.height;
    if previous.is_none_or(|previous| previous.bounds != command.bounds) {
        send_window_configure(
            &surfaces[content],
            command.bounds.width,
            command.bounds.height,
        );
    }
    if let Some(decoration) = decoration_surface_index_for_window(surfaces, window) {
        surfaces[decoration].visible = false;
    }
}

fn release(clients: &[Client], surfaces: &mut [Surface], windows: &mut [Window], index: usize) {
    // A renderer may become a protected presentation while leased. Keep its
    // pixels and geometry stable until that presentation has been withdrawn.
    if content_surface_index_for_window(surfaces, &windows[index])
        .is_some_and(|content| protected(&surfaces[content]))
    {
        return;
    }
    let Some(lease) = windows[index].presentation.take() else {
        return;
    };
    let window = &mut windows[index];
    window.insets = lease.insets;
    window.state = lease.state;
    window.configured_width = lease.restore.width;
    window.configured_height = lease.restore.height;
    if let Some(content) = content_surface_index_for_window(surfaces, window) {
        translate_children(surfaces, content, lease.restore.x, lease.restore.y);
        surfaces[content].x = lease.restore.x;
        surfaces[content].y = lease.restore.y;
        surfaces[content].visible = lease.state != WINDOW_STATE_MINIMIZED;
        send_window_configure(
            &surfaces[content],
            lease.restore.width,
            lease.restore.height,
        );
    }
    if let Some(decoration) = decoration_surface_index_for_window(surfaces, window) {
        surfaces[decoration].visible = lease.state != WINDOW_STATE_MINIMIZED;
    }
    reposition_window_surfaces(surfaces, window);
    notify_decorators(clients, windows, surfaces, index);
}

fn translate_children(surfaces: &mut [Surface], content: usize, x: i32, y: i32) {
    let root = surfaces[content].handle;
    let dx = x.saturating_sub(surfaces[content].x);
    let dy = y.saturating_sub(surfaces[content].y);
    for index in 0..surfaces.len() {
        if !surfaces[index].live {
            continue;
        }
        let mut parent = surfaces[index].parent;
        for _ in 0..surfaces.len() {
            match parent {
                Some(handle) if handle == root => {
                    surfaces[index].x = surfaces[index].x.saturating_add(dx);
                    surfaces[index].y = surfaces[index].y.saturating_add(dy);
                    break;
                }
                Some(handle) => {
                    parent = crate::surface::surface_index_by_handle(surfaces, handle)
                        .and_then(|i| surfaces[i].parent)
                }
                None => break,
            }
        }
    }
}

pub(crate) fn release_client(
    clients: &[Client],
    surfaces: &mut [Surface],
    windows: &mut [Window],
    client: ClientId,
) {
    for index in 0..windows.len() {
        if windows[index]
            .presentation
            .is_some_and(|lease| lease.owner == client)
        {
            release(clients, surfaces, windows, index);
        }
    }
}

pub(crate) fn release_orphaned(
    clients: &[Client],
    surfaces: &mut [Surface],
    windows: &mut [Window],
) -> bool {
    let mut changed = false;
    for index in 0..windows.len() {
        if windows[index].presentation.is_some_and(|lease| {
            !clients
                .iter()
                .any(|client| client.live && client.id == lease.owner)
        }) {
            release(clients, surfaces, windows, index);
            changed |= windows[index].presentation.is_none();
        }
    }
    changed
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unregistered_senders_cannot_enumerate_windows() {
        let mut reply = [0; wire::MAX_REPLY];
        let length = snapshot(
            &[],
            &[],
            &[],
            None,
            ClientId(7),
            123,
            &wire::SNAPSHOT.to_le_bytes(),
            &mut reply,
        );
        assert_eq!(length, 16);
        assert_eq!(
            read_u32(&reply, 0),
            Some(errno_status(mochi_user_syscall::EACCES))
        );
        assert!(wire::snapshot_records(&reply[..length]).is_none());
    }
    #[test]
    fn viewport_rejects_overflow_and_offscreen_rectangles() {
        let bounds = wire::Bounds {
            x: 0,
            y: 32,
            width: 1280,
            height: 768,
        };
        assert!(valid_bounds(bounds, 1280, 800));
        assert!(!valid_bounds(
            wire::Bounds {
                width: u32::MAX,
                ..bounds
            },
            1280,
            800
        ));
        assert!(!valid_bounds(wire::Bounds { x: -1, ..bounds }, 1280, 800));
    }
    #[test]
    fn lease_restores_original_geometry_and_requested_chrome() {
        let mut surfaces = [Surface::empty()];
        surfaces[0].live = true;
        surfaces[0].role = SurfaceRole::Toplevel;
        surfaces[0].handle = crate::surface::SurfaceHandle(5);
        surfaces[0].token = 5;
        surfaces[0].width = 640;
        surfaces[0].height = 480;
        surfaces[0].x = 100;
        surfaces[0].y = 80;
        let mut windows = [Window::empty()];
        windows[0].content = surfaces[0].handle;
        windows[0].live = true;
        windows[0].insets.top = 40;
        let command = wire::Present {
            window: 7,
            flags: wire::LEASE | wire::VISIBLE,
            bounds: wire::Bounds {
                x: 0,
                y: 32,
                width: 1280,
                height: 768,
            },
        };
        present(&mut surfaces, &mut windows[0], 0, ClientId(3), command);
        assert_eq!(windows[0].state, WINDOW_STATE_MAXIMIZED);
        assert_eq!(windows[0].insets.top, 0);
        present(
            &mut surfaces,
            &mut windows[0],
            0,
            ClientId(3),
            wire::Present {
                flags: wire::LEASE,
                ..command
            },
        );
        assert!(!surfaces[0].visible);
        surfaces[0].protected_presentation = true;
        assert!(!release_orphaned(&[], &mut surfaces, &mut windows));
        assert!(windows[0].presentation.is_some());
        surfaces[0].protected_presentation = false;
        assert!(release_orphaned(&[], &mut surfaces, &mut windows));
        assert_eq!((surfaces[0].x, surfaces[0].y), (100, 80));
        assert_eq!(
            (windows[0].configured_width, windows[0].configured_height),
            (640, 480)
        );
        assert_eq!(windows[0].insets.top, 40);
        assert!(surfaces[0].visible);
    }
}
