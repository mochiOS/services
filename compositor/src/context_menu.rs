use alloc::vec::Vec;

use mochi_user_platform as platform;

use crate::client::ClientId;
use crate::decoration::sender_has_overlay_compat_capability;
use crate::input::update_keyboard_focus;
use crate::protocol::{
    CONTEXT_MENU_EVENT_DISMISS, CONTEXT_MENU_EVENT_SHOW, EVENT_CONTEXT_MENU_RESULT,
    OP_CONTEXT_MENU_COMPLETE, OP_CONTEXT_MENU_SHOW, OP_CONTEXT_MENU_SUBSCRIBE, errno_status,
    put_i32, put_u32, put_u64, read_u32, read_u64,
};
use crate::surface::Surface;

const MAX_MENU_ITEMS: u32 = 32;
const MAX_MENU_LABEL_BYTES: usize = 128;
const ITEM_HEADER_SIZE: usize = 8;
const SHOW_HEADER_SIZE: usize = 32;
const FORWARDED_HEADER_SIZE: usize = 24;
const FLAG_SEPARATOR: u16 = 1 << 0;
const ALLOWED_FLAGS: u16 = FLAG_SEPARATOR | (1 << 1) | (1 << 2) | (1 << 3);
const ERRNO_BUSY: u64 = 16;
const ERRNO_NO_DEVICE: u64 = 19;

#[derive(Clone, Copy, Default)]
struct PendingMenu {
    owner: ClientId,
    event_endpoint: u64,
    request_id: u64,
}

#[derive(Default)]
pub(crate) struct ContextMenuBroker {
    manager: ClientId,
    manager_endpoint: u64,
    pending: Option<PendingMenu>,
    dismiss_sent: bool,
    suppress_pointer_release: bool,
}

impl ContextMenuBroker {
    pub(crate) fn handle_request(
        &mut self,
        surfaces: &[Surface],
        keyboard_focus: &mut Option<usize>,
        client: ClientId,
        sender: u64,
        request: &[u8],
    ) -> [u8; 16] {
        let mut reply = [0u8; 16];
        let Some(opcode) = read_u32(request, 0) else {
            put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EINVAL));
            return reply;
        };
        let status = match opcode {
            OP_CONTEXT_MENU_SUBSCRIBE => self.subscribe(client, sender, request),
            OP_CONTEXT_MENU_SHOW => self.show(surfaces, client, request),
            OP_CONTEXT_MENU_COMPLETE => self.complete(surfaces, keyboard_focus, client, request),
            _ => mochios_errno(mochi_user_syscall::EINVAL),
        };
        put_u32(&mut reply, 0, status);
        reply
    }

    fn subscribe(&mut self, client: ClientId, sender: u64, request: &[u8]) -> u32 {
        if request.len() != 12 || !sender_has_overlay_compat_capability(sender) {
            return mochios_errno(mochi_user_syscall::EACCES);
        }
        let endpoint = read_u64(request, 4).unwrap_or(0);
        if endpoint == 0 {
            return mochios_errno(mochi_user_syscall::EINVAL);
        }
        self.manager = client;
        self.manager_endpoint = endpoint;
        0
    }

    fn show(&mut self, surfaces: &[Surface], client: ClientId, request: &[u8]) -> u32 {
        if self.manager == ClientId(0) || self.manager_endpoint == 0 {
            return mochios_errno(ERRNO_NO_DEVICE);
        }
        if self.pending.is_some() {
            return mochios_errno(ERRNO_BUSY);
        }
        let Some(surface_token) = read_u64(request, 4) else {
            return mochios_errno(mochi_user_syscall::EINVAL);
        };
        let Some(request_id) = read_u64(request, 12).filter(|id| *id != 0) else {
            return mochios_errno(mochi_user_syscall::EINVAL);
        };
        let Some(anchor_x) = read_u32(request, 20).map(|value| value as i32) else {
            return mochios_errno(mochi_user_syscall::EINVAL);
        };
        let Some(anchor_y) = read_u32(request, 24).map(|value| value as i32) else {
            return mochios_errno(mochi_user_syscall::EINVAL);
        };
        let Some(item_count) = read_u32(request, 28) else {
            return mochios_errno(mochi_user_syscall::EINVAL);
        };
        if !validate_items(request, item_count) {
            return mochios_errno(mochi_user_syscall::EINVAL);
        }
        let Some(surface) = surfaces.iter().find(|surface| {
            surface.live
                && !surface.is_decoration
                && surface.owner == client
                && surface.token == surface_token
        }) else {
            return mochios_errno(mochi_user_syscall::EACCES);
        };
        if surface.event_endpoint == 0
            || anchor_x < 0
            || anchor_y < 0
            || anchor_x >= surface.width as i32
            || anchor_y >= surface.height as i32
        {
            return mochios_errno(mochi_user_syscall::EINVAL);
        }

        let mut event = Vec::with_capacity(
            FORWARDED_HEADER_SIZE + request.len().saturating_sub(SHOW_HEADER_SIZE),
        );
        event.resize(FORWARDED_HEADER_SIZE, 0);
        put_u32(&mut event, 0, CONTEXT_MENU_EVENT_SHOW);
        put_i32(&mut event, 4, surface.x.saturating_add(anchor_x));
        put_i32(&mut event, 8, surface.y.saturating_add(anchor_y));
        put_u32(&mut event, 12, item_count);
        put_u64(&mut event, 16, request_id);
        event.extend_from_slice(&request[SHOW_HEADER_SIZE..]);
        if platform::ipc::send(self.manager_endpoint, &event).is_err() {
            return mochios_errno(mochi_user_syscall::EIO);
        }
        self.pending = Some(PendingMenu {
            owner: client,
            event_endpoint: surface.event_endpoint,
            request_id,
        });
        self.dismiss_sent = false;
        0
    }

    fn complete(
        &mut self,
        surfaces: &[Surface],
        keyboard_focus: &mut Option<usize>,
        client: ClientId,
        request: &[u8],
    ) -> u32 {
        if request.len() != 24 || client != self.manager {
            return mochios_errno(mochi_user_syscall::EACCES);
        }
        let status = read_u32(request, 4).unwrap_or(u32::MAX);
        let request_id = read_u64(request, 8).unwrap_or(0);
        let command_id = read_u32(request, 16).unwrap_or(0);
        if status > 1 {
            return mochios_errno(mochi_user_syscall::EINVAL);
        }
        let Some(pending) = self.pending else {
            return mochios_errno(mochi_user_syscall::ENOENT);
        };
        if pending.request_id != request_id {
            return mochios_errno(mochi_user_syscall::EINVAL);
        }
        let mut event = [0u8; 24];
        put_u32(&mut event, 0, EVENT_CONTEXT_MENU_RESULT);
        put_u32(&mut event, 4, status);
        put_u64(&mut event, 8, request_id);
        put_u32(&mut event, 16, command_id);
        let _ = platform::ipc::send(pending.event_endpoint, &event);
        let owner_surface = surfaces.iter().position(|surface| {
            surface.live
                && !surface.is_decoration
                && surface.owner == pending.owner
                && surface.event_endpoint == pending.event_endpoint
        });
        update_keyboard_focus(surfaces, keyboard_focus, owner_surface);
        self.pending = None;
        self.dismiss_sent = false;
        0
    }

    pub(crate) fn capture_pointer_button(
        &mut self,
        target_owner: Option<ClientId>,
        pressed: bool,
    ) -> bool {
        let Some(pending) = self.pending else {
            if !pressed && self.suppress_pointer_release {
                self.suppress_pointer_release = false;
                return true;
            }
            return false;
        };
        if target_owner == Some(self.manager) {
            return false;
        }
        if pressed && !self.dismiss_sent {
            let mut event = [0u8; 16];
            put_u32(&mut event, 0, CONTEXT_MENU_EVENT_DISMISS);
            put_u64(&mut event, 8, pending.request_id);
            let _ = platform::ipc::send(self.manager_endpoint, &event);
            self.dismiss_sent = true;
            self.suppress_pointer_release = true;
        }
        true
    }

    pub(crate) fn capture_key(&mut self, keycode: u16, pressed: bool) -> bool {
        let Some(pending) = self.pending else {
            return false;
        };
        if pressed && keycode == platform::input::KEY_ESC && !self.dismiss_sent {
            let mut event = [0u8; 16];
            put_u32(&mut event, 0, CONTEXT_MENU_EVENT_DISMISS);
            put_u64(&mut event, 8, pending.request_id);
            let _ = platform::ipc::send(self.manager_endpoint, &event);
            self.dismiss_sent = true;
        }
        true
    }

    pub(crate) fn cleanup_client(&mut self, client: ClientId) {
        if self.manager == client {
            *self = Self::default();
        } else if self.pending.is_some_and(|pending| pending.owner == client) {
            self.pending = None;
            self.dismiss_sent = false;
            self.suppress_pointer_release = false;
        }
    }
}

fn validate_items(request: &[u8], item_count: u32) -> bool {
    if item_count == 0 || item_count > MAX_MENU_ITEMS || request.len() < SHOW_HEADER_SIZE {
        return false;
    }
    let mut offset = SHOW_HEADER_SIZE;
    for _ in 0..item_count {
        let Some(header) = request.get(offset..offset + ITEM_HEADER_SIZE) else {
            return false;
        };
        let command = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        let flags = u16::from_le_bytes([header[4], header[5]]);
        let label_len = u16::from_le_bytes([header[6], header[7]]) as usize;
        if flags & !ALLOWED_FLAGS != 0
            || label_len > MAX_MENU_LABEL_BYTES
            || (flags & FLAG_SEPARATOR == 0 && (command == 0 || label_len == 0))
            || (flags & FLAG_SEPARATOR != 0 && (command != 0 || label_len != 0))
        {
            return false;
        }
        offset = offset.saturating_add(ITEM_HEADER_SIZE);
        let Some(label) = request.get(offset..offset.saturating_add(label_len)) else {
            return false;
        };
        if core::str::from_utf8(label).is_err() {
            return false;
        }
        offset = offset.saturating_add(label_len);
    }
    offset == request.len()
}

fn mochios_errno(errno: u64) -> u32 {
    errno_status(errno)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_one_enabled_item() {
        let mut request = vec![0u8; SHOW_HEADER_SIZE + ITEM_HEADER_SIZE + 4];
        put_u32(&mut request, 28, 1);
        put_u32(&mut request, SHOW_HEADER_SIZE, 7);
        request[SHOW_HEADER_SIZE + 4..SHOW_HEADER_SIZE + 6].copy_from_slice(&2u16.to_le_bytes());
        request[SHOW_HEADER_SIZE + 6..SHOW_HEADER_SIZE + 8].copy_from_slice(&4u16.to_le_bytes());
        request[SHOW_HEADER_SIZE + 8..].copy_from_slice(b"Open");
        assert!(validate_items(&request, 1));
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut request = vec![0u8; SHOW_HEADER_SIZE + ITEM_HEADER_SIZE + 1];
        put_u32(&mut request, 28, 1);
        put_u32(&mut request, SHOW_HEADER_SIZE, 7);
        request[SHOW_HEADER_SIZE + 4..SHOW_HEADER_SIZE + 6].copy_from_slice(&2u16.to_le_bytes());
        assert!(!validate_items(&request, 1));
    }
}
