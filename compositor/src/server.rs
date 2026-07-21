use alloc::vec::Vec;
use mochi_user_platform as platform;

use crate::client::{Client, ClientId, client_id_for_sender};
use crate::decoration::sender_has_overlay_compat_capability;
use crate::display::{display_claim_present_owner, display_request_info, wait_for_service};
use crate::geometry::{Point, PopupPlacement, Rect, merge_damage, validate_damage_rect};
use crate::input::{
    PointerSerial, clear_focus_for_surface, handle_input_event, subscribe_input_events,
};
use crate::protocol::*;
use crate::renderer::composite_and_present;
use crate::state::CompositorState;
use crate::surface::{Surface, SurfaceBuffer, SurfaceHandle, SurfaceRights, SurfaceRole};
use crate::window::{
    Window, WindowId, generate_window_token, notify_decorators, window_index_by_id,
};

pub(crate) const MAX_SURFACES: usize = 16;
pub(crate) const MAX_WINDOWS: usize = 8;
pub(crate) const MAX_CLIENTS: usize = 16;
pub(crate) const PAGE_SIZE: usize = 4096;
pub(crate) const MAX_SHARED_PAGES: usize = 262_144;
const MAX_SHARED_BYTES: usize = MAX_SHARED_PAGES * PAGE_SIZE;
pub(crate) const MAX_SHARED_PIXELS: usize = MAX_SHARED_BYTES / 4;
pub(crate) const MAX_DIMENSION: u32 = 16_384;
const IDLE_CLEANUP_YIELDS: u32 = 64;
static mut TOKEN_RANDOM_BUF: [u8; 8] = [0; 8];
static mut IPC_BUF: [u8; 4128] = [0; 4128];

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
            platform::println!(
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
        platform::println!("compositor.service: getrandom short read len={}", len);
        None
    }
}

pub(crate) fn sleep_one_tick() {
    let _ = mochi_user_syscall::call1(mochi_user_syscall::SyscallNumber::Sleep, 1);
}

pub(crate) fn surface_index_for(
    surfaces: &[Surface],
    client: ClientId,
    handle: SurfaceHandle,
    required: SurfaceRights,
) -> Option<usize> {
    surfaces.iter().position(|surface| {
        surface.live
            && surface.owner == client
            && surface.handle == handle
            && surface.token == handle.0
            && surface.rights.contains(required)
    })
}

fn surface_index_for_child(surfaces: &[Surface], parent: SurfaceHandle) -> Option<usize> {
    surfaces
        .iter()
        .position(|surface| surface.live && surface.parent == Some(parent))
}

pub(crate) fn destroy_surface_tree(
    surfaces: &mut [Surface],
    windows: &mut [Window],
    index: usize,
    pointer_focus: &mut Option<usize>,
    keyboard_focus: &mut Option<usize>,
) {
    let Some(handle) = surfaces
        .get(index)
        .filter(|surface| surface.live)
        .map(|s| s.handle)
    else {
        return;
    };
    while let Some(child) = surface_index_for_child(surfaces, handle) {
        destroy_surface_tree(surfaces, windows, child, pointer_focus, keyboard_focus);
    }
    let window_id = surfaces[index].window;
    if surfaces[index].is_decoration {
        if let Some(window_index) = window_index_by_id(windows, window_id) {
            windows[window_index].decoration = None;
            windows[window_index].decorator = ClientId(0);
            windows[window_index].decorator_endpoint = 0;
        }
    } else if let Some(window_index) = window_index_by_id(windows, window_id) {
        if let Some(decoration) = windows[window_index].decoration
            && let Some(decoration_index) = surface_index_by_handle(surfaces, decoration)
        {
            clear_focus_for_surface(surfaces, decoration_index, pointer_focus, keyboard_focus);
            surfaces[decoration_index].reset();
        }
        windows[window_index] = Window::empty();
    }
    clear_focus_for_surface(surfaces, index, pointer_focus, keyboard_focus);
    surfaces[index].reset();
}

fn cleanup_client(
    clients: &mut [Client],
    surfaces: &mut [Surface],
    windows: &mut [Window],
    client: ClientId,
    pointer_focus: &mut Option<usize>,
    keyboard_focus: &mut Option<usize>,
) {
    if client == ClientId(0) {
        return;
    }
    while let Some(index) = surfaces
        .iter()
        .position(|surface| surface.live && surface.owner == client && !surface.is_decoration)
    {
        destroy_surface_tree(surfaces, windows, index, pointer_focus, keyboard_focus);
    }
    while let Some(index) = surfaces
        .iter()
        .position(|surface| surface.live && surface.owner == client && surface.is_decoration)
    {
        destroy_surface_tree(surfaces, windows, index, pointer_focus, keyboard_focus);
    }
    for window in windows
        .iter_mut()
        .filter(|window| window.live && window.decorator == client)
    {
        window.decorator = ClientId(0);
        window.decorator_endpoint = 0;
    }
    if let Some(record) = clients
        .iter_mut()
        .find(|record| record.live && record.id == client)
    {
        *record = Client::default();
    }
}

fn cleanup_dead_clients(
    clients: &mut [Client],
    surfaces: &mut [Surface],
    windows: &mut [Window],
    pointer_focus: &mut Option<usize>,
    keyboard_focus: &mut Option<usize>,
) -> bool {
    let mut changed = false;
    for index in 0..clients.len() {
        let client = clients[index];
        if !client.live {
            continue;
        }
        let has_live_surface = surfaces
            .iter()
            .any(|surface| surface.live && surface.owner == client.id);
        let has_live_decoration_endpoint = client.decoration_endpoint != 0
            && platform::ipc::endpoint_alive(client.decoration_endpoint);
        let has_live_window_decorator_endpoint = windows.iter().any(|window| {
            window.live
                && window.decorator == client.id
                && window.decorator_endpoint != 0
                && platform::ipc::endpoint_alive(window.decorator_endpoint)
        });

        if !has_live_surface && !has_live_decoration_endpoint && !has_live_window_decorator_endpoint
        {
            cleanup_client(
                clients,
                surfaces,
                windows,
                client.id,
                pointer_focus,
                keyboard_focus,
            );
            changed = true;
        }
    }
    changed
}

pub(crate) fn generate_surface_token(surfaces: &[Surface]) -> Result<u64, u32> {
    for _ in 0..16 {
        let Some(token) = getrandom_u64() else {
            return Err(errno_status(mochi_user_syscall::EIO));
        };
        if token != 0
            && surfaces
                .iter()
                .all(|surface| !surface.live || surface.token != token)
        {
            return Ok(token);
        }
    }
    Err(errno_status(mochi_user_syscall::EAGAIN))
}

pub(crate) fn surface_index_by_handle(
    surfaces: &[Surface],
    handle: SurfaceHandle,
) -> Option<usize> {
    surfaces
        .iter()
        .position(|surface| surface.live && surface.handle == handle && surface.token == handle.0)
}

pub(crate) fn surface_extent(surface: &Surface) -> (u32, u32) {
    let width = if surface.current_width == 0 {
        surface.width
    } else {
        surface.current_width
    };
    let height = if surface.current_height == 0 {
        surface.height
    } else {
        surface.current_height
    };
    (width, height)
}

fn resize_buffer(buffer: &mut Vec<u32>, width: u32, height: u32) -> bool {
    let Some(len) = (width as usize).checked_mul(height as usize) else {
        return false;
    };
    buffer.clear();
    if buffer.capacity() < len && buffer.try_reserve_exact(len - buffer.capacity()).is_err() {
        return false;
    }
    buffer.resize(len, 0);
    true
}

pub(crate) fn surface_has_current_pixels(surface: &Surface) -> bool {
    if surface.role == SurfaceRole::Background {
        let Some(surface_len) =
            (surface.current_width as usize).checked_mul(surface.current_height as usize)
        else {
            return false;
        };
        return surface.current.len() >= surface_len;
    }
    if let Some(buffer) = &surface.current_buffer {
        return buffer.width == surface.current_width
            && buffer.height == surface.current_height
            && buffer.stride >= buffer.width
            && buffer.byte_len >= buffer.pixels.saturating_mul(4);
    }
    let Some(surface_len) =
        (surface.current_width as usize).checked_mul(surface.current_height as usize)
    else {
        return false;
    };
    surface.current.len() >= surface_len
}

pub(crate) fn read_current_pixel(surface: &Surface, sx: usize, sy: usize) -> Option<u32> {
    if surface.role == SurfaceRole::Background {
        let width = usize::try_from(surface.current_width).ok()?;
        let index = sy.checked_mul(width)?.checked_add(sx)?;
        return surface.current.get(index).copied();
    }
    if let Some(buffer) = &surface.current_buffer {
        let stride = usize::try_from(buffer.stride).ok()?;
        let src = sy.checked_mul(stride)?.checked_add(sx)?;
        let byte_offset = src.checked_mul(4)?;
        if byte_offset.checked_add(4)? > buffer.byte_len {
            return None;
        }
        let ptr = (buffer.mapped_addr as *const u8).wrapping_add(byte_offset);
        let bytes = unsafe { core::slice::from_raw_parts(ptr, 4) };
        return Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]));
    }
    let src = sy
        .checked_mul(surface.current_stride as usize)?
        .checked_add(sx)?;
    surface.current.get(src).copied()
}

fn copy_surface_buffer(buffer: &SurfaceBuffer) -> Result<Vec<u32>, u32> {
    let mut pixels = Vec::new();
    if !resize_buffer(&mut pixels, buffer.width, buffer.height) {
        return Err(errno_status(mochi_user_syscall::ENOMEM));
    }
    let stride =
        usize::try_from(buffer.stride).map_err(|_| errno_status(mochi_user_syscall::EINVAL))?;
    let width =
        usize::try_from(buffer.width).map_err(|_| errno_status(mochi_user_syscall::EINVAL))?;
    let height =
        usize::try_from(buffer.height).map_err(|_| errno_status(mochi_user_syscall::EINVAL))?;
    let row_bytes = stride
        .checked_mul(4)
        .ok_or_else(|| errno_status(mochi_user_syscall::ERANGE))?;
    let needed = row_bytes
        .checked_mul(height)
        .ok_or_else(|| errno_status(mochi_user_syscall::ERANGE))?;
    if buffer.byte_len < needed {
        return Err(errno_status(mochi_user_syscall::EINVAL));
    }
    let source =
        unsafe { core::slice::from_raw_parts(buffer.mapped_addr as *const u8, buffer.byte_len) };
    for y in 0..height {
        let src_row = y
            .checked_mul(stride)
            .ok_or_else(|| errno_status(mochi_user_syscall::ERANGE))?;
        let dst_row = y
            .checked_mul(width)
            .ok_or_else(|| errno_status(mochi_user_syscall::ERANGE))?;
        for x in 0..width {
            let src = src_row
                .checked_add(x)
                .and_then(|offset| offset.checked_mul(4))
                .ok_or_else(|| errno_status(mochi_user_syscall::ERANGE))?;
            let Some(pixel) = read_pixel(source, src) else {
                return Err(errno_status(mochi_user_syscall::EINVAL));
            };
            let dst = dst_row
                .checked_add(x)
                .ok_or_else(|| errno_status(mochi_user_syscall::ERANGE))?;
            let Some(slot) = pixels.get_mut(dst) else {
                return Err(errno_status(mochi_user_syscall::EINVAL));
            };
            *slot = pixel;
        }
    }
    Ok(pixels)
}

fn copy_surface_buffer_rect(
    buffer: &SurfaceBuffer,
    rect: Rect,
    destination: &mut [u32],
    destination_width: u32,
    destination_height: u32,
) -> Result<(), u32> {
    let rect = validate_damage_rect(rect, destination_width, destination_height)?;
    if buffer.width != destination_width || buffer.height != destination_height {
        return Err(errno_status(mochi_user_syscall::EINVAL));
    }
    let stride =
        usize::try_from(buffer.stride).map_err(|_| errno_status(mochi_user_syscall::EINVAL))?;
    let width =
        usize::try_from(destination_width).map_err(|_| errno_status(mochi_user_syscall::EINVAL))?;
    let height = usize::try_from(destination_height)
        .map_err(|_| errno_status(mochi_user_syscall::EINVAL))?;
    let row_bytes = stride
        .checked_mul(4)
        .ok_or_else(|| errno_status(mochi_user_syscall::ERANGE))?;
    let needed = row_bytes
        .checked_mul(height)
        .ok_or_else(|| errno_status(mochi_user_syscall::ERANGE))?;
    if buffer.byte_len < needed || destination.len() < width.saturating_mul(height) {
        return Err(errno_status(mochi_user_syscall::EINVAL));
    }
    let source =
        unsafe { core::slice::from_raw_parts(buffer.mapped_addr as *const u8, buffer.byte_len) };
    let left = rect.x as usize;
    let top = rect.y as usize;
    let right = left.saturating_add(rect.width as usize);
    let bottom = top.saturating_add(rect.height as usize);
    for y in top..bottom {
        let src_row = y
            .checked_mul(stride)
            .ok_or_else(|| errno_status(mochi_user_syscall::ERANGE))?;
        let dst_row = y
            .checked_mul(width)
            .ok_or_else(|| errno_status(mochi_user_syscall::ERANGE))?;
        for x in left..right {
            let src = src_row
                .checked_add(x)
                .and_then(|offset| offset.checked_mul(4))
                .ok_or_else(|| errno_status(mochi_user_syscall::ERANGE))?;
            let Some(pixel) = read_pixel(source, src) else {
                return Err(errno_status(mochi_user_syscall::EINVAL));
            };
            let dst = dst_row
                .checked_add(x)
                .ok_or_else(|| errno_status(mochi_user_syscall::ERANGE))?;
            let Some(slot) = destination.get_mut(dst) else {
                return Err(errno_status(mochi_user_syscall::EINVAL));
            };
            *slot = pixel;
        }
    }
    Ok(())
}

pub(crate) fn shared_page_count(byte_len: usize) -> Option<usize> {
    byte_len
        .checked_add(PAGE_SIZE - 1)
        .map(|len| len / PAGE_SIZE)
}

fn validate_buffer_layout(
    width: u32,
    height: u32,
    stride: u32,
    format: u32,
    expected_width: u32,
    expected_height: u32,
) -> Result<(usize, usize, usize), u32> {
    if format != PIXEL_FORMAT_XRGB8888
        || width == 0
        || height == 0
        || stride < width
        || width > MAX_DIMENSION
        || height > MAX_DIMENSION
        || width != expected_width
        || height != expected_height
    {
        return Err(errno_status(mochi_user_syscall::EINVAL));
    }
    let row_pixels =
        usize::try_from(stride).map_err(|_| errno_status(mochi_user_syscall::EINVAL))?;
    let row_bytes = row_pixels
        .checked_mul(4)
        .ok_or_else(|| errno_status(mochi_user_syscall::ERANGE))?;
    let height_usize =
        usize::try_from(height).map_err(|_| errno_status(mochi_user_syscall::EINVAL))?;
    let needed_bytes = row_bytes
        .checked_mul(height_usize)
        .ok_or_else(|| errno_status(mochi_user_syscall::ERANGE))?;
    let width_usize =
        usize::try_from(width).map_err(|_| errno_status(mochi_user_syscall::EINVAL))?;
    let pixels = width_usize
        .checked_mul(height_usize)
        .ok_or_else(|| errno_status(mochi_user_syscall::ERANGE))?;
    Ok((row_bytes, needed_bytes, pixels))
}

fn send_frame_done(surface: &Surface) {
    if surface.event_endpoint == 0 || surface.is_decoration {
        return;
    }
    let mut event = [0u8; 20];
    put_u32(&mut event, 0, EVENT_FRAME_DONE);
    let _ = platform::ipc::send(surface.event_endpoint, &event);
}

fn handle_shared_buffer(
    surfaces: &mut [Surface],
    client: ClientId,
    mapped_addr: u64,
    total: u64,
) -> bool {
    let Some(index) = surfaces
        .iter()
        .position(|surface| surface.live && surface.owner == client && surface.awaiting_buffer)
    else {
        return false;
    };
    let surface = &mut surfaces[index];
    let width = surface.pending_width;
    let height = surface.pending_height;
    let stride = surface.pending_stride;
    if width == 0 || height == 0 || stride < width {
        surface.awaiting_buffer = false;
        return true;
    }
    let Ok((_row_bytes, needed_bytes, pixels)) = validate_buffer_layout(
        width,
        height,
        stride,
        PIXEL_FORMAT_XRGB8888,
        surface.width,
        surface.height,
    ) else {
        surface.awaiting_buffer = false;
        return true;
    };
    let Ok(total) = usize::try_from(total) else {
        surface.awaiting_buffer = false;
        return true;
    };
    if total == 0 || total > MAX_SHARED_BYTES || total < needed_bytes {
        surface.awaiting_buffer = false;
        return true;
    }
    if mapped_addr == 0 {
        surface.awaiting_buffer = false;
        return true;
    }
    surface.pending.clear();
    surface.pending_buffer = Some(SurfaceBuffer {
        mapped_addr,
        byte_len: needed_bytes,
        width,
        height,
        stride,
        pixels,
    });
    surface.pending_bytes_received = needed_bytes;
    surface.pending_len = pixels;
    surface.pending_damage = Some(Rect::full(width, height));
    surface.awaiting_buffer = false;
    true
}

fn handle_request(
    clients: &mut [Client],
    surfaces: &mut [Surface],
    windows: &mut [Window],
    next_z: &mut u32,
    next_window_index: &mut u32,
    next_window_id: &mut u64,
    _next_pointer_serial: &mut u64,
    pointer_serials: &mut [PointerSerial],
    pointer_focus: &mut Option<usize>,
    keyboard_focus: &mut Option<usize>,
    client: ClientId,
    sender: u64,
    request: &[u8],
    needs_present: &mut bool,
    present_damage: &mut Option<Rect>,
    _display_tid: u64,
    _display_width: u32,
    _display_height: u32,
    _display_stride: u32,
    _display_format: u32,
) -> [u8; 16] {
    let mut reply = [0u8; 16];
    let Some(opcode) = read_u32(request, 0) else {
        put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EINVAL));
        return reply;
    };
    match opcode {
        OP_CREATE_SURFACE => {
            let role_raw = read_u32(request, 4).unwrap_or(0);
            let role = match SurfaceRole::from_wire(role_raw) {
                Ok(role) => role,
                Err(status) => {
                    put_u32(&mut reply, 0, status);
                    return reply;
                }
            };
            let rights = if sender_has_overlay_compat_capability(sender) {
                match role.privileged_overlay_rights() {
                    Ok(rights) => rights,
                    Err(status) => {
                        put_u32(&mut reply, 0, status);
                        return reply;
                    }
                }
            } else {
                match role.general_client_rights() {
                    Ok(rights) => rights,
                    Err(status) => {
                        put_u32(&mut reply, 0, status);
                        return reply;
                    }
                }
            };
            let width = read_u32(request, 8).unwrap_or(0);
            let height = read_u32(request, 12).unwrap_or(0);
            let event_endpoint = read_u64(request, 16).unwrap_or(0);
            if width == 0 || height == 0 || width > MAX_DIMENSION || height > MAX_DIMENSION {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EINVAL));
                return reply;
            }
            let (parent, placement) = if role == SurfaceRole::Popup {
                let Some(parent_token) = read_u64(request, 24) else {
                    put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EINVAL));
                    return reply;
                };
                let parent_handle = SurfaceHandle(parent_token);
                let Some(parent_index) =
                    surface_index_for(surfaces, client, parent_handle, SurfaceRights::COMMIT)
                else {
                    put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                    return reply;
                };
                let parent_role = surfaces[parent_index].role;
                if !matches!(parent_role, SurfaceRole::Toplevel | SurfaceRole::Popup) {
                    put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                    return reply;
                }
                let placement = PopupPlacement {
                    anchor_rect: Rect {
                        x: read_u32(request, 32).unwrap_or(0) as i32,
                        y: read_u32(request, 36).unwrap_or(0) as i32,
                        width: read_u32(request, 40).unwrap_or(1),
                        height: read_u32(request, 44).unwrap_or(1),
                    },
                    offset: Point {
                        x: read_u32(request, 48).unwrap_or(0) as i32,
                        y: read_u32(request, 52).unwrap_or(0) as i32,
                    },
                };
                if validate_damage_rect(
                    placement.anchor_rect,
                    surfaces[parent_index].width,
                    surfaces[parent_index].height,
                )
                .is_err()
                {
                    put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EINVAL));
                    return reply;
                }
                (Some(parent_handle), placement)
            } else {
                (None, PopupPlacement::default())
            };
            let Some(index) = surfaces.iter().position(|s| !s.live) else {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::ENOSPC));
                return reply;
            };
            let z = if role == SurfaceRole::Background {
                0
            } else {
                *next_z = next_z.wrapping_add(1);
                *next_z
            };
            let token = match generate_surface_token(surfaces) {
                Ok(token) => token,
                Err(status) => {
                    put_u32(&mut reply, 0, status);
                    return reply;
                }
            };
            let handle = SurfaceHandle(token);
            let (window_id, window_token, window_slot) = if role == SurfaceRole::Toplevel {
                let Some(slot) = windows.iter().position(|window| !window.live) else {
                    put_u32(&mut reply, 0, errno_status(mochi_user_syscall::ENOSPC));
                    return reply;
                };
                *next_window_id = next_window_id.wrapping_add(1).max(1);
                let window_token = match generate_window_token(windows) {
                    Ok(token) => token,
                    Err(status) => {
                        put_u32(&mut reply, 0, status);
                        return reply;
                    }
                };
                (WindowId(*next_window_id), window_token, Some(slot))
            } else {
                (WindowId(0), 0, None)
            };
            let (x, y) = if let Some(parent_handle) = parent {
                let Some(parent_index) = surfaces
                    .iter()
                    .position(|surface| surface.live && surface.handle == parent_handle)
                else {
                    put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                    return reply;
                };
                (
                    surfaces[parent_index]
                        .x
                        .saturating_add(placement.anchor_rect.x)
                        .saturating_add(placement.offset.x),
                    surfaces[parent_index]
                        .y
                        .saturating_add(placement.anchor_rect.y)
                        .saturating_add(placement.offset.y),
                )
            } else if sender_has_overlay_compat_capability(sender) {
                (0, 0)
            } else {
                let cascade = *next_window_index % 8;
                *next_window_index = next_window_index.wrapping_add(1);
                (
                    32i32.saturating_add((cascade as i32).saturating_mul(24)),
                    48i32.saturating_add((cascade as i32).saturating_mul(24)),
                )
            };
            surfaces[index].reset();
            surfaces[index].live = true;
            surfaces[index].owner = client;
            surfaces[index].event_endpoint = event_endpoint;
            surfaces[index].handle = handle;
            surfaces[index].token = token;
            surfaces[index].role = role;
            surfaces[index].rights = rights;
            surfaces[index].parent = parent;
            surfaces[index].window = window_id;
            surfaces[index].is_decoration = false;
            surfaces[index].visible = true;
            surfaces[index].x = x;
            surfaces[index].y = y;
            surfaces[index].width = width;
            surfaces[index].height = height;
            surfaces[index].z = z;
            if let Some(slot) = window_slot {
                windows[slot] = Window::empty();
                windows[slot].live = true;
                windows[slot].id = window_id;
                windows[slot].token = window_token;
                windows[slot].content = handle;
                windows[slot].resizable = true;
            }
            put_u32(&mut reply, 0, 0);
            reply[4..12].copy_from_slice(&token.to_le_bytes());
        }
        OP_ATTACH_BUFFER => {
            let token = read_u64(request, 4).unwrap_or(0);
            let width = read_u32(request, 12).unwrap_or(0);
            let height = read_u32(request, 16).unwrap_or(0);
            let stride = read_u32(request, 20).unwrap_or(0);
            let format = read_u32(request, 24).unwrap_or(0);
            let handle = SurfaceHandle(token);
            let Some(index) =
                surface_index_for(surfaces, client, handle, SurfaceRights::ATTACH_BUFFER)
            else {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            };
            let attach_reject_reason = if format != PIXEL_FORMAT_XRGB8888 {
                Some(1)
            } else if width == 0 {
                Some(2)
            } else if height == 0 {
                Some(3)
            } else if stride < width {
                Some(4)
            } else if width > MAX_DIMENSION || height > MAX_DIMENSION {
                Some(5)
            } else {
                None
            };
            if let Some(reason) = attach_reject_reason {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EINVAL));
                put_u32(&mut reply, 4, reason);
                put_u32(&mut reply, 8, height);
                put_u32(&mut reply, 12, height);
                return reply;
            }
            let (row_bytes, needed, pixels) =
                match validate_buffer_layout(width, height, stride, format, width, height) {
                    Ok(layout) => layout,
                    Err(status) => {
                        put_u32(&mut reply, 0, status);
                        return reply;
                    }
                };
            if request.len() == 28 {
                let surface = &mut surfaces[index];
                surface.width = width;
                surface.height = height;
                surface.pending_width = width;
                surface.pending_height = height;
                surface.pending_stride = stride;
                surface.pending_len = pixels;
                surface.pending_bytes_received = 0;
                surface.pending.clear();
                surface.pending_buffer = None;
                surface.pending_damage = Some(Rect::full(width, height));
                if let Some(buffer) = surface.current_buffer.as_ref() {
                    if buffer.width == width
                        && buffer.height == height
                        && buffer.stride == stride
                        && buffer.pixels == pixels
                    {
                        surface.pending_buffer = Some(buffer.clone());
                        surface.pending_bytes_received = buffer.byte_len;
                        surface.awaiting_buffer = false;
                    } else {
                        surface.awaiting_buffer = true;
                    }
                } else {
                    surface.awaiting_buffer = true;
                }
            } else {
                if needed > MAX_SHARED_BYTES {
                    put_u32(&mut reply, 0, errno_status(mochi_user_syscall::ERANGE));
                    return reply;
                }
                if request.len() < 28 + needed {
                    put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EINVAL));
                    return reply;
                }
                let mut pending = Vec::new();
                if !resize_buffer(&mut pending, width, height) {
                    put_u32(&mut reply, 0, errno_status(mochi_user_syscall::ENOMEM));
                    return reply;
                }
                for y in 0..height as usize {
                    let Some(src_row) = y.checked_mul(row_bytes) else {
                        put_u32(&mut reply, 0, errno_status(mochi_user_syscall::ERANGE));
                        return reply;
                    };
                    let Some(dst_row) = y.checked_mul(width as usize) else {
                        put_u32(&mut reply, 0, errno_status(mochi_user_syscall::ERANGE));
                        return reply;
                    };
                    for x in 0..width as usize {
                        let Some(src) = src_row
                            .checked_add(x.saturating_mul(4))
                            .and_then(|offset| offset.checked_add(28))
                        else {
                            put_u32(&mut reply, 0, errno_status(mochi_user_syscall::ERANGE));
                            return reply;
                        };
                        let Some(pixel) = read_pixel(request, src) else {
                            put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EINVAL));
                            return reply;
                        };
                        let Some(dst) = dst_row.checked_add(x) else {
                            put_u32(&mut reply, 0, errno_status(mochi_user_syscall::ERANGE));
                            return reply;
                        };
                        let Some(slot) = pending.get_mut(dst) else {
                            put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EINVAL));
                            return reply;
                        };
                        *slot = pixel;
                    }
                }
                let surface = &mut surfaces[index];
                surface.width = width;
                surface.height = height;
                surface.pending = pending;
                surface.pending_width = width;
                surface.pending_height = height;
                surface.pending_stride = stride;
                surface.pending_len = pixels;
                surface.pending_bytes_received = needed;
                surface.pending_buffer = None;
                surface.pending_damage = Some(Rect::full(width, height));
                surface.awaiting_buffer = false;
            }
            put_u32(&mut reply, 0, 0);
        }
        OP_DAMAGE => {
            let token = read_u64(request, 4).unwrap_or(0);
            let handle = SurfaceHandle(token);
            let Some(index) = surface_index_for(surfaces, client, handle, SurfaceRights::DAMAGE)
            else {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            };
            let damage = if request.len() >= 28 {
                let rect = Rect {
                    x: read_u32(request, 12).unwrap_or(0) as i32,
                    y: read_u32(request, 16).unwrap_or(0) as i32,
                    width: read_u32(request, 20).unwrap_or(0),
                    height: read_u32(request, 24).unwrap_or(0),
                };
                match validate_damage_rect(rect, surfaces[index].width, surfaces[index].height) {
                    Ok(rect) => Some(rect),
                    Err(status) => {
                        put_u32(&mut reply, 0, status);
                        return reply;
                    }
                }
            } else {
                Some(Rect::full(surfaces[index].width, surfaces[index].height))
            };
            if surfaces[index].pending_width == 0 {
                if let Some(buffer) = surfaces[index].current_buffer.clone() {
                    let surface = &mut surfaces[index];
                    surface.pending_width = buffer.width;
                    surface.pending_height = buffer.height;
                    surface.pending_stride = buffer.stride;
                    surface.pending_len = buffer.pixels;
                    surface.pending_bytes_received = buffer.byte_len;
                    surface.pending_buffer = Some(buffer);
                    surface.awaiting_buffer = false;
                }
            }
            surfaces[index].pending_damage = damage;
            put_u32(&mut reply, 0, 0);
        }
        OP_COMMIT => {
            let token = read_u64(request, 4).unwrap_or(0);
            let handle = SurfaceHandle(token);
            let Some(index) = surface_index_for(surfaces, client, handle, SurfaceRights::COMMIT)
            else {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            };
            let (pending_width, pending_height, pending_len, pending_stride, awaiting_buffer) = {
                let surface = &surfaces[index];
                (
                    surface.pending_width,
                    surface.pending_height,
                    surface.pending_len,
                    surface.pending_stride,
                    surface.awaiting_buffer,
                )
            };
            let pending_damage = surfaces[index]
                .pending_damage
                .unwrap_or(Rect::full(pending_width, pending_height));
            if awaiting_buffer || pending_width == 0 || pending_len == 0 {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EINVAL));
                return reply;
            }
            let Some(needed) = (pending_width as usize).checked_mul(pending_height as usize) else {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EINVAL));
                return reply;
            };
            if pending_stride < pending_width {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EINVAL));
                return reply;
            }
            if surfaces[index].pending_buffer.is_none() && surfaces[index].pending.len() < needed {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EINVAL));
                return reply;
            }
            {
                let surface = &mut surfaces[index];
                if surface.role == SurfaceRole::Background {
                    if let Some(buffer) = surface.pending_buffer.take() {
                        let can_patch_current = surface.current_width == pending_width
                            && surface.current_height == pending_height
                            && surface.current_stride == pending_width
                            && surface.current.len() >= needed;
                        if can_patch_current {
                            if let Err(status) = copy_surface_buffer_rect(
                                &buffer,
                                pending_damage,
                                &mut surface.current,
                                pending_width,
                                pending_height,
                            ) {
                                put_u32(&mut reply, 0, status);
                                return reply;
                            }
                            surface.current_buffer = Some(buffer);
                        } else {
                            match copy_surface_buffer(&buffer) {
                                Ok(pixels) => {
                                    surface.current = pixels;
                                    surface.current_buffer = Some(buffer);
                                }
                                Err(status) => {
                                    put_u32(&mut reply, 0, status);
                                    return reply;
                                }
                            }
                        }
                    } else {
                        surface.current_buffer = None;
                        core::mem::swap(&mut surface.current, &mut surface.pending);
                    }
                    surface.current_stride = pending_width;
                } else {
                    surface.current_buffer = surface.pending_buffer.take();
                    if surface.current_buffer.is_some() {
                        surface.current.clear();
                    } else {
                        core::mem::swap(&mut surface.current, &mut surface.pending);
                    }
                    surface.current_stride = pending_stride;
                }
                surface.current_width = pending_width;
                surface.current_height = pending_height;
                surface.pending_width = 0;
                surface.pending_height = 0;
                surface.pending_stride = 0;
                surface.pending_len = 0;
                surface.pending_bytes_received = 0;
                surface.pending_damage = None;
                surface.pending_buffer = None;
                surface.awaiting_buffer = false;
            }
            *needs_present = true;
            let screen_damage = Rect {
                x: surfaces[index].x.saturating_add(pending_damage.x),
                y: surfaces[index].y.saturating_add(pending_damage.y),
                width: pending_damage.width,
                height: pending_damage.height,
            };
            *present_damage = merge_damage(*present_damage, screen_damage);
            if !surfaces[index].is_decoration {
                let window_id = surfaces[index].window;
                if let Some(window_index) = window_index_by_id(windows, window_id) {
                    if !windows[window_index].metadata_sent {
                        windows[window_index].metadata_sent = true;
                        notify_decorators(clients, windows, surfaces, window_index);
                    }
                }
            }
            put_u32(&mut reply, 0, 0);
        }
        OP_SET_POSITION => {
            put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
        }
        OP_DESTROY_SURFACE => {
            let token = read_u64(request, 4).unwrap_or(0);
            let handle = SurfaceHandle(token);
            if let Some(index) = surface_index_for(surfaces, client, handle, SurfaceRights::DESTROY)
            {
                destroy_surface_tree(surfaces, windows, index, pointer_focus, keyboard_focus);
                *needs_present = true;
                put_u32(&mut reply, 0, 0);
            } else {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
            }
        }
        OP_DECOR_SUBSCRIBE
        | OP_DECOR_CREATE_SURFACE
        | OP_DECOR_ATTACH
        | OP_DECOR_DETACH
        | OP_DECOR_UPDATE_INSETS
        | OP_DECOR_BEGIN_MOVE
        | OP_DECOR_BEGIN_RESIZE
        | OP_DECOR_MINIMIZE
        | OP_DECOR_TOGGLE_MAXIMIZE
        | OP_DECOR_CLOSE_REQUEST => {
            return crate::decoration::handle_request(
                clients,
                surfaces,
                windows,
                next_z,
                pointer_serials,
                pointer_focus,
                keyboard_focus,
                client,
                sender,
                request,
                needs_present,
            );
        }
        _ => put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EINVAL)),
    }
    reply
}

pub(crate) fn run() -> ! {
    platform::println!("compositor.service: start");
    let endpoint = match platform::ipc::create() {
        Ok(endpoint) => endpoint,
        Err(_) => platform::process::exit(1),
    };
    let Some(display_tid) = wait_for_service(4096) else {
        platform::println!("compositor.service: display.driver not found");
        platform::process::exit(1);
    };
    let input_subscribed = subscribe_input_events(endpoint);
    let claim_status = display_claim_present_owner(display_tid);
    if claim_status != 0 {
        platform::println!(
            "compositor.service: display claim failed status={}",
            claim_status
        );
    }
    let (display_width, display_height, display_stride, display_format) =
        display_request_info(display_tid);

    let mut state = CompositorState::new(
        display_tid,
        display_width,
        display_height,
        display_stride,
        display_format,
        input_subscribed,
    );
    let _ = composite_and_present(
        &state.surfaces,
        &mut state.present_frame,
        state.display_tid,
        state.display_width,
        state.display_height,
        state.display_stride,
        state.display_format,
        None,
    );
    loop {
        let buf = unsafe {
            core::slice::from_raw_parts_mut(core::ptr::addr_of_mut!(IPC_BUF).cast::<u8>(), 4128)
        };
        let msg = match platform::ipc::try_wait(buf) {
            Ok(msg) => {
                state.idle_cleanup_ticks = 0;
                msg
            }
            Err(_) => {
                state.idle_cleanup_ticks = state.idle_cleanup_ticks.wrapping_add(1);
                state.input_subscribe_retry_ticks =
                    state.input_subscribe_retry_ticks.wrapping_add(1);
                if !state.input_subscribed
                    && state.input_subscribe_retry_ticks >= IDLE_CLEANUP_YIELDS
                {
                    state.input_subscribe_retry_ticks = 0;
                    state.input_subscribed = subscribe_input_events(endpoint);
                }
                if state.idle_cleanup_ticks >= IDLE_CLEANUP_YIELDS {
                    state.idle_cleanup_ticks = 0;
                    if cleanup_dead_clients(
                        &mut state.clients,
                        &mut state.surfaces,
                        &mut state.windows,
                        &mut state.pointer_focus,
                        &mut state.keyboard_focus,
                    ) {
                        let _ = composite_and_present(
                            &state.surfaces,
                            &mut state.present_frame,
                            state.display_tid,
                            state.display_width,
                            state.display_height,
                            state.display_stride,
                            state.display_format,
                            None,
                        );
                    }
                }
                sleep_one_tick();
                continue;
            }
        };
        let sender = msg >> 32;
        let len = (msg & 0xffff_ffff) as usize;
        if len == 16 {
            let client =
                client_id_for_sender(&mut state.clients, sender, &mut state.next_client_id);
            if client == ClientId(0) {
                continue;
            }
            let mapped_addr = u64::from_le_bytes([
                buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
            ]);
            let total = u64::from_le_bytes([
                buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
            ]);
            if handle_shared_buffer(&mut state.surfaces, client, mapped_addr, total) {
                continue;
            }
        }
        if len == core::mem::size_of::<platform::input::InputEvent>() {
            let event = unsafe {
                core::ptr::read_unaligned(buf.as_ptr().cast::<platform::input::InputEvent>())
            };
            let needs_present = handle_input_event(
                &state.surfaces,
                &state.windows,
                &mut state.next_pointer_serial,
                &mut state.pointer_serials,
                &mut state.pointer_x,
                &mut state.pointer_y,
                state.display_width,
                state.display_height,
                &mut state.pointer_focus,
                &mut state.keyboard_focus,
                &event,
            );
            if needs_present {
                let _ = composite_and_present(
                    &state.surfaces,
                    &mut state.present_frame,
                    state.display_tid,
                    state.display_width,
                    state.display_height,
                    state.display_stride,
                    state.display_format,
                    None,
                );
            }
            continue;
        }
        if len == 0 || len > buf.len() {
            let mut reply = [0u8; 16];
            put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EINVAL));
            let _ = platform::ipc::reply(sender, &reply);
            continue;
        }
        let client = client_id_for_sender(&mut state.clients, sender, &mut state.next_client_id);
        if client == ClientId(0) {
            let mut reply = [0u8; 16];
            put_u32(&mut reply, 0, errno_status(mochi_user_syscall::ENOSPC));
            let _ = platform::ipc::reply(sender, &reply);
            continue;
        }
        let mut needs_present = false;
        let mut present_damage = None;
        let reply = handle_request(
            &mut state.clients,
            &mut state.surfaces,
            &mut state.windows,
            &mut state.next_z,
            &mut state.next_window_index,
            &mut state.next_window_id,
            &mut state.next_pointer_serial,
            &mut state.pointer_serials,
            &mut state.pointer_focus,
            &mut state.keyboard_focus,
            client,
            sender,
            &buf[..len],
            &mut needs_present,
            &mut present_damage,
            state.display_tid,
            state.display_width,
            state.display_height,
            state.display_stride,
            state.display_format,
        );
        if platform::ipc::reply(sender, &reply).is_err() {
            cleanup_client(
                &mut state.clients,
                &mut state.surfaces,
                &mut state.windows,
                client,
                &mut state.pointer_focus,
                &mut state.keyboard_focus,
            );
        } else {
            if needs_present {
                let status = composite_and_present(
                    &state.surfaces,
                    &mut state.present_frame,
                    state.display_tid,
                    state.display_width,
                    state.display_height,
                    state.display_stride,
                    state.display_format,
                    present_damage,
                );
                if status == 0 {
                    for surface in state.surfaces.iter().filter(|surface| surface.live) {
                        send_frame_done(surface);
                    }
                } else {
                    platform::println!("compositor.service: present deferred status={}", status);
                }
            }
        }
    }
}
