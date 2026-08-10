use mochi_user_platform as platform;

use crate::context_menu::ContextMenuBroker;
use crate::geometry::{Rect, merge_damage};
use crate::protocol::{
    DECOR_EVENT_POINTER_BUTTON, DECOR_EVENT_POINTER_LEAVE, DECOR_EVENT_POINTER_MOTION,
    EVENT_APPEARANCE_CHANGED, EVENT_FOCUS_GAINED, EVENT_FOCUS_LOST, EVENT_KEY,
    EVENT_POINTER_BUTTON, EVENT_POINTER_ENTER, EVENT_POINTER_LEAVE, EVENT_POINTER_MOTION,
    EVENT_POINTER_SCROLL, put_i32, put_u32, put_u64,
};
use crate::state::MAX_DIMENSION;
use crate::surface::surface_extent;
use crate::surface::{Surface, SurfaceHandle, SurfaceRole, read_current_pixel};
use crate::window::{
    WINDOW_SHADOW_MARGIN, Window, WindowId, content_surface_index_for_window,
    point_inside_window_frame, window_frame_rect, window_index_by_id,
};

const INPUT_SERVICE_NAME: &str = "input.service";
const RELIABLE_SEND_RETRIES: usize = 256;

static mut INPUT_SUBSCRIBE_REQ: [u8; 16] = [0; 16];
static mut INPUT_SUBSCRIBE_REP: [u8; 8] = [0; 8];

#[derive(Clone, Copy, Default)]
pub(crate) struct PointerSerial {
    pub(crate) serial: u64,
    pub(crate) window: WindowId,
    pub(crate) decoration: SurfaceHandle,
    pub(crate) used: bool,
}

#[derive(Clone, Copy)]
pub(crate) struct PointerGrab {
    pub(crate) window: WindowId,
    pub(crate) pointer_x: i32,
    pub(crate) pointer_y: i32,
    pub(crate) content_x: i32,
    pub(crate) content_y: i32,
}

fn find_service(name: &str) -> Option<u64> {
    for _ in 0..64 {
        if let Ok(tid) = platform::process::find_by_name(name)
            && tid != 0
        {
            return Some(tid);
        }
        platform::thread::yield_now();
    }
    None
}

pub(crate) fn subscribe_input_events(endpoint: u64) -> bool {
    let Some(input_tid) = find_service(INPUT_SERVICE_NAME) else {
        return false;
    };
    let subscribe = unsafe {
        core::slice::from_raw_parts_mut(
            core::ptr::addr_of_mut!(INPUT_SUBSCRIBE_REQ).cast::<u8>(),
            16,
        )
    };
    subscribe.fill(0);
    put_u32(subscribe, 0, platform::input::SUBSCRIBE_OPCODE);
    subscribe[8..16].copy_from_slice(&endpoint.to_le_bytes());
    let reply = unsafe {
        core::slice::from_raw_parts_mut(
            core::ptr::addr_of_mut!(INPUT_SUBSCRIBE_REP).cast::<u8>(),
            8,
        )
    };
    reply.fill(0);
    platform::ipc::call(input_tid, subscribe, reply).is_ok()
}

pub(crate) fn clear_focus_for_surface(
    surfaces: &[Surface],
    index: usize,
    pointer_focus: &mut Option<usize>,
    keyboard_focus: &mut Option<usize>,
) {
    if pointer_focus.is_some_and(|focus| focus == index) {
        if let Some(surface) = surfaces.get(index)
            && surface.live
        {
            send_event(surface.event_endpoint, EVENT_POINTER_LEAVE, 0, 0, 0);
        }
        *pointer_focus = None;
    }
    if keyboard_focus.is_some_and(|focus| focus == index) {
        update_keyboard_focus(surfaces, keyboard_focus, None);
    }
}

fn hit_test(surfaces: &[Surface], windows: &[Window], x: i32, y: i32) -> Option<usize> {
    let mut hit = None;
    let mut best_stack = (0u8, 0u32);
    for (index, surface) in surfaces.iter().enumerate() {
        if !surface.live || !surface.visible {
            continue;
        }
        let (width, height) = surface_extent(surface);
        let right = surface.x.saturating_add(width as i32);
        let bottom = surface.y.saturating_add(height as i32);
        if x >= surface.x
            && x < right
            && y >= surface.y
            && y < bottom
            && (surface.role.stack_layer(), surface.z) >= best_stack
            && point_inside_window_frame(surfaces, windows, surface, x, y)
        {
            if surface.role == SurfaceRole::Panel {
                let sx = x.saturating_sub(surface.x) as usize;
                let sy = y.saturating_sub(surface.y) as usize;
                if read_current_pixel(surface, sx, sy).is_none_or(|pixel| pixel >> 24 == 0) {
                    continue;
                }
            }
            hit = Some(index);
            best_stack = (surface.role.stack_layer(), surface.z);
        }
    }
    hit
}

pub(crate) fn send_event(endpoint: u64, kind: u32, a: i32, b: i32, c: u32) {
    if endpoint == 0 {
        return;
    }
    let mut event = [0u8; 20];
    put_u32(&mut event, 0, kind);
    put_i32(&mut event, 4, a);
    put_i32(&mut event, 8, b);
    put_u32(&mut event, 12, c);
    if kind != EVENT_KEY
        && kind != EVENT_POINTER_BUTTON
        && kind != EVENT_POINTER_SCROLL
        && kind != EVENT_APPEARANCE_CHANGED
    {
        let _ = platform::ipc::send(endpoint, &event);
        return;
    }
    for _ in 0..RELIABLE_SEND_RETRIES {
        match platform::ipc::send(endpoint, &event) {
            Ok(_) => break,
            Err(error) if error.errno() == Some(mochi_user_syscall::EAGAIN) => {
                platform::thread::yield_now();
            }
            Err(_) => break,
        }
    }
}

fn send_decoration_button_event(
    endpoint: u64,
    window_token: u64,
    x: i32,
    y: i32,
    detail: u32,
    serial: u64,
) {
    if endpoint == 0 {
        return;
    }
    let mut event = [0u8; 32];
    put_u32(&mut event, 0, DECOR_EVENT_POINTER_BUTTON);
    put_i32(&mut event, 4, x);
    put_i32(&mut event, 8, y);
    put_u32(&mut event, 12, detail);
    put_u64(&mut event, 16, window_token);
    put_u64(&mut event, 24, serial);
    let _ = platform::ipc::send(endpoint, &event);
}

fn send_decoration_pointer_event(endpoint: u64, kind: u32, window_token: u64, x: i32, y: i32) {
    if endpoint == 0 {
        return;
    }
    let mut event = [0u8; 24];
    put_u32(&mut event, 0, kind);
    put_i32(&mut event, 4, x);
    put_i32(&mut event, 8, y);
    put_u64(&mut event, 16, window_token);
    let _ = platform::ipc::send(endpoint, &event);
}

fn dispatch_pointer_motion(
    surfaces: &[Surface],
    windows: &[Window],
    pointer_x: i32,
    pointer_y: i32,
    pointer_focus: &mut Option<usize>,
) {
    let next = hit_test(surfaces, windows, pointer_x, pointer_y);
    if *pointer_focus != next {
        if let Some(index) = *pointer_focus {
            if let Some(surface) = surfaces.get(index)
                && surface.live
            {
                if surface.is_decoration {
                    let window_token = window_index_by_id(windows, surface.window)
                        .map(|index| windows[index].token)
                        .unwrap_or(0);
                    send_decoration_pointer_event(
                        surface.event_endpoint,
                        DECOR_EVENT_POINTER_LEAVE,
                        window_token,
                        0,
                        0,
                    );
                } else {
                    send_event(surface.event_endpoint, EVENT_POINTER_LEAVE, 0, 0, 0);
                }
            }
        }
        *pointer_focus = next;
        if let Some(index) = next {
            let surface = &surfaces[index];
            if !surface.is_decoration {
                send_event(
                    surface.event_endpoint,
                    EVENT_POINTER_ENTER,
                    pointer_x - surface.x,
                    pointer_y - surface.y,
                    0,
                );
            }
        }
    }
    if let Some(index) = *pointer_focus {
        if let Some(surface) = surfaces.get(index)
            && surface.live
        {
            if surface.is_decoration {
                let window_token = window_index_by_id(windows, surface.window)
                    .map(|index| windows[index].token)
                    .unwrap_or(0);
                send_decoration_pointer_event(
                    surface.event_endpoint,
                    DECOR_EVENT_POINTER_MOTION,
                    window_token,
                    pointer_x - surface.x,
                    pointer_y - surface.y,
                );
            } else {
                send_event(
                    surface.event_endpoint,
                    EVENT_POINTER_MOTION,
                    pointer_x - surface.x,
                    pointer_y - surface.y,
                    0,
                );
            }
        }
    }
}

pub(crate) fn update_keyboard_focus(
    surfaces: &[Surface],
    keyboard_focus: &mut Option<usize>,
    next: Option<usize>,
) {
    if *keyboard_focus == next {
        return;
    }
    if let Some(index) = *keyboard_focus {
        if let Some(surface) = surfaces.get(index)
            && surface.live
        {
            send_event(surface.event_endpoint, EVENT_FOCUS_LOST, 0, 0, 0);
        }
    }
    *keyboard_focus = next;
    if let Some(index) = *keyboard_focus {
        if let Some(surface) = surfaces.get(index)
            && surface.live
        {
            send_event(surface.event_endpoint, EVENT_FOCUS_GAINED, 0, 0, 0);
        }
    }
}

pub(crate) fn handle_input_event(
    surfaces: &mut [Surface],
    windows: &mut [Window],
    next_z: &mut u32,
    next_pointer_serial: &mut u64,
    pointer_serials: &mut [PointerSerial],
    pointer_x: &mut i32,
    pointer_y: &mut i32,
    display_width: u32,
    display_height: u32,
    pointer_focus: &mut Option<usize>,
    keyboard_focus: &mut Option<usize>,
    pointer_grab: &mut Option<PointerGrab>,
    context_menu: &mut ContextMenuBroker,
    event: &platform::input::InputEvent,
) -> Option<Rect> {
    match event.kind {
        platform::input::EVENT_KIND_POINTER_MOVE | platform::input::EVENT_KIND_POINTER_ABSOLUTE => {
            update_pointer_position(pointer_x, pointer_y, display_width, display_height, event);
            finish_pointer_motion(
                surfaces,
                windows,
                pointer_grab,
                *pointer_x,
                *pointer_y,
                pointer_focus,
            )
        }
        platform::input::EVENT_KIND_POINTER_BUTTON => {
            let target = hit_test(surfaces, windows, *pointer_x, *pointer_y);
            if context_menu.capture_pointer_button(
                target.map(|index| surfaces[index].owner),
                event.flags & platform::input::FLAG_PRESS != 0,
            ) {
                return None;
            }
            let mut needs_window_redraw = false;
            if event.flags & platform::input::FLAG_PRESS != 0 {
                let focus = target.and_then(|index| {
                    let surface = &surfaces[index];
                    if surface.is_decoration {
                        let window_index = window_index_by_id(windows, surface.window)?;
                        content_surface_index_for_window(surfaces, &windows[window_index])
                    } else {
                        Some(index)
                    }
                });
                let previous_focus = *keyboard_focus;
                update_keyboard_focus(surfaces, keyboard_focus, focus);
                needs_window_redraw = previous_focus != *keyboard_focus;
                if let Some(index) = target {
                    let window = surfaces[index].window;
                    raise_window(surfaces, windows, next_z, window);
                    needs_window_redraw |= window != WindowId(0);
                }
            }
            if let Some(index) = target {
                let surface = &surfaces[index];
                let detail = (u32::from(event.flags) << 16) | u32::from(event.detail);
                let mut serial = 0;
                if event.flags & platform::input::FLAG_PRESS != 0 && surface.is_decoration {
                    *next_pointer_serial = next_pointer_serial.wrapping_add(1).max(1);
                    serial = *next_pointer_serial;
                    if let Some(slot) = pointer_serials
                        .iter_mut()
                        .find(|record| record.used || record.serial == 0)
                    {
                        *slot = PointerSerial {
                            serial: *next_pointer_serial,
                            window: surface.window,
                            decoration: surface.handle,
                            used: false,
                        };
                    }
                }
                if surface.is_decoration {
                    let window_token = window_index_by_id(windows, surface.window)
                        .map(|index| windows[index].token)
                        .unwrap_or(0);
                    send_decoration_button_event(
                        surface.event_endpoint,
                        window_token,
                        *pointer_x - surface.x,
                        *pointer_y - surface.y,
                        detail,
                        serial,
                    );
                } else {
                    send_event(
                        surface.event_endpoint,
                        EVENT_POINTER_BUTTON,
                        *pointer_x - surface.x,
                        *pointer_y - surface.y,
                        detail,
                    );
                }
            }
            if event.flags & platform::input::FLAG_RELEASE != 0 {
                *pointer_grab = None;
            }
            needs_window_redraw.then_some(Rect::full(display_width, display_height))
        }
        platform::input::EVENT_KIND_POINTER_WHEEL => {
            if let Some(index) = *pointer_focus
                && let Some(surface) = surfaces.get(index)
                && surface.live
                && !surface.is_decoration
            {
                send_event(
                    surface.event_endpoint,
                    EVENT_POINTER_SCROLL,
                    event.value_x,
                    event.value_y,
                    0,
                );
            }
            None
        }
        platform::input::EVENT_KIND_KEY => {
            if context_menu.capture_key(
                event.keycode,
                event.flags & platform::input::FLAG_PRESS != 0,
            ) {
                return None;
            }
            if let Some(index) = *keyboard_focus {
                if let Some(surface) = surfaces.get(index)
                    && surface.live
                {
                    send_event(
                        surface.event_endpoint,
                        EVENT_KEY,
                        i32::from(event.keycode),
                        event.codepoint as i32,
                        encode_key_event_detail(event.flags, event.modifiers),
                    );
                }
            }
            None
        }
        _ => None,
    }
}

fn encode_key_event_detail(flags: u16, modifiers: u32) -> u32 {
    u32::from(flags) | ((modifiers & 0xffff) << 16)
}

#[cfg(test)]
mod tests {
    use super::encode_key_event_detail;

    #[test]
    fn key_event_detail_preserves_flags_and_modifiers() {
        assert_eq!(encode_key_event_detail(0x0003, 0x000b), 0x000b_0003);
    }
}

pub(crate) fn update_pointer_position(
    pointer_x: &mut i32,
    pointer_y: &mut i32,
    display_width: u32,
    display_height: u32,
    event: &platform::input::InputEvent,
) {
    let max_x = display_width.saturating_sub(1).min(MAX_DIMENSION);
    let max_y = display_height.saturating_sub(1).min(MAX_DIMENSION);
    if event.kind == platform::input::EVENT_KIND_POINTER_MOVE {
        *pointer_x = pointer_x
            .saturating_add(event.value_x)
            .clamp(0, max_x as i32);
        *pointer_y = pointer_y
            .saturating_add(event.value_y)
            .clamp(0, max_y as i32);
    } else if event.kind == platform::input::EVENT_KIND_POINTER_ABSOLUTE {
        let x = event.value_x.clamp(0, 32_767) as u32;
        let y = event.value_y.clamp(0, 32_767) as u32;
        *pointer_x = if max_x == 0 {
            0
        } else {
            ((u64::from(x) * u64::from(max_x)) / 32_767) as i32
        };
        *pointer_y = if max_y == 0 {
            0
        } else {
            ((u64::from(y) * u64::from(max_y)) / 32_767) as i32
        };
    }
}

pub(crate) fn finish_pointer_motion(
    surfaces: &mut [Surface],
    windows: &[Window],
    pointer_grab: &Option<PointerGrab>,
    pointer_x: i32,
    pointer_y: i32,
    pointer_focus: &mut Option<usize>,
) -> Option<Rect> {
    let damage = apply_pointer_grab(surfaces, windows, pointer_grab, pointer_x, pointer_y);
    dispatch_pointer_motion(surfaces, windows, pointer_x, pointer_y, pointer_focus);
    damage
}

fn raise_window(
    surfaces: &mut [Surface],
    windows: &[Window],
    next_z: &mut u32,
    window_id: WindowId,
) {
    let Some(window_index) = window_index_by_id(windows, window_id) else {
        return;
    };
    *next_z = next_z.wrapping_add(2).max(2);
    if let Some(content_index) = content_surface_index_for_window(surfaces, &windows[window_index])
    {
        surfaces[content_index].z = next_z.saturating_sub(1);
    }
    if let Some(decoration) = windows[window_index].decoration
        && let Some(index) = surfaces
            .iter()
            .position(|surface| surface.live && surface.handle == decoration)
    {
        surfaces[index].z = *next_z;
    }
}

fn apply_pointer_grab(
    surfaces: &mut [Surface],
    windows: &[Window],
    pointer_grab: &Option<PointerGrab>,
    pointer_x: i32,
    pointer_y: i32,
) -> Option<Rect> {
    const WORK_AREA_TOP: i32 = 40;

    let Some(grab) = *pointer_grab else {
        return None;
    };
    let Some(window_index) = window_index_by_id(windows, grab.window) else {
        return None;
    };
    let Some(content_index) = content_surface_index_for_window(surfaces, &windows[window_index])
    else {
        return None;
    };
    let window = &windows[window_index];
    let next_x = grab
        .content_x
        .saturating_add(pointer_x.saturating_sub(grab.pointer_x));
    let next_y = grab
        .content_y
        .saturating_add(pointer_y.saturating_sub(grab.pointer_y))
        .max(WORK_AREA_TOP.saturating_add(window.insets.top as i32));
    if surfaces[content_index].x == next_x && surfaces[content_index].y == next_y {
        return None;
    }
    let old_frame =
        window_frame_rect(&surfaces[content_index], window).expanded(WINDOW_SHADOW_MARGIN);
    surfaces[content_index].x = next_x;
    surfaces[content_index].y = next_y;
    crate::window::reposition_window_surfaces(surfaces, window);
    let new_frame =
        window_frame_rect(&surfaces[content_index], window).expanded(WINDOW_SHADOW_MARGIN);
    merge_damage(Some(old_frame), new_frame)
}
