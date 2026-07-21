use mochi_user_platform as platform;

use crate::protocol::{
    EVENT_FOCUS_GAINED, EVENT_FOCUS_LOST, EVENT_KEY, EVENT_POINTER_BUTTON, EVENT_POINTER_ENTER,
    EVENT_POINTER_LEAVE, EVENT_POINTER_MOTION, put_i32, put_u32,
};
use crate::state::MAX_DIMENSION;
use crate::surface::surface_extent;
use crate::surface::{Surface, SurfaceHandle};
use crate::window::{Window, WindowId, content_surface_index_for_window, window_index_by_id};

const INPUT_SERVICE_NAME: &str = "input.service";

static mut INPUT_SUBSCRIBE_REQ: [u8; 16] = [0; 16];
static mut INPUT_SUBSCRIBE_REP: [u8; 8] = [0; 8];

#[derive(Clone, Copy, Default)]
pub(crate) struct PointerSerial {
    pub(crate) serial: u64,
    pub(crate) window: WindowId,
    pub(crate) decoration: SurfaceHandle,
    pub(crate) used: bool,
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

fn hit_test(surfaces: &[Surface], x: i32, y: i32) -> Option<usize> {
    let mut hit = None;
    let mut best_z = 0u32;
    for (index, surface) in surfaces.iter().enumerate() {
        if !surface.live || !surface.visible {
            continue;
        }
        let (width, height) = surface_extent(surface);
        let right = surface.x.saturating_add(width as i32);
        let bottom = surface.y.saturating_add(height as i32);
        if x >= surface.x && x < right && y >= surface.y && y < bottom && surface.z >= best_z {
            hit = Some(index);
            best_z = surface.z;
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
    let _ = platform::ipc::send(endpoint, &event);
}

fn dispatch_pointer_motion(
    surfaces: &[Surface],
    pointer_x: i32,
    pointer_y: i32,
    pointer_focus: &mut Option<usize>,
) {
    let next = hit_test(surfaces, pointer_x, pointer_y);
    if *pointer_focus != next {
        if let Some(index) = *pointer_focus {
            if let Some(surface) = surfaces.get(index)
                && surface.live
            {
                send_event(surface.event_endpoint, EVENT_POINTER_LEAVE, 0, 0, 0);
            }
        }
        *pointer_focus = next;
        if let Some(index) = next {
            let surface = &surfaces[index];
            send_event(
                surface.event_endpoint,
                EVENT_POINTER_ENTER,
                pointer_x - surface.x,
                pointer_y - surface.y,
                0,
            );
        }
    }
    if let Some(index) = *pointer_focus {
        if let Some(surface) = surfaces.get(index)
            && surface.live
        {
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
    surfaces: &[Surface],
    windows: &[Window],
    next_pointer_serial: &mut u64,
    pointer_serials: &mut [PointerSerial],
    pointer_x: &mut i32,
    pointer_y: &mut i32,
    display_width: u32,
    display_height: u32,
    pointer_focus: &mut Option<usize>,
    keyboard_focus: &mut Option<usize>,
    event: &platform::input::InputEvent,
) -> bool {
    match event.kind {
        platform::input::EVENT_KIND_POINTER_MOVE => {
            *pointer_x = pointer_x.saturating_add(event.value_x);
            *pointer_y = pointer_y.saturating_add(event.value_y);
            if *pointer_x < 0 {
                *pointer_x = 0;
            }
            if *pointer_y < 0 {
                *pointer_y = 0;
            }
            let max_x = display_width.saturating_sub(1).min(MAX_DIMENSION) as i32;
            let max_y = display_height.saturating_sub(1).min(MAX_DIMENSION) as i32;
            if *pointer_x > max_x {
                *pointer_x = max_x;
            }
            if *pointer_y > max_y {
                *pointer_y = max_y;
            }
            dispatch_pointer_motion(surfaces, *pointer_x, *pointer_y, pointer_focus);
            false
        }
        platform::input::EVENT_KIND_POINTER_ABSOLUTE => {
            let max_x = display_width.saturating_sub(1).min(MAX_DIMENSION);
            let max_y = display_height.saturating_sub(1).min(MAX_DIMENSION);
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
            dispatch_pointer_motion(surfaces, *pointer_x, *pointer_y, pointer_focus);
            false
        }
        platform::input::EVENT_KIND_POINTER_BUTTON => {
            let target = hit_test(surfaces, *pointer_x, *pointer_y);
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
                update_keyboard_focus(surfaces, keyboard_focus, focus);
            }
            if let Some(index) = target {
                let surface = &surfaces[index];
                let mut detail = if surface.is_decoration {
                    u32::from(event.detail)
                } else {
                    (u32::from(event.flags) << 16) | u32::from(event.detail)
                };
                if event.flags & platform::input::FLAG_PRESS != 0 && surface.is_decoration {
                    *next_pointer_serial = next_pointer_serial.wrapping_add(1).max(1);
                    detail = (*next_pointer_serial & 0xffff_ffff) as u32;
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
                send_event(
                    surface.event_endpoint,
                    EVENT_POINTER_BUTTON,
                    *pointer_x - surface.x,
                    *pointer_y - surface.y,
                    detail,
                );
            }
            false
        }
        platform::input::EVENT_KIND_KEY => {
            if let Some(index) = *keyboard_focus {
                if let Some(surface) = surfaces.get(index)
                    && surface.live
                {
                    send_event(
                        surface.event_endpoint,
                        EVENT_KEY,
                        i32::from(event.keycode),
                        event.codepoint as i32,
                        u32::from(event.flags),
                    );
                }
            }
            false
        }
        _ => false,
    }
}
