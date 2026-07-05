#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::arch::global_asm;
use mochi_user_platform as platform;

global_asm!(
    r#"
    .global _start
_start:
    xor rbp, rbp
    mov rdi, rsp
    and rsp, -16
    call service_main
1:
    hlt
    jmp 1b
"#
);

const DISPLAY_SERVICE_NAME: &str = "display.driver";
const INPUT_SERVICE_NAME: &str = "input.service";
const OP_CREATE_SURFACE: u32 = 1;
const OP_ATTACH_BUFFER: u32 = 2;
const OP_DAMAGE: u32 = 3;
const OP_COMMIT: u32 = 4;
const OP_SET_POSITION: u32 = 5;
const OP_DESTROY_SURFACE: u32 = 6;
const OP_DISPLAY_GET_INFO: u32 = 1;
const OP_DISPLAY_PRESENT: u32 = 2;
const EVENT_POINTER_ENTER: u32 = 2;
const EVENT_POINTER_LEAVE: u32 = 3;
const EVENT_POINTER_MOTION: u32 = 4;
const EVENT_POINTER_BUTTON: u32 = 5;
const EVENT_KEY: u32 = 6;
const EVENT_CONFIGURE: u32 = 7;
const EVENT_FOCUS_GAINED: u32 = 8;
const EVENT_FOCUS_LOST: u32 = 9;
const EVENT_FRAME_DONE: u32 = 10;
const ROLE_TOPLEVEL: u32 = 1;
const ROLE_POPUP: u32 = 2;
const PIXEL_FORMAT_XRGB8888: u32 = 1;
const MAX_SURFACES: usize = 8;
const MAX_DISPLAY_DIMENSION: usize = 4096;

#[allow(dead_code)]
#[derive(Clone, Copy, Default)]
struct Rect {
    x: i32,
    y: i32,
    width: u32,
    height: u32,
}

impl Rect {
    const fn full(width: u32, height: u32) -> Self {
        Self {
            x: 0,
            y: 0,
            width,
            height,
        }
    }
}

#[derive(Clone)]
struct Surface {
    live: bool,
    owner: u64,
    event_endpoint: u64,
    token: u64,
    role: u32,
    x: i32,
    y: i32,
    width: u32,
    height: u32,
    pending_width: u32,
    pending_height: u32,
    pending_stride: u32,
    pending_len: usize,
    pending_damage: Option<Rect>,
    pending: Vec<u32>,
    current_width: u32,
    current_height: u32,
    current_stride: u32,
    current: Vec<u32>,
    z: u32,
}

impl Surface {
    fn empty() -> Self {
        Self {
            live: false,
            owner: 0,
            event_endpoint: 0,
            token: 0,
            role: 0,
            x: 0,
            y: 0,
            width: 0,
            height: 0,
            pending_width: 0,
            pending_height: 0,
            pending_stride: 0,
            pending_len: 0,
            pending_damage: None,
            pending: Vec::new(),
            current_width: 0,
            current_height: 0,
            current_stride: 0,
            current: Vec::new(),
            z: 0,
        }
    }
}

fn read_u32(buf: &[u8], offset: usize) -> Option<u32> {
    let bytes = buf.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64(buf: &[u8], offset: usize) -> Option<u64> {
    let bytes = buf.get(offset..offset + 8)?;
    Some(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn put_u32(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_i32(out: &mut [u8], offset: usize, value: i32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn decode_display_info(reply: &[u8]) -> Option<(u32, u32, u32, u32)> {
    if reply.len() < 20 {
        return None;
    }
    let status = read_u32(reply, 0)?;
    if status != 0 {
        return None;
    }
    Some((
        read_u32(reply, 4)?,
        read_u32(reply, 8)?,
        read_u32(reply, 12)?,
        read_u32(reply, 16)?,
    ))
}

fn display_request_info(display_tid: u64) -> (u32, u32, u32, u32) {
    let mut req = [0u8; 4];
    put_u32(&mut req, 0, OP_DISPLAY_GET_INFO);
    let mut reply = [0u8; 32];
    if let Ok(msg) = platform::ipc::call(display_tid, &req, &mut reply) {
        let len = (msg & 0xffff_ffff) as usize;
        if let Some(info) = decode_display_info(&reply[..len.min(reply.len())]) {
            return info;
        }
    }
    (640, 480, 640, PIXEL_FORMAT_XRGB8888)
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

fn surface_index_for(surfaces: &[Surface], owner: u64, token: u64) -> Option<usize> {
    surfaces
        .iter()
        .position(|surface| surface.live && surface.owner == owner && surface.token == token)
}

fn surface_extent(surface: &Surface) -> (u32, u32) {
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
    buffer.resize(len, 0);
    true
}

fn send_configure(surface: &Surface) {
    if surface.event_endpoint == 0 {
        return;
    }
    let mut event = [0u8; 20];
    put_u32(&mut event, 0, EVENT_CONFIGURE);
    put_i32(&mut event, 4, surface.x);
    put_i32(&mut event, 8, surface.y);
    put_u32(&mut event, 12, surface.width);
    put_u32(&mut event, 16, surface.height);
    let _ = platform::ipc::send(surface.event_endpoint, &event);
}

fn send_frame_done(surface: &Surface) {
    if surface.event_endpoint == 0 {
        return;
    }
    let mut event = [0u8; 20];
    put_u32(&mut event, 0, EVENT_FRAME_DONE);
    let _ = platform::ipc::send(surface.event_endpoint, &event);
}

fn hit_test(surfaces: &[Surface], x: i32, y: i32) -> Option<usize> {
    let mut hit = None;
    let mut best_z = 0u32;
    for (index, surface) in surfaces.iter().enumerate() {
        if !surface.live {
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

fn send_event(endpoint: u64, kind: u32, a: i32, b: i32, c: u32) {
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

fn update_keyboard_focus(
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

fn handle_input_event(
    surfaces: &[Surface],
    pointer_x: &mut i32,
    pointer_y: &mut i32,
    pointer_focus: &mut Option<usize>,
    keyboard_focus: &mut Option<usize>,
    event: &platform::input::InputEvent,
) {
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
            let next = hit_test(surfaces, *pointer_x, *pointer_y);
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
                        *pointer_x - surface.x,
                        *pointer_y - surface.y,
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
                        *pointer_x - surface.x,
                        *pointer_y - surface.y,
                        0,
                    );
                }
            }
        }
        platform::input::EVENT_KIND_POINTER_BUTTON => {
            let target = hit_test(surfaces, *pointer_x, *pointer_y);
            if event.flags & platform::input::FLAG_PRESS != 0 {
                update_keyboard_focus(surfaces, keyboard_focus, target);
            }
            if let Some(index) = target {
                let surface = &surfaces[index];
                send_event(
                    surface.event_endpoint,
                    EVENT_POINTER_BUTTON,
                    *pointer_x - surface.x,
                    *pointer_y - surface.y,
                    u32::from(event.detail),
                );
            }
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
        }
        _ => {}
    }
}

fn composite_and_present(
    surfaces: &[Surface],
    display_tid: u64,
    display_width: u32,
    display_height: u32,
    display_stride: u32,
    display_format: u32,
) -> u32 {
    if display_format != PIXEL_FORMAT_XRGB8888 {
        return mochi_user_syscall::ENOTSUP as u32;
    }
    let display_w = display_width as usize;
    let display_h = display_height as usize;
    let display_s = display_stride as usize;
    if display_w == 0
        || display_h == 0
        || display_w > MAX_DISPLAY_DIMENSION
        || display_h > MAX_DISPLAY_DIMENSION
        || display_s < display_w
        || display_s > MAX_DISPLAY_DIMENSION
    {
        return mochi_user_syscall::ERANGE as u32;
    }
    let Some(frame_len) = display_w.checked_mul(display_h) else {
        return mochi_user_syscall::ERANGE as u32;
    };
    let mut frame = vec![0u32; frame_len];
    for y in 0..display_h {
        for x in 0..display_w {
            let shade = 0x0020_2630u32 + (((x as u32) ^ (y as u32)) & 0x7);
            frame[y * display_w + x] = 0xff00_0000 | shade;
        }
    }
    for surface in surfaces.iter().filter(|s| s.live) {
        let Some(surface_len) =
            (surface.current_width as usize).checked_mul(surface.current_height as usize)
        else {
            continue;
        };
        if surface.current.len() < surface_len {
            continue;
        }
        for sy in 0..surface.current_height as usize {
            let dy = surface.y + sy as i32;
            if dy < 0 || dy >= display_h as i32 {
                continue;
            }
            for sx in 0..surface.current_width as usize {
                let dx = surface.x + sx as i32;
                if dx < 0 || dx >= display_w as i32 {
                    continue;
                }
                let src = sy * surface.current_stride as usize + sx;
                if src < surface.current.len() {
                    frame[dy as usize * display_w + dx as usize] = surface.current[src];
                }
            }
        }
    }
    let Some(payload_bytes) = frame_len.checked_mul(4) else {
        return mochi_user_syscall::ERANGE as u32;
    };
    let mut request = vec![0u8; 20 + payload_bytes];
    put_u32(&mut request, 0, OP_DISPLAY_PRESENT);
    put_u32(&mut request, 4, display_width);
    put_u32(&mut request, 8, display_height);
    put_u32(&mut request, 12, display_width);
    put_u32(&mut request, 16, PIXEL_FORMAT_XRGB8888);
    for (i, pixel) in frame.iter().enumerate() {
        request[20 + i * 4..24 + i * 4].copy_from_slice(&pixel.to_le_bytes());
    }
    let mut reply = [0u8; 8];
    let Ok(msg) = platform::ipc::call(display_tid, &request, &mut reply) else {
        return mochi_user_syscall::EIO as u32;
    };
    if (msg & 0xffff_ffff) < 4 {
        return mochi_user_syscall::EIO as u32;
    }
    read_u32(&reply, 0).unwrap_or(mochi_user_syscall::EIO as u32)
}

fn handle_request(
    surfaces: &mut [Surface],
    next_token: &mut u64,
    next_z: &mut u32,
    pointer_focus: &mut Option<usize>,
    keyboard_focus: &mut Option<usize>,
    sender: u64,
    request: &[u8],
    display_tid: u64,
    display_width: u32,
    display_height: u32,
    display_stride: u32,
    display_format: u32,
) -> [u8; 16] {
    let mut reply = [0u8; 16];
    let Some(opcode) = read_u32(request, 0) else {
        put_u32(&mut reply, 0, mochi_user_syscall::EINVAL as u32);
        return reply;
    };
    match opcode {
        OP_CREATE_SURFACE => {
            let role = read_u32(request, 4).unwrap_or(0);
            let width = read_u32(request, 8).unwrap_or(0);
            let height = read_u32(request, 12).unwrap_or(0);
            let event_endpoint = read_u64(request, 16).unwrap_or(0);
            if !matches!(role, ROLE_TOPLEVEL | ROLE_POPUP)
                || width == 0
                || height == 0
                || width as usize > MAX_DISPLAY_DIMENSION
                || height as usize > MAX_DISPLAY_DIMENSION
            {
                put_u32(&mut reply, 0, mochi_user_syscall::EACCES as u32);
                return reply;
            }
            let Some(index) = surfaces.iter().position(|s| !s.live) else {
                put_u32(&mut reply, 0, mochi_user_syscall::ENOSPC as u32);
                return reply;
            };
            *next_token = next_token.wrapping_add(0x9e37_79b9_7f4a_7c15);
            *next_z = next_z.wrapping_add(1);
            let token = *next_token ^ sender.rotate_left(17);
            let x = 2 + (index as i32 * 3);
            let y = 2 + (index as i32 * 2);
            surfaces[index] = Surface::empty();
            surfaces[index].live = true;
            surfaces[index].owner = sender;
            surfaces[index].event_endpoint = event_endpoint;
            surfaces[index].token = token;
            surfaces[index].role = role;
            surfaces[index].x = x;
            surfaces[index].y = y;
            surfaces[index].width = width;
            surfaces[index].height = height;
            if !resize_buffer(&mut surfaces[index].pending, width, height)
                || !resize_buffer(&mut surfaces[index].current, width, height)
            {
                surfaces[index] = Surface::empty();
                put_u32(&mut reply, 0, mochi_user_syscall::ENOMEM as u32);
                return reply;
            }
            surfaces[index].pending_len = (width as usize) * (height as usize);
            surfaces[index].pending_damage = Some(Rect::full(width, height));
            surfaces[index].z = *next_z;
            send_configure(&surfaces[index]);
            put_u32(&mut reply, 0, 0);
            reply[4..12].copy_from_slice(&token.to_le_bytes());
        }
        OP_ATTACH_BUFFER => {
            let token = read_u64(request, 4).unwrap_or(0);
            let width = read_u32(request, 12).unwrap_or(0);
            let height = read_u32(request, 16).unwrap_or(0);
            let stride = read_u32(request, 20).unwrap_or(0);
            let format = read_u32(request, 24).unwrap_or(0);
            let Some(index) = surface_index_for(surfaces, sender, token) else {
                put_u32(&mut reply, 0, mochi_user_syscall::EACCES as u32);
                return reply;
            };
            if format != PIXEL_FORMAT_XRGB8888
                || width == 0
                || height == 0
                || stride < width
                || width as usize > MAX_DISPLAY_DIMENSION
                || height as usize > MAX_DISPLAY_DIMENSION
            {
                put_u32(&mut reply, 0, mochi_user_syscall::EINVAL as u32);
                return reply;
            }
            let Some(index_width) = surfaces.get(index).map(|surface| surface.width) else {
                put_u32(&mut reply, 0, mochi_user_syscall::EINVAL as u32);
                return reply;
            };
            let Some(index_height) = surfaces.get(index).map(|surface| surface.height) else {
                put_u32(&mut reply, 0, mochi_user_syscall::EINVAL as u32);
                return reply;
            };
            if width != index_width || height != index_height {
                put_u32(&mut reply, 0, mochi_user_syscall::ERANGE as u32);
                return reply;
            }
            let Some(row_bytes) = (stride as usize).checked_mul(4) else {
                put_u32(&mut reply, 0, mochi_user_syscall::EINVAL as u32);
                return reply;
            };
            let Some(needed) = row_bytes.checked_mul(height as usize) else {
                put_u32(&mut reply, 0, mochi_user_syscall::EINVAL as u32);
                return reply;
            };
            if request.len() < 28 + needed {
                put_u32(&mut reply, 0, mochi_user_syscall::EINVAL as u32);
                return reply;
            }
            let Some(pixels) = (width as usize).checked_mul(height as usize) else {
                put_u32(&mut reply, 0, mochi_user_syscall::EINVAL as u32);
                return reply;
            };
            let surface = &mut surfaces[index];
            surface.pending_width = width;
            surface.pending_height = height;
            surface.pending_stride = stride;
            surface.pending_len = pixels;
            surface.pending_damage = Some(Rect::full(width, height));
            if surface.pending.len() != pixels {
                if !resize_buffer(&mut surface.pending, width, height) {
                    put_u32(&mut reply, 0, mochi_user_syscall::ENOMEM as u32);
                    return reply;
                }
            }
            for y in 0..height as usize {
                for x in 0..width as usize {
                    let src = 28 + y * row_bytes + x * 4;
                    surface.pending[y * width as usize + x] = u32::from_le_bytes([
                        request[src],
                        request[src + 1],
                        request[src + 2],
                        request[src + 3],
                    ]);
                }
            }
            put_u32(&mut reply, 0, 0);
        }
        OP_DAMAGE => {
            let token = read_u64(request, 4).unwrap_or(0);
            if let Some(index) = surface_index_for(surfaces, sender, token) {
                let damage = if request.len() >= 28 {
                    let x = read_u32(request, 12).unwrap_or(0);
                    let y = read_u32(request, 16).unwrap_or(0);
                    let width = read_u32(request, 20).unwrap_or(0);
                    let height = read_u32(request, 24).unwrap_or(0);
                    Some(Rect {
                        x: x as i32,
                        y: y as i32,
                        width,
                        height,
                    })
                } else {
                    Some(Rect::full(surfaces[index].width, surfaces[index].height))
                };
                surfaces[index].pending_damage = damage;
                put_u32(&mut reply, 0, 0);
            } else {
                put_u32(&mut reply, 0, mochi_user_syscall::EACCES as u32);
            }
        }
        OP_COMMIT => {
            let token = read_u64(request, 4).unwrap_or(0);
            let Some(index) = surface_index_for(surfaces, sender, token) else {
                put_u32(&mut reply, 0, mochi_user_syscall::EACCES as u32);
                return reply;
            };
            let (pending_width, pending_height, pending_len, pending_stride) = {
                let surface = &surfaces[index];
                (
                    surface.pending_width,
                    surface.pending_height,
                    surface.pending_len,
                    surface.pending_stride,
                )
            };
            if pending_width == 0 || pending_len == 0 {
                put_u32(&mut reply, 0, mochi_user_syscall::EINVAL as u32);
                return reply;
            }
            let Some(needed) = (pending_width as usize).checked_mul(pending_height as usize) else {
                put_u32(&mut reply, 0, mochi_user_syscall::EINVAL as u32);
                return reply;
            };
            if pending_stride < pending_width {
                put_u32(&mut reply, 0, mochi_user_syscall::EINVAL as u32);
                return reply;
            }
            if surfaces[index].pending.len() < needed {
                put_u32(&mut reply, 0, mochi_user_syscall::EINVAL as u32);
                return reply;
            }
            {
                let surface = &mut surfaces[index];
                if surface.current.len() != needed
                    && !resize_buffer(&mut surface.current, pending_width, pending_height)
                {
                    put_u32(&mut reply, 0, mochi_user_syscall::ENOMEM as u32);
                    return reply;
                }
                surface.current_width = pending_width;
                surface.current_height = pending_height;
                surface.current_stride = pending_width;
                surface.current[..needed].copy_from_slice(&surface.pending[..needed]);
            }
            let status = composite_and_present(
                surfaces,
                display_tid,
                display_width,
                display_height,
                display_stride,
                display_format,
            );
            if status == 0 {
                for surface in surfaces.iter().filter(|surface| surface.live) {
                    send_frame_done(surface);
                }
            }
            put_u32(&mut reply, 0, status);
        }
        OP_SET_POSITION => {
            if request.len() < 12 {
                put_u32(&mut reply, 0, mochi_user_syscall::EINVAL as u32);
                return reply;
            }
            let token = read_u64(request, 4).unwrap_or(0);
            let Some(index) = surface_index_for(surfaces, sender, token) else {
                put_u32(&mut reply, 0, mochi_user_syscall::EACCES as u32);
                return reply;
            };
            if request.len() >= 20 {
                let x = read_u32(request, 12).unwrap_or(0) as i32;
                let y = read_u32(request, 16).unwrap_or(0) as i32;
                surfaces[index].x = x;
                surfaces[index].y = y;
            }
            send_configure(&surfaces[index]);
            let status = composite_and_present(
                surfaces,
                display_tid,
                display_width,
                display_height,
                display_stride,
                display_format,
            );
            put_u32(&mut reply, 0, status);
        }
        OP_DESTROY_SURFACE => {
            let token = read_u64(request, 4).unwrap_or(0);
            if let Some(index) = surface_index_for(surfaces, sender, token) {
                if pointer_focus.is_some_and(|focus| focus == index) {
                    if let Some(surface) = surfaces.get(index) {
                        send_event(surface.event_endpoint, EVENT_POINTER_LEAVE, 0, 0, 0);
                    }
                    *pointer_focus = None;
                }
                if keyboard_focus.is_some_and(|focus| focus == index) {
                    update_keyboard_focus(surfaces, keyboard_focus, None);
                }
                surfaces[index] = Surface::empty();
                let status = composite_and_present(
                    surfaces,
                    display_tid,
                    display_width,
                    display_height,
                    display_stride,
                    display_format,
                );
                put_u32(&mut reply, 0, status);
            } else {
                put_u32(&mut reply, 0, mochi_user_syscall::EACCES as u32);
            }
        }
        _ => put_u32(&mut reply, 0, mochi_user_syscall::EINVAL as u32),
    }
    reply
}

#[unsafe(no_mangle)]
pub extern "C" fn service_main(sp: *const usize) -> ! {
    unsafe {
        let _ = platform::logger::init_from_initial_stack(sp);
    }
    platform::println!("compositor.service: start");
    let endpoint = match platform::ipc::create() {
        Ok(endpoint) => endpoint,
        Err(_) => platform::process::exit(1),
    };
    let Some(display_tid) = find_service(DISPLAY_SERVICE_NAME) else {
        platform::println!("compositor.service: display.driver not found");
        platform::process::exit(1);
    };
    if let Some(input_tid) = find_service(INPUT_SERVICE_NAME) {
        let subscribe = platform::input::SubscribeRequest {
            opcode: platform::input::SUBSCRIBE_OPCODE,
            reserved: 0,
            endpoint,
        };
        let mut reply = [0u8; 8];
        let _ = platform::ipc::call(input_tid, platform::input::bytes_of(&subscribe), &mut reply);
    }
    let (display_width, display_height, display_stride, display_format) =
        display_request_info(display_tid);

    let mut surfaces: Vec<Surface> = vec![Surface::empty(); MAX_SURFACES];
    let mut next_token = 0x434f_4d50_5355_5246u64;
    let mut next_z = 0u32;
    let mut pointer_x = 0i32;
    let mut pointer_y = 0i32;
    let mut pointer_focus = None;
    let mut keyboard_focus = None;
    let mut buf = vec![0u8; 4128];
    loop {
        let Ok(msg) = platform::ipc::wait(endpoint, &mut buf) else {
            platform::thread::yield_now();
            continue;
        };
        let sender = msg >> 32;
        let len = (msg & 0xffff_ffff) as usize;
        if len == core::mem::size_of::<platform::input::InputEvent>() {
            let event = unsafe {
                core::ptr::read_unaligned(buf.as_ptr().cast::<platform::input::InputEvent>())
            };
            handle_input_event(
                &surfaces,
                &mut pointer_x,
                &mut pointer_y,
                &mut pointer_focus,
                &mut keyboard_focus,
                &event,
            );
            continue;
        }
        if len == 0 || len > buf.len() {
            let _ = platform::ipc::reply(sender, &mochi_user_syscall::EINVAL.to_le_bytes());
            continue;
        }
        let reply = handle_request(
            &mut surfaces,
            &mut next_token,
            &mut next_z,
            &mut pointer_focus,
            &mut keyboard_focus,
            sender,
            &buf[..len],
            display_tid,
            display_width,
            display_height,
            display_stride,
            display_format,
        );
        let _ = platform::ipc::reply(sender, &reply);
    }
}
