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

const DISPLAY_SERVICE_NAME: &str = "display";
const INPUT_SERVICE_NAME: &str = "input";
const OP_CREATE_SURFACE: u32 = 1;
const OP_ATTACH_BUFFER: u32 = 2;
const OP_DAMAGE: u32 = 3;
const OP_COMMIT: u32 = 4;
const OP_SET_POSITION: u32 = 5;
const OP_DESTROY_SURFACE: u32 = 6;
const OP_DISPLAY_GET_INFO: u32 = 1;
const OP_DISPLAY_PRESENT: u32 = 2;
const ROLE_TOPLEVEL: u32 = 1;
const ROLE_POPUP: u32 = 2;
const PIXEL_FORMAT_XRGB8888: u32 = 1;
const MAX_SURFACES: usize = 8;
const MAX_SURFACE_W: u32 = 28;
const MAX_SURFACE_H: u32 = 20;
const FRAME_W: usize = 32;
const FRAME_H: usize = 24;
const FRAME_BYTES: usize = FRAME_W * FRAME_H * 4;

#[derive(Clone, Copy)]
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
    pending: [u32; (MAX_SURFACE_W as usize) * (MAX_SURFACE_H as usize)],
    current_width: u32,
    current_height: u32,
    current_stride: u32,
    current: [u32; (MAX_SURFACE_W as usize) * (MAX_SURFACE_H as usize)],
    z: u32,
}

impl Surface {
    const fn empty() -> Self {
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
            pending: [0; (MAX_SURFACE_W as usize) * (MAX_SURFACE_H as usize)],
            current_width: 0,
            current_height: 0,
            current_stride: 0,
            current: [0; (MAX_SURFACE_W as usize) * (MAX_SURFACE_H as usize)],
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

fn composite_and_present(surfaces: &[Surface], display_tid: u64) -> u32 {
    let mut frame = vec![0u32; FRAME_W * FRAME_H];
    for y in 0..FRAME_H {
        for x in 0..FRAME_W {
            let shade = 0x0020_2630u32 + (((x as u32) ^ (y as u32)) & 0x7);
            frame[y * FRAME_W + x] = 0xff00_0000 | shade;
        }
    }
    for surface in surfaces.iter().filter(|s| s.live) {
        for sy in 0..surface.current_height as usize {
            let dy = surface.y + sy as i32;
            if dy < 0 || dy >= FRAME_H as i32 {
                continue;
            }
            for sx in 0..surface.current_width as usize {
                let dx = surface.x + sx as i32;
                if dx < 0 || dx >= FRAME_W as i32 {
                    continue;
                }
                let src = sy * surface.current_stride as usize + sx;
                if src < surface.current.len() {
                    frame[dy as usize * FRAME_W + dx as usize] = surface.current[src];
                }
            }
        }
    }
    let mut request = vec![0u8; 20 + FRAME_BYTES];
    put_u32(&mut request, 0, OP_DISPLAY_PRESENT);
    put_u32(&mut request, 4, FRAME_W as u32);
    put_u32(&mut request, 8, FRAME_H as u32);
    put_u32(&mut request, 12, FRAME_W as u32);
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
    sender: u64,
    request: &[u8],
    display_tid: u64,
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
                || width > MAX_SURFACE_W
                || height > MAX_SURFACE_H
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
            surfaces[index].z = *next_z;
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
                || width > MAX_SURFACE_W
                || height > MAX_SURFACE_H
            {
                put_u32(&mut reply, 0, mochi_user_syscall::EINVAL as u32);
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
            let surface = &mut surfaces[index];
            surface.pending_width = width;
            surface.pending_height = height;
            surface.pending_stride = stride;
            surface.pending_len = width as usize * height as usize;
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
            if surface_index_for(surfaces, sender, token).is_some() {
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
            let surface = &mut surfaces[index];
            if surface.pending_width == 0 || surface.pending_len == 0 {
                put_u32(&mut reply, 0, mochi_user_syscall::EINVAL as u32);
                return reply;
            }
            surface.current_width = surface.pending_width;
            surface.current_height = surface.pending_height;
            surface.current_stride = surface.pending_width;
            for i in 0..surface.pending_len {
                surface.current[i] = surface.pending[i];
            }
            let status = composite_and_present(surfaces, display_tid);
            put_u32(&mut reply, 0, status);
        }
        OP_SET_POSITION => {
            put_u32(&mut reply, 0, mochi_user_syscall::EACCES as u32);
        }
        OP_DESTROY_SURFACE => {
            let token = read_u64(request, 4).unwrap_or(0);
            if let Some(index) = surface_index_for(surfaces, sender, token) {
                surfaces[index] = Surface::empty();
                let status = composite_and_present(surfaces, display_tid);
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
    let mut info_req = [0u8; 4];
    put_u32(&mut info_req, 0, OP_DISPLAY_GET_INFO);
    let mut info_reply = [0u8; 32];
    let _ = platform::ipc::call(display_tid, &info_req, &mut info_reply);

    let mut surfaces: Vec<Surface> = vec![Surface::empty(); MAX_SURFACES];
    let mut next_token = 0x434f_4d50_5355_5246u64;
    let mut next_z = 0u32;
    let mut buf = vec![0u8; 4128];
    loop {
        let Ok(msg) = platform::ipc::wait(endpoint, &mut buf) else {
            platform::thread::yield_now();
            continue;
        };
        let sender = msg >> 32;
        let len = (msg & 0xffff_ffff) as usize;
        if len == core::mem::size_of::<platform::input::InputEvent>() {
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
            sender,
            &buf[..len],
            display_tid,
        );
        let _ = platform::ipc::reply(sender, &reply);
    }
}
