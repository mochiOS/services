#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec;
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

const OP_GET_INFO: u32 = 1;
const OP_PRESENT: u32 = 2;
const PIXEL_FORMAT_XRGB8888: u32 = 1;
const FB_VIRT: u64 = 0x0000_6000_0000_0000;

fn put_u32(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn read_u32(buf: &[u8], offset: usize) -> Option<u32> {
    let bytes = buf.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn page_align_up(value: u64) -> Option<u64> {
    value.checked_add(0xfff).map(|v| v & !0xfff)
}

fn map_framebuffer(info: &platform::memory::FramebufferInfo) -> bool {
    let Some(size) = page_align_up(info.size + (info.addr & 0xfff)) else {
        return false;
    };
    platform::memory::map_framebuffer(FB_VIRT, size).is_ok()
}

fn present(info: &platform::memory::FramebufferInfo, request: &[u8]) -> u32 {
    if request.len() < 20 {
        return mochi_user_syscall::EINVAL as u32;
    }
    let Some(width) = read_u32(request, 4) else {
        return mochi_user_syscall::EINVAL as u32;
    };
    let Some(height) = read_u32(request, 8) else {
        return mochi_user_syscall::EINVAL as u32;
    };
    let Some(stride) = read_u32(request, 12) else {
        return mochi_user_syscall::EINVAL as u32;
    };
    let Some(format) = read_u32(request, 16) else {
        return mochi_user_syscall::EINVAL as u32;
    };
    if format != PIXEL_FORMAT_XRGB8888 || width == 0 || height == 0 || stride < width {
        return mochi_user_syscall::EINVAL as u32;
    }
    if width > info.width || height > info.height {
        return mochi_user_syscall::ERANGE as u32;
    }
    let Some(row_bytes) = (stride as usize).checked_mul(4) else {
        return mochi_user_syscall::EINVAL as u32;
    };
    let Some(needed) = row_bytes.checked_mul(height as usize) else {
        return mochi_user_syscall::EINVAL as u32;
    };
    if request.len() - 20 < needed {
        return mochi_user_syscall::EINVAL as u32;
    }
    if !map_framebuffer(info) {
        return mochi_user_syscall::EIO as u32;
    }
    let dest_stride = if info.stride >= info.width
        && info.stride <= info.width.saturating_add(4096)
        && ((info.stride as usize) * 4) <= info.size as usize
    {
        info.stride
    } else {
        info.width
    };
    let dest_stride = dest_stride as usize;
    let target_width = core::cmp::min(info.width as usize, dest_stride);
    let Some(row_capacity_bytes) = dest_stride.checked_mul(4) else {
        return mochi_user_syscall::ERANGE as u32;
    };
    if target_width == 0 || row_capacity_bytes == 0 {
        return mochi_user_syscall::ERANGE as u32;
    }
    let target_height = core::cmp::min(
        info.height as usize,
        info.size as usize / row_capacity_bytes,
    );
    if target_height == 0 {
        return mochi_user_syscall::ERANGE as u32;
    }
    let target_width = core::cmp::min(target_width, info.size as usize / 4);

    let fb_offset = (info.addr & 0xfff) as usize;
    let fb = (FB_VIRT as usize + fb_offset) as *mut u32;
    let pixels = &request[20..20 + needed];
    for y in 0..target_height {
        let src_y = y * height as usize / target_height;
        let src_row = &pixels[src_y * row_bytes..src_y * row_bytes + stride as usize * 4];
        for x in 0..target_width {
            let src_x = x * width as usize / target_width;
            let i = src_x * 4;
            let pixel =
                u32::from_le_bytes([src_row[i], src_row[i + 1], src_row[i + 2], src_row[i + 3]]);
            unsafe {
                fb.add(y * dest_stride + x).write_volatile(pixel);
            }
        }
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn service_main(sp: *const usize) -> ! {
    unsafe {
        let _ = platform::logger::init_from_initial_stack(sp);
    }
    platform::println!("display.driver: start");
    let endpoint = match platform::ipc::create() {
        Ok(endpoint) => endpoint,
        Err(_) => platform::process::exit(1),
    };
    let mut buf = vec![0u8; 4128];
    loop {
        let Ok(msg) = platform::ipc::wait(endpoint, &mut buf) else {
            platform::thread::yield_now();
            continue;
        };
        let sender = msg >> 32;
        let len = (msg & 0xffff_ffff) as usize;
        if len < 4 || len > buf.len() {
            let _ = platform::ipc::reply(sender, &mochi_user_syscall::EINVAL.to_le_bytes());
            continue;
        }
        let opcode = read_u32(&buf, 0).unwrap_or(0);
        let info = platform::memory::framebuffer_info().unwrap_or_default();
        let mut reply = [0u8; 32];
        match opcode {
            OP_GET_INFO => {
                put_u32(&mut reply, 0, 0);
                put_u32(&mut reply, 4, info.width);
                put_u32(&mut reply, 8, info.height);
                put_u32(&mut reply, 12, info.stride);
                put_u32(&mut reply, 16, PIXEL_FORMAT_XRGB8888);
                let _ = platform::ipc::reply(sender, &reply[..20]);
            }
            OP_PRESENT => {
                let status = present(&info, &buf[..len]);
                let _ = platform::ipc::reply(sender, &status.to_le_bytes());
            }
            _ => {
                let _ = platform::ipc::reply(sender, &mochi_user_syscall::EINVAL.to_le_bytes());
            }
        }
    }
}
