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
const MAX_DIMENSION: usize = 4096;

fn put_u32(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn read_u32(buf: &[u8], offset: usize) -> Option<u32> {
    let bytes = buf.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_pixel(buf: &[u8], offset: usize) -> Option<u32> {
    let bytes = buf.get(offset..offset.checked_add(4)?)?;
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

fn present_pixels(
    info: &platform::memory::FramebufferInfo,
    width: u32,
    height: u32,
    stride: u32,
    format: u32,
    pixels: &[u8],
) -> u32 {
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
    if pixels.len() < needed {
        return mochi_user_syscall::EINVAL as u32;
    }
    if !map_framebuffer(info) {
        return mochi_user_syscall::EIO as u32;
    }
    let dest_width = info.width as usize;
    let dest_height = info.height as usize;
    let dest_stride = info.stride as usize;
    if dest_width == 0
        || dest_height == 0
        || dest_width > MAX_DIMENSION
        || dest_height > MAX_DIMENSION
        || dest_stride < dest_width
        || dest_stride > MAX_DIMENSION
    {
        platform::println!(
            "display.driver: invalid framebuffer geometry width={} height={} stride={} size={}",
            info.width,
            info.height,
            info.stride,
            info.size
        );
        return mochi_user_syscall::ERANGE as u32;
    }
    let Some(dest_row_bytes) = dest_stride.checked_mul(4) else {
        return mochi_user_syscall::ERANGE as u32;
    };
    let max_rows = info.size as usize / dest_row_bytes;
    if max_rows < dest_height {
        platform::println!(
            "display.driver: framebuffer too small size={} row_bytes={} height={}",
            info.size,
            dest_row_bytes,
            dest_height
        );
        return mochi_user_syscall::ERANGE as u32;
    }
    let target_width = dest_width;
    let target_height = dest_height;

    let fb_offset = (info.addr & 0xfff) as usize;
    let fb = (FB_VIRT as usize + fb_offset) as *mut u32;
    let Some(pixels) = pixels.get(..needed) else {
        return mochi_user_syscall::EINVAL as u32;
    };
    for y in 0..target_height {
        let Some(scaled_y) = y.checked_mul(height as usize) else {
            return mochi_user_syscall::ERANGE as u32;
        };
        let src_y = scaled_y / target_height;
        let Some(src_row) = src_y.checked_mul(row_bytes) else {
            return mochi_user_syscall::ERANGE as u32;
        };
        let Some(dest_row) = y.checked_mul(dest_stride) else {
            return mochi_user_syscall::ERANGE as u32;
        };
        for x in 0..target_width {
            let Some(scaled_x) = x.checked_mul(width as usize) else {
                return mochi_user_syscall::ERANGE as u32;
            };
            let src_x = scaled_x / target_width;
            let Some(src_offset) = src_row.checked_add(src_x.saturating_mul(4)) else {
                return mochi_user_syscall::ERANGE as u32;
            };
            let Some(pixel) = read_pixel(pixels, src_offset) else {
                return mochi_user_syscall::EINVAL as u32;
            };
            let Some(dest_offset) = dest_row.checked_add(x) else {
                return mochi_user_syscall::ERANGE as u32;
            };
            unsafe {
                fb.add(dest_offset).write_volatile(pixel);
            }
        }
    }
    0
}

fn present_inline(info: &platform::memory::FramebufferInfo, request: &[u8]) -> u32 {
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
    present_pixels(info, width, height, stride, format, &request[20..])
}

fn present_shared(
    info: &platform::memory::FramebufferInfo,
    mapped_addr: u64,
    total: u64,
    width: u32,
    height: u32,
    stride: u32,
    format: u32,
) -> u32 {
    if mapped_addr == 0
        || format != PIXEL_FORMAT_XRGB8888
        || width == 0
        || height == 0
        || stride < width
        || width > info.width
        || height > info.height
    {
        return mochi_user_syscall::EINVAL as u32;
    }
    let Some(row_bytes) = (stride as usize).checked_mul(4) else {
        return mochi_user_syscall::EINVAL as u32;
    };
    let Some(needed) = row_bytes.checked_mul(height as usize) else {
        return mochi_user_syscall::EINVAL as u32;
    };
    let Ok(total) = usize::try_from(total) else {
        return mochi_user_syscall::EINVAL as u32;
    };
    if total < needed {
        return mochi_user_syscall::EINVAL as u32;
    }
    let pixels = unsafe { core::slice::from_raw_parts(mapped_addr as *const u8, needed) };
    present_pixels(info, width, height, stride, format, pixels)
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
    let mut shared_buffer: Option<(u64, u64)> = None;
    loop {
        let Ok(msg) = platform::ipc::wait(endpoint, &mut buf) else {
            platform::thread::yield_now();
            continue;
        };
        let sender = msg >> 32;
        let len = (msg & 0xffff_ffff) as usize;
        if len == 16 {
            let mapped_addr = u64::from_le_bytes([
                buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
            ]);
            let total = u64::from_le_bytes([
                buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
            ]);
            shared_buffer = Some((mapped_addr, total));
            continue;
        }
        if len < 4 || len > buf.len() {
            let mut reply = vec![0u8; 4];
            put_u32(&mut reply, 0, mochi_user_syscall::EINVAL as u32);
            let _ = platform::ipc::reply(sender, &reply);
            continue;
        }
        let opcode = read_u32(&buf, 0).unwrap_or(0);
        let info = platform::memory::framebuffer_info().unwrap_or_default();
        match opcode {
            OP_GET_INFO => {
                let mut reply = vec![0u8; 20];
                put_u32(&mut reply, 0, 0);
                put_u32(&mut reply, 4, info.width);
                put_u32(&mut reply, 8, info.height);
                put_u32(&mut reply, 12, info.stride);
                put_u32(&mut reply, 16, PIXEL_FORMAT_XRGB8888);
                let _ = platform::ipc::reply(sender, &reply);
            }
            OP_PRESENT => {
                let status = if len == 20 {
                    let width = read_u32(&buf, 4).unwrap_or(0);
                    let height = read_u32(&buf, 8).unwrap_or(0);
                    let stride = read_u32(&buf, 12).unwrap_or(0);
                    let format = read_u32(&buf, 16).unwrap_or(0);
                    match shared_buffer.take() {
                        Some((mapped_addr, total)) => {
                            present_shared(&info, mapped_addr, total, width, height, stride, format)
                        }
                        None => mochi_user_syscall::EINVAL as u32,
                    }
                } else {
                    present_inline(&info, &buf[..len])
                };
                let mut reply = vec![0u8; 4];
                put_u32(&mut reply, 0, status);
                let _ = platform::ipc::reply(sender, &reply);
            }
            _ => {
                let mut reply = vec![0u8; 4];
                put_u32(&mut reply, 0, mochi_user_syscall::EINVAL as u32);
                let _ = platform::ipc::reply(sender, &reply);
            }
        }
    }
}
