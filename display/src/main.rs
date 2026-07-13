#![no_std]
#![no_main]

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
const OP_CLAIM_PRESENT_OWNER: u32 = 3;
const OP_PRESENT_RECT: u32 = 4;
const PIXEL_FORMAT_XRGB8888: u32 = 1;
const FB_VIRT: u64 = 0x0000_6000_0000_0000;
const MAX_DIMENSION: usize = 4096;

fn put_u32(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn errno_status(errno: u64) -> u32 {
    let signed = errno as i64;
    if signed < 0 {
        signed.wrapping_neg() as u32
    } else {
        errno as u32
    }
}

fn read_u32(buf: &[u8], offset: usize) -> Option<u32> {
    let bytes = buf.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

static mut IPC_BUF: [u8; 4128] = [0; 4128];
static mut IPC_REPLY_20: [u8; 20] = [0; 20];
static mut IPC_REPLY_4: [u8; 4] = [0; 4];

fn page_align_up(value: u64) -> Option<u64> {
    value.checked_add(0xfff).map(|v| v & !0xfff)
}

fn map_framebuffer(info: &platform::memory::FramebufferInfo) -> bool {
    let Some(size) = page_align_up(info.size + (info.addr & 0xfff)) else {
        return false;
    };
    platform::memory::map_framebuffer(FB_VIRT, size).is_ok()
}

fn framebuffer_visible_height(info: &platform::memory::FramebufferInfo) -> usize {
    let height = info.height as usize;
    let stride = info.stride as usize;
    let Some(row_bytes) = stride.checked_mul(4) else {
        return height;
    };
    if row_bytes == 0 {
        return height;
    }
    let rows_from_size = info.size as usize / row_bytes;
    if rows_from_size > height && rows_from_size <= MAX_DIMENSION {
        rows_from_size
    } else {
        height
    }
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
        return errno_status(mochi_user_syscall::EINVAL);
    }
    let Some(row_bytes) = (stride as usize).checked_mul(4) else {
        return errno_status(mochi_user_syscall::EINVAL);
    };
    let Some(needed) = row_bytes.checked_mul(height as usize) else {
        return errno_status(mochi_user_syscall::EINVAL);
    };
    if pixels.len() < needed {
        return errno_status(mochi_user_syscall::EINVAL);
    }
    if !map_framebuffer(info) {
        return errno_status(mochi_user_syscall::EIO);
    }
    let dest_width = info.width as usize;
    let dest_height = framebuffer_visible_height(info);
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
        return errno_status(mochi_user_syscall::ERANGE);
    }
    let Some(dest_row_bytes) = dest_stride.checked_mul(4) else {
        return errno_status(mochi_user_syscall::ERANGE);
    };
    let max_rows = info.size as usize / dest_row_bytes;
    if max_rows < dest_height {
        platform::println!(
            "display.driver: framebuffer too small size={} row_bytes={} height={}",
            info.size,
            dest_row_bytes,
            dest_height
        );
        return errno_status(mochi_user_syscall::ERANGE);
    }
    let fb_offset = (info.addr & 0xfff) as usize;
    let fb = (FB_VIRT as usize + fb_offset) as *mut u32;
    let Some(pixels) = pixels.get(..needed) else {
        return errno_status(mochi_user_syscall::EINVAL);
    };
    let copy_width = dest_width.min(width as usize);
    let copy_height = dest_height.min(height as usize);
    let Some(copy_row_bytes) = copy_width.checked_mul(4) else {
        return errno_status(mochi_user_syscall::ERANGE);
    };
    for y in 0..copy_height {
        let Some(src_row) = y.checked_mul(row_bytes) else {
            return errno_status(mochi_user_syscall::ERANGE);
        };
        let Some(dest_row) = y.checked_mul(dest_stride) else {
            return errno_status(mochi_user_syscall::ERANGE);
        };
        let Some(src_end) = src_row.checked_add(copy_row_bytes) else {
            return errno_status(mochi_user_syscall::ERANGE);
        };
        if src_end > pixels.len() {
            return errno_status(mochi_user_syscall::EINVAL);
        }
        unsafe {
            core::ptr::copy_nonoverlapping(
                pixels.as_ptr().add(src_row),
                fb.add(dest_row).cast::<u8>(),
                copy_row_bytes,
            );
        }
    }
    0
}

fn present_pixels_rect(
    info: &platform::memory::FramebufferInfo,
    width: u32,
    height: u32,
    stride: u32,
    format: u32,
    rect_x: u32,
    rect_y: u32,
    rect_width: u32,
    rect_height: u32,
    pixels: &[u8],
) -> u32 {
    if format != PIXEL_FORMAT_XRGB8888
        || width == 0
        || height == 0
        || stride < width
        || rect_width == 0
        || rect_height == 0
    {
        return errno_status(mochi_user_syscall::EINVAL);
    }
    let Some(rect_right) = rect_x.checked_add(rect_width) else {
        return errno_status(mochi_user_syscall::ERANGE);
    };
    let Some(rect_bottom) = rect_y.checked_add(rect_height) else {
        return errno_status(mochi_user_syscall::ERANGE);
    };
    if rect_right > width || rect_bottom > height {
        return errno_status(mochi_user_syscall::EINVAL);
    }
    let Some(row_bytes) = (stride as usize).checked_mul(4) else {
        return errno_status(mochi_user_syscall::EINVAL);
    };
    let Some(needed) = row_bytes.checked_mul(height as usize) else {
        return errno_status(mochi_user_syscall::EINVAL);
    };
    if pixels.len() < needed {
        return errno_status(mochi_user_syscall::EINVAL);
    }
    if !map_framebuffer(info) {
        return errno_status(mochi_user_syscall::EIO);
    }
    let dest_width = info.width as usize;
    let dest_height = framebuffer_visible_height(info);
    let dest_stride = info.stride as usize;
    if dest_width == 0
        || dest_height == 0
        || dest_width > MAX_DIMENSION
        || dest_height > MAX_DIMENSION
        || dest_stride < dest_width
        || dest_stride > MAX_DIMENSION
    {
        return errno_status(mochi_user_syscall::ERANGE);
    }
    let Some(dest_row_bytes) = dest_stride.checked_mul(4) else {
        return errno_status(mochi_user_syscall::ERANGE);
    };
    let max_rows = info.size as usize / dest_row_bytes;
    if max_rows < dest_height {
        return errno_status(mochi_user_syscall::ERANGE);
    }
    let fb_offset = (info.addr & 0xfff) as usize;
    let fb = (FB_VIRT as usize + fb_offset) as *mut u32;
    let copy_right = (rect_right as usize).min(dest_width);
    let copy_bottom = (rect_bottom as usize).min(dest_height);
    let copy_left = rect_x as usize;
    if copy_right <= copy_left || copy_bottom <= rect_y as usize {
        return 0;
    }
    let Some(copy_row_bytes) = copy_right
        .checked_sub(copy_left)
        .and_then(|width| width.checked_mul(4))
    else {
        return errno_status(mochi_user_syscall::ERANGE);
    };
    for y in rect_y as usize..copy_bottom {
        let Some(src_row) = y.checked_mul(row_bytes) else {
            return errno_status(mochi_user_syscall::ERANGE);
        };
        let Some(dest_row) = y.checked_mul(dest_stride) else {
            return errno_status(mochi_user_syscall::ERANGE);
        };
        let Some(src_offset) = src_row.checked_add(copy_left.saturating_mul(4)) else {
            return errno_status(mochi_user_syscall::ERANGE);
        };
        let Some(src_end) = src_offset.checked_add(copy_row_bytes) else {
            return errno_status(mochi_user_syscall::ERANGE);
        };
        if src_end > pixels.len() {
            return errno_status(mochi_user_syscall::EINVAL);
        }
        let Some(dest_offset) = dest_row.checked_add(copy_left) else {
            return errno_status(mochi_user_syscall::ERANGE);
        };
        unsafe {
            core::ptr::copy_nonoverlapping(
                pixels.as_ptr().add(src_offset),
                fb.add(dest_offset).cast::<u8>(),
                copy_row_bytes,
            );
        }
    }
    0
}

fn present_inline(info: &platform::memory::FramebufferInfo, request: &[u8]) -> u32 {
    if request.len() < 20 {
        return errno_status(mochi_user_syscall::EINVAL);
    }
    let Some(width) = read_u32(request, 4) else {
        return errno_status(mochi_user_syscall::EINVAL);
    };
    let Some(height) = read_u32(request, 8) else {
        return errno_status(mochi_user_syscall::EINVAL);
    };
    let Some(stride) = read_u32(request, 12) else {
        return errno_status(mochi_user_syscall::EINVAL);
    };
    let Some(format) = read_u32(request, 16) else {
        return errno_status(mochi_user_syscall::EINVAL);
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
    {
        return errno_status(mochi_user_syscall::EINVAL);
    }
    let Some(row_bytes) = (stride as usize).checked_mul(4) else {
        return errno_status(mochi_user_syscall::EINVAL);
    };
    let Some(needed) = row_bytes.checked_mul(height as usize) else {
        return errno_status(mochi_user_syscall::EINVAL);
    };
    let Ok(total) = usize::try_from(total) else {
        return errno_status(mochi_user_syscall::EINVAL);
    };
    if total < needed {
        return errno_status(mochi_user_syscall::EINVAL);
    }
    let pixels = unsafe { core::slice::from_raw_parts(mapped_addr as *const u8, needed) };
    present_pixels(info, width, height, stride, format, pixels)
}

fn present_shared_rect(
    info: &platform::memory::FramebufferInfo,
    mapped_addr: u64,
    total: u64,
    width: u32,
    height: u32,
    stride: u32,
    format: u32,
    rect_x: u32,
    rect_y: u32,
    rect_width: u32,
    rect_height: u32,
) -> u32 {
    if mapped_addr == 0 {
        return errno_status(mochi_user_syscall::EINVAL);
    }
    let Some(row_bytes) = (stride as usize).checked_mul(4) else {
        return errno_status(mochi_user_syscall::EINVAL);
    };
    let Some(needed) = row_bytes.checked_mul(height as usize) else {
        return errno_status(mochi_user_syscall::EINVAL);
    };
    let Ok(total) = usize::try_from(total) else {
        return errno_status(mochi_user_syscall::EINVAL);
    };
    if total < needed {
        return errno_status(mochi_user_syscall::EINVAL);
    }
    let pixels = unsafe { core::slice::from_raw_parts(mapped_addr as *const u8, needed) };
    present_pixels_rect(
        info,
        width,
        height,
        stride,
        format,
        rect_x,
        rect_y,
        rect_width,
        rect_height,
        pixels,
    )
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
    let mut shared_buffer: Option<(u64, u64, u64)> = None;
    let mut present_owner = 0u64;
    loop {
        let buf = unsafe {
            core::slice::from_raw_parts_mut(core::ptr::addr_of_mut!(IPC_BUF).cast::<u8>(), 4128)
        };
        let Ok(msg) = platform::ipc::wait(endpoint, buf) else {
            platform::thread::yield_now();
            continue;
        };
        let sender = msg >> 32;
        let len = (msg & 0xffff_ffff) as usize;
        if len == 16 {
            if present_owner != 0 && sender != present_owner {
                continue;
            }
            let mapped_addr = u64::from_le_bytes([
                buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
            ]);
            let total = u64::from_le_bytes([
                buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
            ]);
            shared_buffer = Some((sender, mapped_addr, total));
            continue;
        }
        if len < 4 || len > buf.len() {
            let reply = unsafe {
                core::slice::from_raw_parts_mut(
                    core::ptr::addr_of_mut!(IPC_REPLY_4).cast::<u8>(),
                    4,
                )
            };
            put_u32(reply, 0, errno_status(mochi_user_syscall::EINVAL));
            let _ = platform::ipc::reply(sender, reply);
            continue;
        }
        let opcode = read_u32(&buf, 0).unwrap_or(0);
        let info = platform::memory::framebuffer_info().unwrap_or_default();
        match opcode {
            OP_GET_INFO => {
                let reply = unsafe {
                    core::slice::from_raw_parts_mut(
                        core::ptr::addr_of_mut!(IPC_REPLY_20).cast::<u8>(),
                        20,
                    )
                };
                put_u32(reply, 0, 0);
                put_u32(reply, 4, info.width);
                put_u32(reply, 8, framebuffer_visible_height(&info) as u32);
                put_u32(reply, 12, info.stride);
                put_u32(reply, 16, PIXEL_FORMAT_XRGB8888);
                let _ = platform::ipc::reply(sender, reply);
            }
            OP_CLAIM_PRESENT_OWNER => {
                present_owner = sender;
                shared_buffer = None;
                let reply = unsafe {
                    core::slice::from_raw_parts_mut(
                        core::ptr::addr_of_mut!(IPC_REPLY_4).cast::<u8>(),
                        4,
                    )
                };
                put_u32(reply, 0, 0);
                let _ = platform::ipc::reply(sender, reply);
            }
            OP_PRESENT => {
                let status = if present_owner != 0 && sender != present_owner {
                    errno_status(mochi_user_syscall::EACCES)
                } else if len == 20 {
                    let width = read_u32(&buf, 4).unwrap_or(0);
                    let height = read_u32(&buf, 8).unwrap_or(0);
                    let stride = read_u32(&buf, 12).unwrap_or(0);
                    let format = read_u32(&buf, 16).unwrap_or(0);
                    match shared_buffer {
                        Some((buffer_sender, mapped_addr, total)) if buffer_sender == sender => {
                            present_shared(&info, mapped_addr, total, width, height, stride, format)
                        }
                        None => errno_status(mochi_user_syscall::EINVAL),
                        Some(_) => errno_status(mochi_user_syscall::EINVAL),
                    }
                } else {
                    present_inline(&info, &buf[..len])
                };
                if status != 0 && status != errno_status(mochi_user_syscall::EACCES) {
                    platform::println!(
                        "display.driver: present failed status={} fb={}x{} stride={} size={}",
                        status,
                        info.width,
                        framebuffer_visible_height(&info) as u32,
                        info.stride,
                        info.size
                    );
                }
                let reply = unsafe {
                    core::slice::from_raw_parts_mut(
                        core::ptr::addr_of_mut!(IPC_REPLY_4).cast::<u8>(),
                        4,
                    )
                };
                put_u32(reply, 0, status);
                let _ = platform::ipc::reply(sender, reply);
            }
            OP_PRESENT_RECT => {
                let status = if present_owner != 0 && sender != present_owner {
                    errno_status(mochi_user_syscall::EACCES)
                } else if len == 36 {
                    let width = read_u32(&buf, 4).unwrap_or(0);
                    let height = read_u32(&buf, 8).unwrap_or(0);
                    let stride = read_u32(&buf, 12).unwrap_or(0);
                    let format = read_u32(&buf, 16).unwrap_or(0);
                    let rect_x = read_u32(&buf, 20).unwrap_or(0);
                    let rect_y = read_u32(&buf, 24).unwrap_or(0);
                    let rect_width = read_u32(&buf, 28).unwrap_or(0);
                    let rect_height = read_u32(&buf, 32).unwrap_or(0);
                    match shared_buffer {
                        Some((buffer_sender, mapped_addr, total)) if buffer_sender == sender => {
                            present_shared_rect(
                                &info,
                                mapped_addr,
                                total,
                                width,
                                height,
                                stride,
                                format,
                                rect_x,
                                rect_y,
                                rect_width,
                                rect_height,
                            )
                        }
                        None => errno_status(mochi_user_syscall::EINVAL),
                        Some(_) => errno_status(mochi_user_syscall::EINVAL),
                    }
                } else {
                    errno_status(mochi_user_syscall::EINVAL)
                };
                if status != 0 && status != errno_status(mochi_user_syscall::EACCES) {
                    platform::println!(
                        "display.driver: present rect failed status={} fb={}x{} stride={} size={}",
                        status,
                        info.width,
                        framebuffer_visible_height(&info) as u32,
                        info.stride,
                        info.size
                    );
                }
                let reply = unsafe {
                    core::slice::from_raw_parts_mut(
                        core::ptr::addr_of_mut!(IPC_REPLY_4).cast::<u8>(),
                        4,
                    )
                };
                put_u32(reply, 0, status);
                let _ = platform::ipc::reply(sender, reply);
            }
            _ => {
                let reply = unsafe {
                    core::slice::from_raw_parts_mut(
                        core::ptr::addr_of_mut!(IPC_REPLY_4).cast::<u8>(),
                        4,
                    )
                };
                put_u32(reply, 0, errno_status(mochi_user_syscall::EINVAL));
                let _ = platform::ipc::reply(sender, reply);
            }
        }
    }
}
