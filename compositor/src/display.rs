use mochi_user_platform as platform;

use crate::protocol::{
    OP_DISPLAY_CLAIM_PRESENT_OWNER, OP_DISPLAY_GET_INFO, OP_DISPLAY_PRESENT_GPU_PANEL,
    OP_DISPLAY_SET_CURSOR_IMAGE, OP_DISPLAY_SET_CURSOR_POSITION, PIXEL_FORMAT_XRGB8888,
    errno_status, put_u32, read_u32,
};

pub(crate) fn sleep_one_tick() {
    let _ = mochi_user_syscall::call1(mochi_user_syscall::SyscallNumber::Sleep, 1);
}

const DISPLAY_SERVICE_NAME: &str = "display.driver";

static mut DISPLAY_REQ_BUF: [u8; 20] = [0; 20];
pub(crate) static mut DISPLAY_REP_BUF: [u8; 32] = [0; 32];
pub(crate) static mut DISPLAY_PRESENT_REQ: [u8; 40] = [0; 40];
static mut DISPLAY_CURSOR_REQ: [u8; 4128] = [0; 4128];

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

pub(crate) fn display_request_info(display_tid: u64) -> (u32, u32, u32, u32) {
    let req = unsafe {
        core::slice::from_raw_parts_mut(core::ptr::addr_of_mut!(DISPLAY_REQ_BUF).cast::<u8>(), 20)
    };
    req.fill(0);
    put_u32(req, 0, OP_DISPLAY_GET_INFO);
    let reply = unsafe {
        core::slice::from_raw_parts_mut(core::ptr::addr_of_mut!(DISPLAY_REP_BUF).cast::<u8>(), 32)
    };
    reply.fill(0);
    if let Ok(msg) = platform::ipc::call(display_tid, req, reply) {
        let len = (msg & 0xffff_ffff) as usize;
        if let Some(info) = decode_display_info(&reply[..len.min(reply.len())]) {
            return info;
        }
    }
    (640, 480, 640, PIXEL_FORMAT_XRGB8888)
}

pub(crate) fn display_renderer_caps(display_tid: u64) -> u32 {
    let req = unsafe {
        core::slice::from_raw_parts_mut(core::ptr::addr_of_mut!(DISPLAY_REQ_BUF).cast::<u8>(), 4)
    };
    req.fill(0);
    put_u32(req, 0, crate::protocol::OP_DISPLAY_GET_RENDERER_CAPS);
    let reply = unsafe {
        core::slice::from_raw_parts_mut(core::ptr::addr_of_mut!(DISPLAY_REP_BUF).cast::<u8>(), 32)
    };
    reply.fill(0);
    let Ok(message) = platform::ipc::call(display_tid, req, reply) else {
        return 0;
    };
    let length = (message & 0xffff_ffff) as usize;
    if length < 8 || read_u32(reply, 0) != Some(0) {
        return 0;
    }
    read_u32(reply, 4).unwrap_or(0)
}

pub(crate) fn display_claim_present_owner(display_tid: u64) -> u32 {
    let req = unsafe {
        core::slice::from_raw_parts_mut(core::ptr::addr_of_mut!(DISPLAY_REQ_BUF).cast::<u8>(), 20)
    };
    req.fill(0);
    put_u32(req, 0, OP_DISPLAY_CLAIM_PRESENT_OWNER);
    let reply = unsafe {
        core::slice::from_raw_parts_mut(core::ptr::addr_of_mut!(DISPLAY_REP_BUF).cast::<u8>(), 32)
    };
    reply.fill(0);
    let Ok(msg) = platform::ipc::call(display_tid, req, reply) else {
        return errno_status(mochi_user_syscall::EIO);
    };
    let len = (msg & 0xffff_ffff) as usize;
    if len < 4 {
        return errno_status(mochi_user_syscall::EIO);
    }
    read_u32(reply, 0).unwrap_or(errno_status(mochi_user_syscall::EIO))
}

#[allow(dead_code)]
pub(crate) fn display_set_cursor_image(display_tid: u64, request: &[u8]) -> u32 {
    if request.len() > 4128 || request.len() < 20 {
        return errno_status(mochi_user_syscall::EINVAL);
    }
    let output = unsafe {
        core::slice::from_raw_parts_mut(
            core::ptr::addr_of_mut!(DISPLAY_CURSOR_REQ).cast::<u8>(),
            request.len(),
        )
    };
    output.copy_from_slice(request);
    put_u32(output, 0, OP_DISPLAY_SET_CURSOR_IMAGE);
    display_cursor_request(display_tid, output)
}

pub(crate) fn display_present_gpu_panel(
    display_tid: u64,
    width: u32,
    height: u32,
    damage: crate::geometry::Rect,
    background: u32,
) -> u32 {
    let request = unsafe {
        core::slice::from_raw_parts_mut(
            core::ptr::addr_of_mut!(DISPLAY_PRESENT_REQ).cast::<u8>(),
            40,
        )
    };
    request.fill(0);
    put_u32(request, 0, OP_DISPLAY_PRESENT_GPU_PANEL);
    put_u32(request, 4, width);
    put_u32(request, 8, height);
    put_u32(request, 12, width);
    put_u32(
        request,
        16,
        crate::protocol::PIXEL_FORMAT_ARGB8888_PREMULTIPLIED,
    );
    put_u32(request, 20, damage.x.max(0) as u32);
    put_u32(request, 24, damage.y.max(0) as u32);
    put_u32(request, 28, damage.width);
    put_u32(request, 32, damage.height);
    put_u32(request, 36, background);
    let reply = unsafe {
        core::slice::from_raw_parts_mut(core::ptr::addr_of_mut!(DISPLAY_REP_BUF).cast::<u8>(), 32)
    };
    reply.fill(0);
    let Ok(message) = platform::ipc::call(display_tid, request, reply) else {
        return errno_status(mochi_user_syscall::EIO);
    };
    let length = (message & 0xffff_ffff) as usize;
    if length < 4 {
        return errno_status(mochi_user_syscall::EIO);
    }
    read_u32(reply, 0).unwrap_or(errno_status(mochi_user_syscall::EIO))
}

pub(crate) fn display_present_gpu_scene(display_tid: u64, byte_len: usize) -> u32 {
    let Ok(byte_len) = u32::try_from(byte_len) else {
        return errno_status(mochi_user_syscall::ERANGE);
    };
    let request = unsafe {
        core::slice::from_raw_parts_mut(
            core::ptr::addr_of_mut!(DISPLAY_PRESENT_REQ).cast::<u8>(),
            8,
        )
    };
    request.fill(0);
    put_u32(request, 0, crate::protocol::OP_DISPLAY_PRESENT_GPU_SCENE);
    put_u32(request, 4, byte_len);
    let reply = unsafe {
        core::slice::from_raw_parts_mut(core::ptr::addr_of_mut!(DISPLAY_REP_BUF).cast::<u8>(), 32)
    };
    reply.fill(0);
    let Ok(message) = platform::ipc::call(display_tid, request, reply) else {
        return errno_status(mochi_user_syscall::EIO);
    };
    let length = (message & 0xffff_ffff) as usize;
    if length < 4 {
        return errno_status(mochi_user_syscall::EIO);
    }
    read_u32(reply, 0).unwrap_or(errno_status(mochi_user_syscall::EIO))
}

pub(crate) fn display_set_cursor_position(display_tid: u64, x: i32, y: i32, visible: bool) -> u32 {
    if x < 0 || y < 0 {
        return errno_status(mochi_user_syscall::EINVAL);
    }
    let request = unsafe {
        core::slice::from_raw_parts_mut(
            core::ptr::addr_of_mut!(DISPLAY_CURSOR_REQ).cast::<u8>(),
            16,
        )
    };
    request.fill(0);
    put_u32(request, 0, OP_DISPLAY_SET_CURSOR_POSITION);
    put_u32(request, 4, x as u32);
    put_u32(request, 8, y as u32);
    put_u32(request, 12, u32::from(visible));
    display_cursor_request(display_tid, request)
}

fn display_cursor_request(display_tid: u64, request: &[u8]) -> u32 {
    let reply = unsafe {
        core::slice::from_raw_parts_mut(core::ptr::addr_of_mut!(DISPLAY_REP_BUF).cast::<u8>(), 32)
    };
    reply.fill(0);
    let Ok(msg) = platform::ipc::call(display_tid, request, reply) else {
        return errno_status(mochi_user_syscall::EIO);
    };
    let len = (msg & 0xffff_ffff) as usize;
    if len < 4 {
        return errno_status(mochi_user_syscall::EIO);
    }
    read_u32(reply, 0).unwrap_or(errno_status(mochi_user_syscall::EIO))
}

pub(crate) fn wait_for_service(attempts: usize) -> Option<u64> {
    for _ in 0..attempts {
        if let Ok(tid) = platform::process::find_by_name(DISPLAY_SERVICE_NAME)
            && tid != 0
        {
            return Some(tid);
        }
        sleep_one_tick();
    }
    None
}
