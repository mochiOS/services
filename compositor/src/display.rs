use mochi_user_platform as platform;

use crate::protocol::{
    OP_DISPLAY_CLAIM_PRESENT_OWNER, OP_DISPLAY_GET_INFO, PIXEL_FORMAT_XRGB8888, errno_status,
    put_u32, read_u32,
};

pub(crate) fn sleep_one_tick() {
    let _ = mochi_user_syscall::call1(mochi_user_syscall::SyscallNumber::Sleep, 1);
}

const DISPLAY_SERVICE_NAME: &str = "display.driver";

static mut DISPLAY_REQ_BUF: [u8; 20] = [0; 20];
pub(crate) static mut DISPLAY_REP_BUF: [u8; 32] = [0; 32];
pub(crate) static mut DISPLAY_PRESENT_REQ: [u8; 36] = [0; 36];

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
