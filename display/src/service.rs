use mochi_user_platform as platform;
use mochi_user_syscall::{EACCES, EINVAL, EIO};

use crate::backend::DisplayBackend;
use crate::present::{DamageRect, PresentFrame};
use crate::protocol::*;

static mut IPC_BUFFER: [u8; 4128] = [0; 4128];
static mut REPLY: [u8; 20] = [0; 20];

pub(crate) fn run() -> ! {
    platform::println!("display.driver: start");
    let Some(ready_target) = platform::service_ready::take_bootstrap_target() else {
        platform::println!("display.driver: missing ready target");
        platform::process::exit(1);
    };
    let mut backend = match DisplayBackend::initialize() {
        Ok(backend) => backend,
        Err(errno) => {
            let _ = platform::service_ready::notify(ready_target, ready_status(errno));
            platform::process::exit(1);
        }
    };
    let endpoint = match platform::ipc::create() {
        Ok(endpoint) => endpoint,
        Err(error) => {
            let _ = platform::service_ready::notify(
                ready_target,
                ready_status(error.errno().unwrap_or(EIO)),
            );
            platform::process::exit(1);
        }
    };
    if platform::service_ready::notify(ready_target, 0).is_err() {
        platform::println!("display.driver: ready notification failed");
        platform::process::exit(1);
    }

    let mut shared_buffer: Option<(u64, u64, u64)> = None;
    let mut present_owner = 0u64;
    loop {
        let buffer = unsafe {
            core::slice::from_raw_parts_mut(core::ptr::addr_of_mut!(IPC_BUFFER).cast::<u8>(), 4128)
        };
        let message = match platform::ipc::wait(endpoint, buffer) {
            Ok(message) => message,
            Err(_) => {
                platform::thread::yield_now();
                continue;
            }
        };
        let sender = message >> 32;
        let length = (message & 0xffff_ffff) as usize;
        if length == 16 {
            if present_owner == 0 || sender == present_owner {
                let address = u64::from_le_bytes([
                    buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5], buffer[6],
                    buffer[7],
                ]);
                let size = u64::from_le_bytes([
                    buffer[8], buffer[9], buffer[10], buffer[11], buffer[12], buffer[13],
                    buffer[14], buffer[15],
                ]);
                shared_buffer = Some((sender, address, size));
            }
            continue;
        }
        if length < 4 || length > buffer.len() {
            reply_status(sender, errno_status(EINVAL));
            continue;
        }
        let request = &buffer[..length];
        match read_u32(request, 0).unwrap_or(0) {
            OP_GET_INFO => reply_info(sender, backend.geometry()),
            OP_CLAIM_PRESENT_OWNER => {
                present_owner = sender;
                shared_buffer = None;
                reply_status(sender, 0);
            }
            OP_PRESENT | OP_PRESENT_RECT => {
                let status = if present_owner != 0 && sender != present_owner {
                    errno_status(EACCES)
                } else {
                    present_request(
                        &mut backend,
                        request,
                        sender,
                        shared_buffer,
                        read_u32(request, 0) == Some(OP_PRESENT_RECT),
                    )
                };
                reply_status(sender, status);
            }
            _ => reply_status(sender, errno_status(EINVAL)),
        }
    }
}

fn present_request(
    backend: &mut DisplayBackend,
    request: &[u8],
    sender: u64,
    shared: Option<(u64, u64, u64)>,
    partial: bool,
) -> u32 {
    let minimum = if partial { 36 } else { 20 };
    if request.len() < minimum {
        return errno_status(EINVAL);
    }
    let Some(geometry) = decode_geometry(request) else {
        return errno_status(EINVAL);
    };
    let damage = if partial {
        match decode_damage(request) {
            Some(damage) => damage,
            None => return errno_status(EINVAL),
        }
    } else {
        DamageRect::full(geometry)
    };
    let required = match geometry.byte_len() {
        Ok(required) => required,
        Err(errno) => return errno_status(errno),
    };
    let pixels = if request.len() > minimum {
        &request[minimum..]
    } else {
        let Some((owner, address, total)) = shared else {
            return errno_status(EINVAL);
        };
        if owner != sender || address == 0 || total < required as u64 {
            return errno_status(EINVAL);
        }
        unsafe { core::slice::from_raw_parts(address as *const u8, required) }
    };
    let frame = PresentFrame {
        geometry,
        pixels,
        damage,
    };
    backend.present(&frame).map_or_else(errno_status, |_| 0)
}

fn reply_info(sender: u64, geometry: crate::present::DisplayGeometry) {
    let reply = reply_buffer(20);
    put_u32(reply, 0, 0);
    put_u32(reply, 4, geometry.width);
    put_u32(reply, 8, geometry.height);
    put_u32(reply, 12, geometry.stride);
    put_u32(reply, 16, geometry.format);
    let _ = platform::ipc::reply(sender, reply);
}

fn reply_status(sender: u64, status: u32) {
    let reply = reply_buffer(4);
    put_u32(reply, 0, status);
    let _ = platform::ipc::reply(sender, reply);
}

fn reply_buffer(length: usize) -> &'static mut [u8] {
    let reply = unsafe {
        core::slice::from_raw_parts_mut(core::ptr::addr_of_mut!(REPLY).cast::<u8>(), length)
    };
    reply.fill(0);
    reply
}

fn ready_status(errno: u64) -> i32 {
    i32::try_from(errno).unwrap_or(i32::MAX)
}
