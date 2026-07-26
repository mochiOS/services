use mochi_user_platform as platform;
use mochi_user_syscall::{EACCES, EINVAL, EIO};

use crate::backend::{DisplayBackend, PendingPresent};
use crate::present::{DamageRect, PanelFrame, PresentFrame};
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
    let mut present_error = None;
    let mut gpu_panel_logged = false;
    let mut gpu_scene_logged = false;
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
            OP_GET_RENDERER_CAPS => reply_caps(sender, backend.renderer_caps()),
            OP_CLAIM_PRESENT_OWNER => {
                present_owner = sender;
                present_error = None;
                shared_buffer = None;
                reply_status(sender, 0);
            }
            OP_PRESENT | OP_PRESENT_RECT => {
                if present_owner != 0 && sender != present_owner {
                    reply_status(sender, errno_status(EACCES));
                    continue;
                }
                if let Some(errno) = present_error.take() {
                    reply_status(sender, errno_status(errno));
                    continue;
                }
                match prepare_present_request(
                    &mut backend,
                    request,
                    sender,
                    shared_buffer,
                    read_u32(request, 0) == Some(OP_PRESENT_RECT),
                ) {
                    Ok(pending) => {
                        reply_status(sender, 0);
                        if let Some(pending) = pending
                            && let Err(errno) = backend.finish_present(pending)
                        {
                            platform::println!(
                                "display.driver: deferred present failed errno={}",
                                errno
                            );
                            present_error = Some(errno);
                        }
                    }
                    Err(status) => reply_status(sender, status),
                }
            }
            OP_PRESENT_GPU_PANEL => {
                if present_owner != 0 && sender != present_owner {
                    reply_status(sender, errno_status(EACCES));
                    continue;
                }
                let status =
                    present_gpu_panel_request(&mut backend, request, sender, shared_buffer);
                if status == 0 && !gpu_panel_logged {
                    platform::println!("display.driver: virgl panel composition enabled");
                    gpu_panel_logged = true;
                } else if status != 0 && !gpu_panel_logged {
                    platform::println!(
                        "display.driver: virgl panel composition failed status={}",
                        status
                    );
                    gpu_panel_logged = true;
                }
                reply_status(sender, status);
            }
            OP_PRESENT_GPU_SCENE => {
                if present_owner != 0 && sender != present_owner {
                    reply_status(sender, errno_status(EACCES));
                    continue;
                }
                let status =
                    present_gpu_scene_request(&mut backend, request, sender, shared_buffer);
                if status == 0 && !gpu_scene_logged {
                    platform::println!("display.driver: ViewKit GPU rendering enabled");
                    gpu_scene_logged = true;
                } else if status != 0 && !gpu_scene_logged {
                    platform::println!(
                        "display.driver: ViewKit GPU rendering failed status={}",
                        status
                    );
                    gpu_scene_logged = true;
                }
                reply_status(sender, status);
            }
            OP_SET_CURSOR_IMAGE => {
                let status = if present_owner == 0 || sender != present_owner {
                    errno_status(EACCES)
                } else {
                    set_cursor_image(&mut backend, request)
                };
                if status == 0 {
                    platform::println!("display.driver: hardware cursor enabled");
                } else {
                    platform::println!(
                        "display.driver: hardware cursor image failed status={} width={} height={} hotspot=({}, {}) bytes={}",
                        status,
                        read_u32(request, 4).unwrap_or(0),
                        read_u32(request, 8).unwrap_or(0),
                        read_u32(request, 12).unwrap_or(u32::MAX),
                        read_u32(request, 16).unwrap_or(u32::MAX),
                        request.len().saturating_sub(20)
                    );
                }
                reply_status(sender, status);
            }
            OP_SET_CURSOR_POSITION => {
                let status = if present_owner == 0 || sender != present_owner {
                    errno_status(EACCES)
                } else {
                    set_cursor_position(&mut backend, request)
                };
                reply_status(sender, status);
            }
            _ => reply_status(sender, errno_status(EINVAL)),
        }
    }
}

fn present_gpu_panel_request(
    backend: &mut DisplayBackend,
    request: &[u8],
    sender: u64,
    shared: Option<(u64, u64, u64)>,
) -> u32 {
    if request.len() != 40 {
        return errno_status(EINVAL);
    }
    let Some(geometry) = decode_geometry(request) else {
        return errno_status(EINVAL);
    };
    let Some(damage) = decode_damage(request) else {
        return errno_status(EINVAL);
    };
    let required = match geometry.panel_byte_len() {
        Ok(required) => required,
        Err(errno) => return errno_status(errno),
    };
    let Some((owner, address, total)) = shared else {
        return errno_status(EINVAL);
    };
    if owner != sender || address == 0 || total < required as u64 {
        return errno_status(EINVAL);
    }
    let pixels = unsafe { core::slice::from_raw_parts(address as *const u8, required) };
    let frame = PanelFrame {
        geometry,
        pixels,
        damage,
        background: read_u32(request, 36).unwrap_or(0),
    };
    backend
        .present_gpu_panel(&frame)
        .map_or_else(errno_status, |_| 0)
}

fn present_gpu_scene_request(
    backend: &mut DisplayBackend,
    request: &[u8],
    sender: u64,
    shared: Option<(u64, u64, u64)>,
) -> u32 {
    if request.len() != 8 {
        return errno_status(EINVAL);
    }
    let byte_len = read_u32(request, 4).unwrap_or(0) as usize;
    let Some((owner, address, total)) = shared else {
        return errno_status(EINVAL);
    };
    if owner != sender || address == 0 || byte_len == 0 || total < byte_len as u64 {
        return errno_status(EINVAL);
    }
    let bytes = unsafe { core::slice::from_raw_parts(address as *const u8, byte_len) };
    let Ok(scene) = mochios_viewkit_gpu_protocol::decode(bytes) else {
        return errno_status(EINVAL);
    };
    backend
        .present_gpu_scene(&scene)
        .map_or_else(errno_status, |_| 0)
}

fn set_cursor_image(backend: &mut DisplayBackend, request: &[u8]) -> u32 {
    if request.len() < 20 {
        return errno_status(EINVAL);
    }
    let width = read_u32(request, 4).unwrap_or(0);
    let height = read_u32(request, 8).unwrap_or(0);
    let hotspot_x = read_u32(request, 12).unwrap_or(u32::MAX);
    let hotspot_y = read_u32(request, 16).unwrap_or(u32::MAX);
    let expected = (width as usize)
        .checked_mul(height as usize)
        .and_then(|pixels| pixels.checked_mul(4))
        .and_then(|bytes| bytes.checked_add(20));
    if expected != Some(request.len()) {
        return errno_status(EINVAL);
    }
    backend
        .set_cursor_image(width, height, hotspot_x, hotspot_y, &request[20..])
        .map_or_else(errno_status, |_| 0)
}

fn set_cursor_position(backend: &mut DisplayBackend, request: &[u8]) -> u32 {
    if request.len() != 16 {
        return errno_status(EINVAL);
    }
    let visible = read_u32(request, 12).unwrap_or(2);
    if visible > 1 {
        return errno_status(EINVAL);
    }
    backend
        .set_cursor_position(
            read_u32(request, 4).unwrap_or(0),
            read_u32(request, 8).unwrap_or(0),
            visible == 1,
        )
        .map_or_else(errno_status, |_| 0)
}

fn prepare_present_request(
    backend: &mut DisplayBackend,
    request: &[u8],
    sender: u64,
    shared: Option<(u64, u64, u64)>,
    partial: bool,
) -> Result<Option<PendingPresent>, u32> {
    let minimum = if partial { 36 } else { 20 };
    if request.len() < minimum {
        return Err(errno_status(EINVAL));
    }
    let Some(geometry) = decode_geometry(request) else {
        return Err(errno_status(EINVAL));
    };
    let damage = if partial {
        match decode_damage(request) {
            Some(damage) => damage,
            None => return Err(errno_status(EINVAL)),
        }
    } else {
        DamageRect::full(geometry)
    };
    let required = match geometry.byte_len() {
        Ok(required) => required,
        Err(errno) => return Err(errno_status(errno)),
    };
    let pixels = if request.len() > minimum {
        &request[minimum..]
    } else {
        let Some((owner, address, total)) = shared else {
            return Err(errno_status(EINVAL));
        };
        if owner != sender || address == 0 || total < required as u64 {
            return Err(errno_status(EINVAL));
        }
        unsafe { core::slice::from_raw_parts(address as *const u8, required) }
    };
    let frame = PresentFrame {
        geometry,
        pixels,
        damage,
    };
    backend.prepare_present(&frame).map_err(errno_status)
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

fn reply_caps(sender: u64, caps: u32) {
    let reply = reply_buffer(8);
    put_u32(reply, 0, 0);
    put_u32(reply, 4, caps);
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
