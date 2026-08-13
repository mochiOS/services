use mochi_user_platform as platform;
use mochios_linux_gui_protocol::{
    BundleLaunchRequest, BundleLaunchResponse, LAUNCH_RESPONSE_LEN, LaunchRequest, LaunchResponse,
    Opcode, STATUS_RESPONSE_LEN, StatusRequest, StatusResponse, decode_opcode,
};

use crate::compositor::Surface;
use crate::host::{HostClient, HostError, decode_frame};
use crate::input::x11_keycode;

const FRAME_INTERVAL_MS: u64 = 100;
const DISCOVERY_INTERVAL_MS: u64 = 25;
const EVENT_BUFFER_LEN: usize = 256;
const MAX_INSTANCES: usize = 16;
const EVENT_POINTER_MOTION: u32 = 4;
const EVENT_POINTER_BUTTON: u32 = 5;
const EVENT_KEY: u32 = 6;
const EVENT_CLOSE_REQUESTED: u32 = 7;
const EVENT_FOCUS_GAINED: u32 = 8;
const EVENT_FOCUS_LOST: u32 = 9;
const EVENT_CONFIGURE: u32 = 11;
const EVENT_POINTER_SCROLL: u32 = 12;
const INPUT_FLAG_PRESS: u32 = 1;
const INPUT_FLAG_RELEASE: u32 = 2;

struct LinuxInstance {
    id: u64,
    windows: Vec<ActiveWindow>,
    next_discovery: u64,
    next_writeback: u64,
    write_grants: Vec<crate::portal::WriteGrant>,
}

struct ActiveWindow {
    host_window: u32,
    surface: Option<Surface>,
    next_update: u64,
    last_generation: u64,
    closing: bool,
    title: String,
    pending_frame: Option<PendingFrame>,
}

struct PendingFrame {
    width: u16,
    height: u16,
    generation: u64,
    frame_size: usize,
    encoded_size: usize,
    encoded: Vec<u8>,
}

pub(crate) fn run() -> ! {
    platform::println!("linux.service: start");
    let mut host = connect_host();
    let mut instances = Vec::new();
    let mut next_instance = 1u64;
    let mut event = [0u8; EVENT_BUFFER_LEN];

    loop {
        match platform::ipc::try_wait(&mut event) {
            Ok(raw) => {
                let sender = raw >> 32;
                let length = raw as u32 as usize;
                let message = &event[..length.min(event.len())];
                match decode_opcode(message) {
                    Ok(Opcode::Launch) => handle_launch(
                        message,
                        sender,
                        &mut host,
                        &mut instances,
                        &mut next_instance,
                    ),
                    Ok(Opcode::LaunchBundle) => handle_bundle_launch(
                        message,
                        sender,
                        &mut host,
                        &mut instances,
                        &mut next_instance,
                    ),
                    Ok(Opcode::Status) => handle_status(message, sender, &instances),
                    Ok(
                        Opcode::LaunchResponse
                        | Opcode::LaunchBundleResponse
                        | Opcode::StatusResponse,
                    ) => {}
                    Err(_) => handle_event(message, &mut instances, &mut host),
                }
            }
            Err(error) if error.raw() == mochi_user_syscall::EAGAIN as i64 => {}
            Err(_) => {}
        }

        let now = platform::time::ticks().unwrap_or_default();
        instances.retain_mut(|instance| update_instance(instance, &mut host, now));
        platform::thread::yield_now();
    }
}

struct BundleSpec {
    bundle_id: String,
    rootfs_path: String,
    rootfs_size: u64,
    rootfs_digest: String,
    entrypoint: String,
    writable_paths: Vec<String>,
    portal_read_paths: Vec<String>,
    portal_write_paths: Vec<String>,
    user: String,
}

fn handle_bundle_launch(
    request: &[u8],
    sender: u64,
    host: &mut HostClient,
    instances: &mut Vec<LinuxInstance>,
    next_instance: &mut u64,
) {
    let decoded = BundleLaunchRequest::decode(request);
    let request_id = decoded.as_ref().map_or(0, BundleLaunchRequest::request_id);
    let authorized = matches!(
        platform::capability::check_thread(sender, "process.spawn"),
        Ok(1)
    );
    let result = if !authorized {
        Err(-(mochi_user_syscall::EPERM as i32))
    } else if instances.len() >= MAX_INSTANCES {
        Err(-(mochi_user_syscall::ENOSPC as i32))
    } else {
        decoded
            .map_err(|_| -(mochi_user_syscall::EINVAL as i32))
            .and_then(|request| load_bundle_spec(request.bundle_id, request.user))
            .and_then(|spec| {
                let instance = allocate_instance(next_instance);
                host.stage_bundle(
                    instance,
                    &spec.bundle_id,
                    &spec.rootfs_path,
                    spec.rootfs_size,
                    &spec.rootfs_digest,
                )
                .map_err(host_status)?;
                let write_grants = crate::portal::prepare(
                    host,
                    instance,
                    &spec.bundle_id,
                    &spec.user,
                    &spec.portal_read_paths,
                    &spec.portal_write_paths,
                )?;
                host.launch_bundle(
                    instance,
                    &spec.bundle_id,
                    &spec.entrypoint,
                    &spec.user,
                    &spec.writable_paths,
                )
                .map_err(host_status)?;
                instances.push(LinuxInstance {
                    id: instance,
                    windows: Vec::new(),
                    next_discovery: 0,
                    next_writeback: 0,
                    write_grants,
                });
                Ok(instance)
            })
    };
    let response = BundleLaunchResponse {
        request_id,
        status: result.as_ref().map_or_else(|status| *status, |_| 0),
        instance: result.unwrap_or_default(),
    };
    let mut encoded = [0u8; LAUNCH_RESPONSE_LEN];
    if response.encode(&mut encoded).is_ok() {
        let _ = platform::ipc::reply(sender, &encoded);
    }
}

fn load_bundle_spec(bundle_id: &str, user: &str) -> Result<BundleSpec, i32> {
    let manifest_path = format!("/system/packages/{bundle_id}/manifest.toml");
    let manifest = platform::package::read_manifest(&manifest_path)
        .ok_or(-(mochi_user_syscall::ENOENT as i32))?;
    if manifest.package_id != bundle_id
        || manifest.package_kind.as_deref() != Some("application")
        || manifest.package_architecture.as_deref() != Some("x86_64")
        || manifest.package_abi.as_deref() != Some("mboot-linux-1")
    {
        return Err(-(mochi_user_syscall::EINVAL as i32));
    }
    let linux = manifest.linux.ok_or(-(mochi_user_syscall::EINVAL as i32))?;
    let rootfs = manifest
        .files
        .iter()
        .find(|file| file.id == linux.rootfs_file)
        .ok_or(-(mochi_user_syscall::EINVAL as i32))?;
    let relative = rootfs
        .path
        .strip_prefix("$/")
        .ok_or(-(mochi_user_syscall::EINVAL as i32))?;
    let digest = rootfs
        .digest
        .strip_prefix("sha256:")
        .filter(|digest| digest.len() == 64)
        .ok_or(-(mochi_user_syscall::EINVAL as i32))?;
    Ok(BundleSpec {
        bundle_id: bundle_id.to_string(),
        rootfs_path: format!("/applications/{}.app/{}", manifest.package_name, relative),
        rootfs_size: rootfs.size,
        rootfs_digest: digest.to_string(),
        entrypoint: linux.entrypoint,
        writable_paths: linux.writable_paths,
        portal_read_paths: linux.portal_read_paths,
        portal_write_paths: linux.portal_write_paths,
        user: user.to_string(),
    })
}

fn connect_host() -> HostClient {
    loop {
        if let Ok(host) = HostClient::connect() {
            return host;
        }
        let _ = platform::thread::sleep_milliseconds(250);
    }
}

fn handle_launch(
    request: &[u8],
    sender: u64,
    host: &mut HostClient,
    instances: &mut Vec<LinuxInstance>,
    next_instance: &mut u64,
) {
    let decoded = LaunchRequest::decode(request);
    let request_id = decoded.as_ref().map_or(0, LaunchRequest::request_id);
    let authorized = matches!(
        platform::capability::check_thread(sender, "process.spawn"),
        Ok(1)
    );
    let result = if !authorized {
        Err(-(mochi_user_syscall::EPERM as i32))
    } else if instances.len() >= MAX_INSTANCES {
        Err(-(mochi_user_syscall::ENOSPC as i32))
    } else {
        decoded
            .map_err(|_| -(mochi_user_syscall::EINVAL as i32))
            .and_then(|request| {
                let instance = allocate_instance(next_instance);
                host.launch(instance, request.application.host_name())
                    .map_err(host_status)?;
                instances.push(LinuxInstance {
                    id: instance,
                    windows: Vec::new(),
                    next_discovery: 0,
                    next_writeback: 0,
                    write_grants: Vec::new(),
                });
                Ok(instance)
            })
    };
    let response = LaunchResponse {
        request_id,
        status: result.as_ref().map_or_else(|status| *status, |_| 0),
        instance: result.unwrap_or_default(),
    };
    let mut encoded = [0u8; LAUNCH_RESPONSE_LEN];
    if response.encode(&mut encoded).is_ok() {
        let _ = platform::ipc::reply(sender, &encoded);
    }
}

fn handle_status(request: &[u8], sender: u64, instances: &[LinuxInstance]) {
    let decoded = StatusRequest::decode(request);
    let request_id = decoded.as_ref().map_or(0, StatusRequest::request_id);
    let authorized = matches!(
        platform::capability::check_thread(sender, "process.inspect"),
        Ok(1)
    );
    let (status, instance, running) = if !authorized {
        (-(mochi_user_syscall::EPERM as i32), 0, false)
    } else {
        match decoded {
            Ok(request) => (
                0,
                request.instance,
                instances
                    .iter()
                    .any(|instance| instance.id == request.instance),
            ),
            Err(_) => (-(mochi_user_syscall::EINVAL as i32), 0, false),
        }
    };
    let response = StatusResponse {
        request_id,
        status,
        running,
        instance,
    };
    let mut encoded = [0u8; STATUS_RESPONSE_LEN];
    if response.encode(&mut encoded).is_ok() {
        let _ = platform::ipc::reply(sender, &encoded);
    }
}

fn allocate_instance(next: &mut u64) -> u64 {
    let instance = (*next).max(1);
    *next = instance.wrapping_add(1).max(1);
    instance
}

fn update_instance(instance: &mut LinuxInstance, host: &mut HostClient, now: u64) -> bool {
    if now >= instance.next_discovery {
        instance.next_discovery = now.saturating_add(DISCOVERY_INTERVAL_MS);
        let host_windows = match host.windows(instance.id) {
            Ok(windows) => windows,
            Err(HostError::Rejected(mboot_protocol::ErrorCode::InvalidState)) => {
                if now < instance.next_writeback {
                    return true;
                }
                instance.next_writeback = now.saturating_add(1_000);
                return crate::portal::write_back(host, instance.id, &instance.write_grants)
                    .is_err();
            }
            Err(_) => return true,
        };
        instance
            .windows
            .retain(|window| host_windows.contains(&window.host_window));
        for host_window in host_windows {
            if !instance
                .windows
                .iter()
                .any(|window| window.host_window == host_window)
            {
                instance.windows.push(ActiveWindow {
                    host_window,
                    surface: None,
                    next_update: 0,
                    last_generation: 0,
                    closing: false,
                    title: String::new(),
                    pending_frame: None,
                });
            }
        }
    }

    for window in &mut instance.windows {
        update_window(instance.id, window, host, now);
    }
    true
}

fn update_window(instance: u64, active: &mut ActiveWindow, host: &mut HostClient, now: u64) {
    if active.closing {
        return;
    }
    if active.pending_frame.is_some() {
        advance_pending_frame(instance, active, host, now);
        return;
    }
    if now < active.next_update {
        return;
    }
    active.next_update = now.saturating_add(FRAME_INTERVAL_MS);
    let Ok(info) = host.window_info(instance, active.host_window) else {
        return;
    };
    if active.surface.is_none() {
        active.surface = Surface::create(info.width, info.height).ok();
    }
    if active.title != info.title {
        if let Some(surface) = active.surface.as_ref() {
            let _ = surface.set_title(&info.title);
        }
        active.title = info.title.clone();
    }
    if info.generation == active.last_generation {
        return;
    }
    let mut encoded = Vec::new();
    if info.encoded_size == 0 || encoded.try_reserve_exact(info.encoded_size).is_err() {
        return;
    }
    active.pending_frame = Some(PendingFrame {
        width: info.width,
        height: info.height,
        generation: info.generation,
        frame_size: info.frame_size,
        encoded_size: info.encoded_size,
        encoded,
    });
    advance_pending_frame(instance, active, host, now);
}

fn advance_pending_frame(
    instance: u64,
    active: &mut ActiveWindow,
    host: &mut HostClient,
    now: u64,
) {
    let Some(pending) = active.pending_frame.as_mut() else {
        return;
    };
    let offset = pending.encoded.len();
    let Ok(chunk) = host.frame_chunk(instance, active.host_window, pending.generation, offset)
    else {
        active.pending_frame = None;
        active.next_update = now.saturating_add(FRAME_INTERVAL_MS);
        return;
    };
    if chunk.total != pending.encoded_size
        || offset.saturating_add(chunk.bytes.len()) > pending.encoded_size
    {
        active.pending_frame = None;
        return;
    }
    pending.encoded.extend_from_slice(&chunk.bytes);
    if pending.encoded.len() != pending.encoded_size {
        return;
    }

    let Some(pending) = active.pending_frame.take() else {
        return;
    };
    let Ok(frame) = decode_frame(&pending.encoded, pending.frame_size) else {
        return;
    };
    if let Some(surface) = active.surface.as_mut()
        && surface
            .present(pending.width, pending.height, &frame)
            .is_ok()
    {
        active.last_generation = pending.generation;
    }
}

fn handle_event(event: &[u8], instances: &mut [LinuxInstance], host: &mut HostClient) {
    if event.len() < 24 {
        return;
    }
    let surface_token = read_u64(event, 16);
    let Some((instance, active)) = instances.iter_mut().find_map(|instance| {
        instance
            .windows
            .iter_mut()
            .find(|window| {
                window
                    .surface
                    .as_ref()
                    .is_some_and(|surface| surface.token() == surface_token)
            })
            .map(|window| (instance.id, window))
    }) else {
        return;
    };
    let kind = read_u32(event, 0);
    let a = read_i32(event, 4);
    let b = read_i32(event, 8);
    let c = read_u32(event, 12);
    match kind {
        EVENT_POINTER_MOTION => {
            let _ = host.input(
                instance,
                active.host_window,
                "motion",
                0,
                0,
                i16(a),
                i16(b),
                0,
            );
        }
        EVENT_POINTER_BUTTON => {
            let mochi_button = (c & 0xffff) as u8;
            let button = match mochi_button {
                2 => 3,
                3 => 2,
                value => value,
            };
            let flags = c >> 16;
            let value = if flags & INPUT_FLAG_RELEASE != 0 {
                0
            } else if flags & INPUT_FLAG_PRESS != 0 {
                1
            } else {
                return;
            };
            let _ = host.input(
                instance,
                active.host_window,
                "button",
                button,
                value,
                i16(a),
                i16(b),
                0,
            );
        }
        EVENT_POINTER_SCROLL => {
            let _ = host.input(instance, active.host_window, "scroll", 0, b, 0, 0, 0);
        }
        EVENT_KEY => {
            let flags = c & 0xffff;
            let value = if flags & INPUT_FLAG_RELEASE != 0 {
                0
            } else {
                1
            };
            let Ok(key) = u16::try_from(a) else {
                return;
            };
            let Some(keycode) = x11_keycode(key) else {
                return;
            };
            let _ = host.input(
                instance,
                active.host_window,
                "key",
                keycode,
                value,
                0,
                0,
                c >> 16,
            );
        }
        EVENT_FOCUS_GAINED | EVENT_FOCUS_LOST => {
            let _ = host.input(
                instance,
                active.host_window,
                "focus",
                0,
                if kind == EVENT_FOCUS_GAINED { 1 } else { 0 },
                0,
                0,
                0,
            );
        }
        EVENT_CONFIGURE => {
            if let (Ok(width), Ok(height)) = (u16::try_from(a), u16::try_from(b)) {
                let _ = host.configure(instance, active.host_window, width, height);
                active.next_update = 0;
            }
        }
        EVENT_CLOSE_REQUESTED => {
            let _ = host.close(instance, active.host_window);
            active.surface = None;
            active.closing = true;
        }
        _ => {}
    }
}

fn host_status(error: HostError) -> i32 {
    match error {
        HostError::Rejected(mboot_protocol::ErrorCode::PermissionDenied) => {
            -(mochi_user_syscall::EACCES as i32)
        }
        HostError::Rejected(mboot_protocol::ErrorCode::Busy) => -16,
        HostError::Rejected(_) => -(mochi_user_syscall::EINVAL as i32),
        HostError::Unavailable => -(mochi_user_syscall::EAGAIN as i32),
        HostError::InvalidReply => -(mochi_user_syscall::EIO as i32),
    }
}

fn i16(value: i32) -> i16 {
    value.clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16
}

fn read_u32(buffer: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        buffer[offset],
        buffer[offset + 1],
        buffer[offset + 2],
        buffer[offset + 3],
    ])
}

fn read_i32(buffer: &[u8], offset: usize) -> i32 {
    i32::from_le_bytes([
        buffer[offset],
        buffer[offset + 1],
        buffer[offset + 2],
        buffer[offset + 3],
    ])
}

fn read_u64(buffer: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        buffer[offset],
        buffer[offset + 1],
        buffer[offset + 2],
        buffer[offset + 3],
        buffer[offset + 4],
        buffer[offset + 5],
        buffer[offset + 6],
        buffer[offset + 7],
    ])
}
