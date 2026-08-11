use mochi_user_platform as platform;
use mochios_linux_gui_protocol::{
    LAUNCH_REQUEST_LEN, LAUNCH_RESPONSE_LEN, LaunchRequest, LaunchResponse, MAGIC,
};

use crate::compositor::Surface;
use crate::host::{HostClient, HostError};

const FRAME_INTERVAL_MS: u64 = 100;
const DISCOVERY_INTERVAL_MS: u64 = 25;
const EVENT_BUFFER_LEN: usize = 64;
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
const EBUSY_ERRNO: i32 = 16;

struct ActiveWindow {
    instance: u64,
    host_window: Option<u32>,
    surface: Option<Surface>,
    next_update: u64,
    close_requested: bool,
}

pub(crate) fn run() -> ! {
    platform::println!("linux.service: start");
    let mut host = connect_host();
    let mut active = None;
    let mut next_instance = 1u64;
    let mut event = [0u8; EVENT_BUFFER_LEN];

    loop {
        match platform::ipc::try_wait(&mut event) {
            Ok(raw) => {
                let sender = raw >> 32;
                let length = raw as u32 as usize;
                if is_launch_request(&event, length) {
                    handle_launch(
                        &event[..length],
                        sender,
                        &mut host,
                        &mut active,
                        &mut next_instance,
                    );
                } else if let Some(window) = active.as_mut() {
                    handle_event(&event[..length.min(event.len())], window, &mut host);
                }
            }
            Err(error) if error.raw() == mochi_user_syscall::EAGAIN as i64 => {}
            Err(_) => {}
        }

        if let Some(window) = active.as_mut() {
            update_window(window, &mut host);
        }
        if active.as_ref().is_some_and(|window| window.close_requested) {
            active = None;
        }
        platform::thread::yield_now();
    }
}

fn connect_host() -> HostClient {
    loop {
        if let Ok(host) = HostClient::connect() {
            return host;
        }
        let _ = platform::thread::sleep_milliseconds(250);
    }
}

fn is_launch_request(buffer: &[u8], length: usize) -> bool {
    length == LAUNCH_REQUEST_LEN
        && buffer
            .get(..4)
            .is_some_and(|bytes| bytes == MAGIC.to_le_bytes())
}

fn handle_launch(
    request: &[u8],
    sender: u64,
    host: &mut HostClient,
    active: &mut Option<ActiveWindow>,
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
    } else {
        decoded
            .map_err(|_| -(mochi_user_syscall::EINVAL as i32))
            .and_then(|request| {
                if active.is_some() {
                    return Err(-EBUSY_ERRNO);
                }
                let instance = allocate_instance(next_instance);
                host.launch(instance, request.application.host_name())
                    .map_err(host_status)?;
                *active = Some(ActiveWindow {
                    instance,
                    host_window: None,
                    surface: None,
                    next_update: 0,
                    close_requested: false,
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

fn allocate_instance(next: &mut u64) -> u64 {
    let instance = (*next).max(1);
    *next = instance.wrapping_add(1).max(1);
    instance
}

fn update_window(active: &mut ActiveWindow, host: &mut HostClient) {
    let now = platform::time::ticks().unwrap_or_default();
    if now < active.next_update {
        return;
    }
    active.next_update = now.saturating_add(if active.host_window.is_some() {
        FRAME_INTERVAL_MS
    } else {
        DISCOVERY_INTERVAL_MS
    });

    if active.host_window.is_none() {
        match host.windows(active.instance) {
            Ok(windows) => active.host_window = windows.first().copied(),
            Err(_) => return,
        }
    }
    let Some(window) = active.host_window else {
        return;
    };
    let Ok(info) = host.window_info(active.instance, window) else {
        return;
    };
    let Ok(frame) = host.frame(active.instance, window, &info) else {
        return;
    };
    if active.surface.is_none() {
        active.surface = Surface::create(info.width, info.height).ok();
    }
    if let Some(surface) = active.surface.as_mut() {
        let _ = surface.present(info.width, info.height, &frame);
    }
}

fn handle_event(event: &[u8], active: &mut ActiveWindow, host: &mut HostClient) {
    if event.len() < 16 {
        return;
    }
    let Some(window) = active.host_window else {
        return;
    };
    let kind = read_u32(event, 0);
    let a = read_i32(event, 4);
    let b = read_i32(event, 8);
    let c = read_u32(event, 12);
    match kind {
        EVENT_POINTER_MOTION => {
            let _ = host.input(active.instance, window, "motion", 0, 0, i16(a), i16(b), 0);
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
                active.instance,
                window,
                "button",
                button,
                value,
                i16(a),
                i16(b),
                0,
            );
        }
        EVENT_POINTER_SCROLL => {
            let _ = host.input(active.instance, window, "scroll", 0, b, 0, 0, 0);
        }
        EVENT_KEY => {
            let flags = c & 0xffff;
            let value = if flags & INPUT_FLAG_RELEASE != 0 {
                0
            } else {
                1
            };
            let keycode = u8::try_from(a).unwrap_or_default().saturating_add(8);
            let _ = host.input(
                active.instance,
                window,
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
                active.instance,
                window,
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
                let _ = host.configure(active.instance, window, width, height);
            }
        }
        EVENT_CLOSE_REQUESTED => {
            let _ = host.close(active.instance, window);
            active.host_window = None;
            active.surface = None;
            active.close_requested = true;
        }
        _ => {}
    }
}

fn host_status(error: HostError) -> i32 {
    match error {
        HostError::Rejected => -(mochi_user_syscall::EACCES as i32),
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
