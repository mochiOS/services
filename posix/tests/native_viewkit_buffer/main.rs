use mochi_user_platform as platform;
use mochi_user_platform::{ipc, memory_object, syscall};
use tiny_skia::Pixmap;

#[path = "../../../../libraries/viewkit/src/platform/mochios/buffer.rs"]
mod buffer;
#[path = "../../../linux/src/compositor_buffer.rs"]
mod linux_buffer;

#[derive(Debug)]
enum CompositorError {
    Unavailable,
    InvalidSize,
}

const PAGE_SIZE: usize = 4096;
const PIXEL_FORMAT_ARGB8888_PREMULTIPLIED: u32 = 2;

#[derive(Debug)]
enum MochiOsBackendError {
    ArithmeticOverflow,
    InvalidWindowSize,
    InvalidReply,
    Syscall(u64),
}

#[derive(Clone, Copy)]
struct Color {
    red: u8,
    green: u8,
    blue: u8,
}

mod connection {
    pub(super) fn syscall_result<T>(
        result: super::syscall::SysResult<T>,
    ) -> Result<T, super::MochiOsBackendError> {
        result.map_err(|error| super::MochiOsBackendError::Syscall(error.errno().unwrap_or(5)))
    }
}

fn rpc(endpoint: u64, request: &[u8]) -> Result<[u8; 16], String> {
    let mut reply = [0; 16];
    let message =
        ipc::call(endpoint, request, &mut reply).map_err(|error| format!("rpc {error:?}"))?;
    let status = u32::from_le_bytes(reply[..4].try_into().unwrap());
    if message as u32 != 16 || status != 0 {
        return Err(format!(
            "opcode={} reply length={} status={status}",
            u32::from_le_bytes(request[..4].try_into().unwrap()),
            message as u32
        ));
    }
    Ok(reply)
}

fn probe() -> Result<u64, String> {
    let _ = mochi_user_platform::logger::init_from_env();
    let target = mochi_user_platform::service_ready::take_bootstrap_target()
        .ok_or("missing ready target")?;
    let endpoint = ipc::create().map_err(|error| format!("endpoint {error:?}"))?;
    mochi_user_platform::service_ready::notify(target, 0)
        .map_err(|error| format!("ready {error:?}"))?;
    let mut request = [0; 32];
    let message =
        ipc::wait(endpoint, &mut request).map_err(|error| format!("subscribe {error:?}"))?;
    if message as u32 != 16 || request[..4] != 0x53554253u32.to_le_bytes() {
        return Err("unexpected subscription".into());
    }
    let compositor = message >> 32;
    ipc::reply(compositor, &[38]).map_err(|error| format!("reject input {error:?}"))?;
    rpc(compositor, &9u32.to_le_bytes())?;
    let mut create = [0u8; 24];
    create[..4].copy_from_slice(&1u32.to_le_bytes());
    create[4..8].copy_from_slice(&1u32.to_le_bytes());
    create[8..12].copy_from_slice(&16u32.to_le_bytes());
    create[12..16].copy_from_slice(&16u32.to_le_bytes());
    create[16..24].copy_from_slice(&endpoint.to_le_bytes());
    let reply = rpc(compositor, &create)?;
    let token = &reply[4..12];
    for color in [0xff203040u32, 0xff607080u32] {
        let mut attach = [0u8; 28];
        attach[..4].copy_from_slice(&2u32.to_le_bytes());
        attach[4..12].copy_from_slice(token);
        for offset in [12, 16, 20] {
            attach[offset..offset + 4].copy_from_slice(&16u32.to_le_bytes());
        }
        // Toplevel surfaces use flattened XRGB, as the production backend does.
        attach[24..28].copy_from_slice(&1u32.to_le_bytes());
        rpc(compositor, &attach)?;
        let mut pixmap = Pixmap::new(16, 16).ok_or("pixmap allocation")?;
        for pixel in pixmap.data_mut().chunks_exact_mut(4) {
            pixel.copy_from_slice(&[(color >> 16) as u8, (color >> 8) as u8, color as u8, 255]);
        }
        let mut shared =
            buffer::SharedBuffer::new(16, 16).map_err(|error| format!("buffer {error:?}"))?;
        shared
            .send_pixmap_to(
                compositor,
                &pixmap,
                Color {
                    red: 0,
                    green: 0,
                    blue: 0,
                },
                buffer::PhysicalDirtyRect {
                    x: 0,
                    y: 0,
                    width: 16,
                    height: 16,
                },
                1,
            )
            .map_err(|error| format!("offer {error:?}"))?;
        // Drop unmaps/closes the actual ViewKit sender before the commit RPC;
        // the receiver's attached object and pending/current guards must suffice.
        drop(shared);
        let mut commit = [0u8; 12];
        commit[..4].copy_from_slice(&4u32.to_le_bytes());
        commit[4..12].copy_from_slice(token);
        rpc(compositor, &commit)?;
    }
    let mut attach = [0u8; 28];
    attach[..4].copy_from_slice(&2u32.to_le_bytes());
    attach[4..12].copy_from_slice(token);
    for offset in [12, 16, 20] {
        attach[offset..offset + 4].copy_from_slice(&16u32.to_le_bytes());
    }
    attach[24..28].copy_from_slice(&1u32.to_le_bytes());
    rpc(compositor, &attach)?;
    let mut linux = linux_buffer::SharedBuffer::allocate(16, 16)
        .map_err(|error| format!("linux buffer {error:?}"))?;
    linux
        .copy_from(&[0x77; 16 * 16 * 4])
        .map_err(|error| format!("linux copy {error:?}"))?;
    linux
        .send_to(compositor)
        .map_err(|error| format!("linux offer {error:?}"))?;
    drop(linux);
    let mut commit = [0u8; 12];
    commit[..4].copy_from_slice(&4u32.to_le_bytes());
    commit[4..12].copy_from_slice(token);
    rpc(compositor, &commit)?;
    let mut destroy = [0u8; 12];
    destroy[..4].copy_from_slice(&6u32.to_le_bytes());
    destroy[4..12].copy_from_slice(token);
    rpc(compositor, &destroy)?;
    Ok(endpoint)
}

fn main() {
    let result = probe();
    let line = format!(
        "viewkit-buffer: {} ViewKit + Linux RAM offers, sender drop, 3 commits, destroy {result:?}\n",
        if result.is_ok() { "PASS" } else { "FAIL" }
    );
    let _ = syscall::call2(
        syscall::SyscallNumber::DebugWrite,
        line.as_ptr() as u64,
        line.len() as u64,
    );
    if result.is_err() {
        std::process::exit(1);
    }
    let endpoint = result.unwrap();
    loop {
        // Stay available as the fixture's input endpoint without depending on
        // an unrelated POSIX timer. Explicitly reject later subscriptions too.
        let mut bytes = [0u8; 32];
        let mut handles = ipc::IpcObjectHandles::default();
        if let Ok(message) = ipc::wait_object_handles(endpoint, &mut bytes, &mut handles) {
            for attached in &handles.handles {
                if attached.handle != 0 {
                    let _ = mochi_user_platform::handle::close(attached.handle);
                }
            }
            if message as u32 == 16 && bytes[..4] == 0x53554253u32.to_le_bytes() {
                let _ = ipc::reply(message >> 32, &[38]);
            }
        }
        mochi_user_platform::thread::yield_now();
    }
}
