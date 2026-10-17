use mochi_user_platform as platform;
use mochi_user_platform::{ipc, memory_object, syscall};
use tiny_skia::Pixmap;

#[path = "../../../mboot-agent/src/stage_mapping.rs"]
mod agent_stage_mapping;
#[path = "../../../../applications/binder/src/platform/mochios/decoration_buffer.rs"]
mod binder_decoration_buffer;
#[path = "../../../../binaries/coreutils/src/gui_buffer.rs"]
mod coreutils_gui_buffer;
#[derive(Debug)]
struct DecorationError(u64);
#[path = "../../../../libraries/viewkit/src/platform/mochios/buffer.rs"]
mod buffer;
#[path = "../../../linux/src/compositor_buffer.rs"]
mod linux_buffer;
#[path = "../../../linux/src/stage_buffer.rs"]
mod linux_stage_buffer;
type HostError = CompositorError;

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
    // This numeric value is deliberately not an ABI enum entry or reservation.
    // A removed operation must take the generic unknown-syscall path.
    for mut unknown in [548u64, 549, 550] {
        unsafe {
            core::arch::asm!("syscall", inout("rax") unknown, in("rdi") 0u64,
            in("rsi") u64::MAX, in("rdx") 1u64, in("r10") 0u64,
            lateout("rcx") _, lateout("r11") _, options(nostack));
        }
        if unknown != syscall::NativeError::Unsupported.into_raw() {
            return Err(format!("removed syscall returned {unknown:#x}"));
        }
    }
    let stage_endpoint = ipc::create().map_err(|error| format!("stage endpoint {error:?}"))?;
    let stage = linux_stage_buffer::SharedStageBuffer::new(stage_endpoint, 4096)
        .map_err(|error| format!("stage source {error:?}"))?;
    unsafe {
        core::ptr::write_volatile(stage.address as *mut u8, 0x71);
    }
    drop(stage);
    let mut wire = [0u8; 32];
    let mut attached = agent_stage_mapping::Attachments::default();
    let delivered = ipc::wait_object_handles(stage_endpoint, &mut wire, &mut attached.handles)
        .map_err(|error| format!("stage receive {error:?}"))?;
    if delivered as u32 != 32 {
        return Err("stage offer length".into());
    }
    let sender = delivered >> 32;
    let mapping =
        agent_stage_mapping::SharedStageMapping::receive(sender, true, &wire, &mut attached, 4096)
            .map_err(|error| format!("stage mapping {error:#x}"))?;
    if mapping
        .snapshot(sender, 1)
        .map_err(|error| format!("stage snapshot {error:#x}"))?
        != [0x71]
    {
        return Err("stage content mismatch".into());
    }
    drop(mapping);
    let decor_endpoint = ipc::create().map_err(|error| format!("decor endpoint {error:?}"))?;
    let mut decor = binder_decoration_buffer::TitleBarBuffer::new(256)
        .map_err(|error| format!("decor allocation {error:?}"))?;
    decor
        .write(&[0xff123456; 256])
        .map_err(|error| format!("decor pixels {error:?}"))?;
    decor
        .offer(decor_endpoint)
        .map_err(|error| format!("decor offer {error:?}"))?;
    drop(decor);
    let mut decor_wire = [0u8; 32];
    let mut decor_attached = agent_stage_mapping::Attachments::default();
    let delivered =
        ipc::wait_object_handles(decor_endpoint, &mut decor_wire, &mut decor_attached.handles)
            .map_err(|error| format!("decor receive {error:?}"))?;
    let owner = delivered >> 32;
    let view = agent_stage_mapping::SharedStageMapping::receive(
        owner,
        true,
        &decor_wire,
        &mut decor_attached,
        4096,
    )
    .map_err(|error| format!("decor mapping {error:#x}"))?;
    if view
        .snapshot(owner, 4)
        .map_err(|error| format!("decor snapshot {error:#x}"))?
        != 0xff123456u32.to_ne_bytes()
    {
        return Err("decor content mismatch".into());
    }
    drop(view);
    let coreutils_endpoint =
        ipc::create().map_err(|error| format!("coreutils endpoint {error:?}"))?;
    let coreutils = coreutils_gui_buffer::GuiBuffer::new(16, 16, |x, y| (y * 16 + x) as u32)
        .map_err(|error| format!("coreutils allocation {error:?}"))?;
    coreutils
        .offer(coreutils_endpoint)
        .map_err(|error| format!("coreutils offer {error:?}"))?;
    drop(coreutils);
    let mut coreutils_wire = [0u8; 32];
    let mut coreutils_attached = agent_stage_mapping::Attachments::default();
    let delivered = ipc::wait_object_handles(
        coreutils_endpoint,
        &mut coreutils_wire,
        &mut coreutils_attached.handles,
    )
    .map_err(|error| format!("coreutils receive {error:?}"))?;
    let owner = delivered >> 32;
    let view = agent_stage_mapping::SharedStageMapping::receive(
        owner,
        true,
        &coreutils_wire,
        &mut coreutils_attached,
        4096,
    )
    .map_err(|error| format!("coreutils mapping {error:#x}"))?;
    let bytes = view
        .snapshot(owner, 1024)
        .map_err(|error| format!("coreutils snapshot {error:#x}"))?;
    if bytes
        .chunks_exact(4)
        .enumerate()
        .any(|(index, bytes)| u32::from_ne_bytes(bytes.try_into().unwrap()) != index as u32)
    {
        return Err("coreutils pixels mismatch".into());
    }
    drop(view);
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
        let mut forged = [0u8; 16];
        forged[..8].copy_from_slice(&0x710000000000u64.to_le_bytes());
        forged[8..].copy_from_slice(&4096u64.to_le_bytes());
        let mut rejected = [0u8; 16];
        ipc::call(compositor, &forged, &mut rejected)
            .map_err(|error| format!("forged address reply {error:?}"))?;
        if u32::from_le_bytes(rejected[..4].try_into().unwrap()) == 0 {
            return Err("raw address offer accepted".into());
        }
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
        "viewkit-buffer: {} removed page ABI, forged address rejection, RAM offers, sender drop, 3 commits, destroy {result:?}\n",
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
