use mochi_user_platform as platform;

use crate::client::{Client, ClientId, cleanup_client, cleanup_dead_clients, client_id_for_sender};
use crate::display::{display_claim_present_owner, display_request_info, wait_for_service};
use crate::geometry::Rect;
use crate::input::{PointerSerial, handle_input_event, subscribe_input_events};
use crate::protocol::*;
use crate::renderer::composite_and_present;
use crate::state::CompositorState;
use crate::surface::{Surface, handle_shared_buffer, send_frame_done};
use crate::window::Window;

pub(crate) const MAX_SURFACES: usize = 16;
pub(crate) const MAX_WINDOWS: usize = 8;
pub(crate) const MAX_CLIENTS: usize = 16;
pub(crate) const PAGE_SIZE: usize = 4096;
pub(crate) const MAX_SHARED_PAGES: usize = 262_144;
pub(crate) const MAX_SHARED_BYTES: usize = MAX_SHARED_PAGES * PAGE_SIZE;
pub(crate) const MAX_SHARED_PIXELS: usize = MAX_SHARED_BYTES / 4;
pub(crate) const MAX_DIMENSION: u32 = 16_384;
const IDLE_CLEANUP_YIELDS: u32 = 64;
static mut TOKEN_RANDOM_BUF: [u8; 8] = [0; 8];
static mut IPC_BUF: [u8; 4128] = [0; 4128];

pub(crate) fn getrandom_u64() -> Option<u64> {
    let bytes = unsafe {
        core::slice::from_raw_parts_mut(core::ptr::addr_of_mut!(TOKEN_RANDOM_BUF).cast::<u8>(), 8)
    };
    let len = match mochi_user_syscall::call3(
        mochi_user_syscall::SyscallNumber::Getrandom,
        bytes.as_mut_ptr() as u64,
        bytes.len() as u64,
        0,
    ) {
        Ok(len) => len,
        Err(err) => {
            platform::println!(
                "compositor.service: getrandom failed errno={}",
                err.errno().unwrap_or(0)
            );
            return None;
        }
    };
    if len == bytes.len() as u64 {
        Some(u64::from_ne_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    } else {
        platform::println!("compositor.service: getrandom short read len={}", len);
        None
    }
}

pub(crate) fn sleep_one_tick() {
    let _ = mochi_user_syscall::call1(mochi_user_syscall::SyscallNumber::Sleep, 1);
}

fn handle_request(
    clients: &mut [Client],
    surfaces: &mut [Surface],
    windows: &mut [Window],
    next_z: &mut u32,
    next_window_index: &mut u32,
    next_window_id: &mut u64,
    _next_pointer_serial: &mut u64,
    pointer_serials: &mut [PointerSerial],
    pointer_focus: &mut Option<usize>,
    keyboard_focus: &mut Option<usize>,
    client: ClientId,
    sender: u64,
    request: &[u8],
    needs_present: &mut bool,
    present_damage: &mut Option<Rect>,
    _display_tid: u64,
    _display_width: u32,
    _display_height: u32,
    _display_stride: u32,
    _display_format: u32,
) -> [u8; 16] {
    let mut reply = [0u8; 16];
    let Some(opcode) = read_u32(request, 0) else {
        put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EINVAL));
        return reply;
    };
    match opcode {
        OP_CREATE_SURFACE | OP_ATTACH_BUFFER | OP_DAMAGE | OP_COMMIT | OP_SET_POSITION
        | OP_DESTROY_SURFACE => {
            return crate::surface::handle_request(
                clients,
                surfaces,
                windows,
                next_z,
                next_window_index,
                next_window_id,
                pointer_focus,
                keyboard_focus,
                client,
                sender,
                request,
                needs_present,
                present_damage,
            );
        }
        OP_DECOR_SUBSCRIBE
        | OP_DECOR_CREATE_SURFACE
        | OP_DECOR_ATTACH
        | OP_DECOR_DETACH
        | OP_DECOR_UPDATE_INSETS
        | OP_DECOR_BEGIN_MOVE
        | OP_DECOR_BEGIN_RESIZE
        | OP_DECOR_MINIMIZE
        | OP_DECOR_TOGGLE_MAXIMIZE
        | OP_DECOR_CLOSE_REQUEST => {
            return crate::decoration::handle_request(
                clients,
                surfaces,
                windows,
                next_z,
                pointer_serials,
                pointer_focus,
                keyboard_focus,
                client,
                sender,
                request,
                needs_present,
            );
        }
        _ => put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EINVAL)),
    }
    reply
}

pub(crate) fn run() -> ! {
    platform::println!("compositor.service: start");
    let endpoint = match platform::ipc::create() {
        Ok(endpoint) => endpoint,
        Err(_) => platform::process::exit(1),
    };
    let Some(display_tid) = wait_for_service(4096) else {
        platform::println!("compositor.service: display.driver not found");
        platform::process::exit(1);
    };
    let input_subscribed = subscribe_input_events(endpoint);
    let claim_status = display_claim_present_owner(display_tid);
    if claim_status != 0 {
        platform::println!(
            "compositor.service: display claim failed status={}",
            claim_status
        );
    }
    let (display_width, display_height, display_stride, display_format) =
        display_request_info(display_tid);

    let mut state = CompositorState::new(
        display_tid,
        display_width,
        display_height,
        display_stride,
        display_format,
        input_subscribed,
    );
    let _ = composite_and_present(
        &state.surfaces,
        &mut state.present_frame,
        state.display_tid,
        state.display_width,
        state.display_height,
        state.display_stride,
        state.display_format,
        None,
    );
    loop {
        let buf = unsafe {
            core::slice::from_raw_parts_mut(core::ptr::addr_of_mut!(IPC_BUF).cast::<u8>(), 4128)
        };
        let msg = match platform::ipc::try_wait(buf) {
            Ok(msg) => {
                state.idle_cleanup_ticks = 0;
                msg
            }
            Err(_) => {
                state.idle_cleanup_ticks = state.idle_cleanup_ticks.wrapping_add(1);
                state.input_subscribe_retry_ticks =
                    state.input_subscribe_retry_ticks.wrapping_add(1);
                if !state.input_subscribed
                    && state.input_subscribe_retry_ticks >= IDLE_CLEANUP_YIELDS
                {
                    state.input_subscribe_retry_ticks = 0;
                    state.input_subscribed = subscribe_input_events(endpoint);
                }
                if state.idle_cleanup_ticks >= IDLE_CLEANUP_YIELDS {
                    state.idle_cleanup_ticks = 0;
                    if cleanup_dead_clients(
                        &mut state.clients,
                        &mut state.surfaces,
                        &mut state.windows,
                        &mut state.pointer_focus,
                        &mut state.keyboard_focus,
                    ) {
                        let _ = composite_and_present(
                            &state.surfaces,
                            &mut state.present_frame,
                            state.display_tid,
                            state.display_width,
                            state.display_height,
                            state.display_stride,
                            state.display_format,
                            None,
                        );
                    }
                }
                sleep_one_tick();
                continue;
            }
        };
        let sender = msg >> 32;
        let len = (msg & 0xffff_ffff) as usize;
        if len == 16 {
            let client =
                client_id_for_sender(&mut state.clients, sender, &mut state.next_client_id);
            if client == ClientId(0) {
                continue;
            }
            let mapped_addr = u64::from_le_bytes([
                buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
            ]);
            let total = u64::from_le_bytes([
                buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
            ]);
            if handle_shared_buffer(&mut state.surfaces, client, mapped_addr, total) {
                continue;
            }
        }
        if len == core::mem::size_of::<platform::input::InputEvent>() {
            let event = unsafe {
                core::ptr::read_unaligned(buf.as_ptr().cast::<platform::input::InputEvent>())
            };
            let needs_present = handle_input_event(
                &state.surfaces,
                &state.windows,
                &mut state.next_pointer_serial,
                &mut state.pointer_serials,
                &mut state.pointer_x,
                &mut state.pointer_y,
                state.display_width,
                state.display_height,
                &mut state.pointer_focus,
                &mut state.keyboard_focus,
                &event,
            );
            if needs_present {
                let _ = composite_and_present(
                    &state.surfaces,
                    &mut state.present_frame,
                    state.display_tid,
                    state.display_width,
                    state.display_height,
                    state.display_stride,
                    state.display_format,
                    None,
                );
            }
            continue;
        }
        if len == 0 || len > buf.len() {
            let mut reply = [0u8; 16];
            put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EINVAL));
            let _ = platform::ipc::reply(sender, &reply);
            continue;
        }
        let client = client_id_for_sender(&mut state.clients, sender, &mut state.next_client_id);
        if client == ClientId(0) {
            let mut reply = [0u8; 16];
            put_u32(&mut reply, 0, errno_status(mochi_user_syscall::ENOSPC));
            let _ = platform::ipc::reply(sender, &reply);
            continue;
        }
        let mut needs_present = false;
        let mut present_damage = None;
        let reply = handle_request(
            &mut state.clients,
            &mut state.surfaces,
            &mut state.windows,
            &mut state.next_z,
            &mut state.next_window_index,
            &mut state.next_window_id,
            &mut state.next_pointer_serial,
            &mut state.pointer_serials,
            &mut state.pointer_focus,
            &mut state.keyboard_focus,
            client,
            sender,
            &buf[..len],
            &mut needs_present,
            &mut present_damage,
            state.display_tid,
            state.display_width,
            state.display_height,
            state.display_stride,
            state.display_format,
        );
        if platform::ipc::reply(sender, &reply).is_err() {
            cleanup_client(
                &mut state.clients,
                &mut state.surfaces,
                &mut state.windows,
                client,
                &mut state.pointer_focus,
                &mut state.keyboard_focus,
            );
        } else {
            if needs_present {
                let status = composite_and_present(
                    &state.surfaces,
                    &mut state.present_frame,
                    state.display_tid,
                    state.display_width,
                    state.display_height,
                    state.display_stride,
                    state.display_format,
                    present_damage,
                );
                if status == 0 {
                    for surface in state.surfaces.iter().filter(|surface| surface.live) {
                        send_frame_done(surface);
                    }
                } else {
                    platform::println!("compositor.service: present deferred status={}", status);
                }
            }
        }
    }
}
