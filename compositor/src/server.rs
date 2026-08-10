use mochi_user_platform as platform;

use crate::client::{Client, ClientId, cleanup_client, cleanup_dead_clients, client_id_for_sender};
use crate::context_menu::ContextMenuBroker;
use crate::cursor::CursorImage;
use crate::decoration::sender_can_control_cursor;
use crate::display::{
    display_claim_present_owner, display_renderer_caps, display_request_info,
    display_set_cursor_position, sleep_one_tick, wait_for_service,
};
use crate::geometry::{Rect, merge_damage};
use crate::input::{
    PointerGrab, PointerSerial, finish_pointer_motion, handle_input_event, send_event,
    subscribe_input_events, update_pointer_position,
};
use crate::protocol::*;
use crate::renderer::composite_and_present;
use crate::state::CompositorState;
use crate::surface::{Surface, handle_shared_buffer, send_frame_done};
use crate::window::Window;

const IDLE_CLEANUP_YIELDS: u32 = 64;
static mut IPC_BUF: [u8; 4128] = [0; 4128];

fn is_pointer_motion(event: &platform::input::InputEvent) -> bool {
    matches!(
        event.kind,
        platform::input::EVENT_KIND_POINTER_MOVE | platform::input::EVENT_KIND_POINTER_ABSOLUTE
    )
}

fn process_input_event(
    state: &mut CompositorState,
    event: &platform::input::InputEvent,
    mut damage: Option<Rect>,
) -> Option<Rect> {
    if let Some(event_damage) = handle_input_event(
        &mut state.surfaces,
        &mut state.windows,
        &mut state.next_z,
        &mut state.next_pointer_serial,
        &mut state.pointer_serials,
        &mut state.pointer_x,
        &mut state.pointer_y,
        state.display_width,
        state.display_height,
        &mut state.pointer_focus,
        &mut state.keyboard_focus,
        &mut state.pointer_grab,
        &mut state.context_menu,
        event,
    ) {
        damage = merge_damage(damage, event_damage);
    }
    if is_pointer_motion(event) && !state.cursor_image.is_empty() {
        let old = state
            .cursor_visible
            .then_some((state.cursor_x, state.cursor_y));
        state.cursor_x = state.pointer_x;
        state.cursor_y = state.pointer_y;
        state.cursor_visible = true;
        if !state.hardware_cursor
            || display_set_cursor_position(state.display_tid, state.cursor_x, state.cursor_y, true)
                != 0
        {
            state.hardware_cursor = false;
            damage = merge_damage(
                damage,
                state
                    .cursor_image
                    .movement_damage(old, state.cursor_x, state.cursor_y),
            );
        }
    }
    damage
}

fn finish_coalesced_pointer_motion(state: &mut CompositorState) -> Option<Rect> {
    let mut damage = finish_pointer_motion(
        &mut state.surfaces,
        &state.windows,
        &state.pointer_grab,
        state.pointer_x,
        state.pointer_y,
        &mut state.pointer_focus,
    );
    if !state.cursor_image.is_empty() {
        let old = state
            .cursor_visible
            .then_some((state.cursor_x, state.cursor_y));
        state.cursor_x = state.pointer_x;
        state.cursor_y = state.pointer_y;
        state.cursor_visible = true;
        if !state.hardware_cursor
            || display_set_cursor_position(state.display_tid, state.cursor_x, state.cursor_y, true)
                != 0
        {
            state.hardware_cursor = false;
            damage = merge_damage(
                damage,
                state
                    .cursor_image
                    .movement_damage(old, state.cursor_x, state.cursor_y),
            );
        }
    }
    damage
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
    pointer_grab: &mut Option<PointerGrab>,
    pointer_x: i32,
    pointer_y: i32,
    client: ClientId,
    sender: u64,
    request: &[u8],
    needs_present: &mut bool,
    present_damage: &mut Option<Rect>,
    cursor_x: &mut i32,
    cursor_y: &mut i32,
    cursor_visible: &mut bool,
    cursor_image: &mut CursorImage,
    hardware_cursor: &mut bool,
    display_tid: u64,
    display_width: u32,
    display_height: u32,
    _display_stride: u32,
    _display_format: u32,
    renderer_caps: u32,
    context_menu: &mut ContextMenuBroker,
) -> [u8; 16] {
    let mut reply = [0u8; 16];
    let Some(opcode) = read_u32(request, 0) else {
        put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EINVAL));
        return reply;
    };
    match opcode {
        OP_GET_RENDERER_CAPS => {
            put_u32(&mut reply, 0, 0);
            put_u32(&mut reply, 4, renderer_caps);
        }
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
                pointer_grab,
                pointer_x,
                pointer_y,
                client,
                sender,
                request,
                needs_present,
                display_width,
                display_height,
            );
        }
        OP_CONTEXT_MENU_SUBSCRIBE | OP_CONTEXT_MENU_SHOW | OP_CONTEXT_MENU_COMPLETE => {
            return context_menu.handle_request(surfaces, keyboard_focus, client, sender, request);
        }
        OP_APPEARANCE_CHANGED => {
            if request.len() != 4 {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EINVAL));
                return reply;
            }
            if !matches!(
                platform::capability::check_thread(sender, "settings.write"),
                Ok(1)
            ) {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            }
            for (index, surface) in surfaces.iter().enumerate() {
                if !surface.live || surface.is_decoration || surface.event_endpoint == 0 {
                    continue;
                }
                let already_notified = surfaces[..index].iter().any(|previous| {
                    previous.live
                        && !previous.is_decoration
                        && previous.event_endpoint == surface.event_endpoint
                });
                if !already_notified {
                    send_event(surface.event_endpoint, EVENT_APPEARANCE_CHANGED, 0, 0, 0);
                }
            }
            put_u32(&mut reply, 0, 0);
        }
        OP_SET_CURSOR_POSITION => {
            if request.len() != 16 || !sender_can_control_cursor(sender) {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            }
            let x = read_u32(request, 4).unwrap_or(0) as i32;
            let y = read_u32(request, 8).unwrap_or(0) as i32;
            let visible = read_u32(request, 12).unwrap_or(0) == 1;
            if (visible && cursor_image.is_empty()) || read_u32(request, 12).unwrap_or(2) > 1 {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EINVAL));
                return reply;
            }
            let old = (*cursor_visible).then_some((*cursor_x, *cursor_y));
            *cursor_x = x;
            *cursor_y = y;
            *cursor_visible = visible;
            if !*hardware_cursor || display_set_cursor_position(display_tid, x, y, visible) != 0 {
                *hardware_cursor = false;
                *present_damage = Some(cursor_image.movement_damage(old, x, y));
                *needs_present = true;
            }
            put_u32(&mut reply, 0, 0);
        }
        OP_SET_CURSOR_IMAGE => {
            if request.len() < 20 || !sender_can_control_cursor(sender) {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EACCES));
                return reply;
            }
            let width = read_u32(request, 4).unwrap_or(0);
            let height = read_u32(request, 8).unwrap_or(0);
            let hotspot_x = read_u32(request, 12).unwrap_or(u32::MAX) as i32;
            let hotspot_y = read_u32(request, 16).unwrap_or(u32::MAX) as i32;
            if !cursor_image.set_premultiplied_rgba(
                width,
                height,
                hotspot_x,
                hotspot_y,
                &request[20..],
            ) {
                put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EINVAL));
                return reply;
            }
            *hardware_cursor = false;
            put_u32(&mut reply, 0, 0);
        }
        _ => put_u32(&mut reply, 0, errno_status(mochi_user_syscall::EINVAL)),
    }
    reply
}

pub(crate) fn run() -> ! {
    let endpoint = match platform::ipc::create() {
        Ok(endpoint) => endpoint,
        Err(_) => platform::process::exit(1),
    };
    let Some(display_tid) = wait_for_service(4096) else {
        platform::process::exit(1);
    };
    let input_subscribed = subscribe_input_events(endpoint);
    let _ = display_claim_present_owner(display_tid);
    let (display_width, display_height, display_stride, display_format) =
        display_request_info(display_tid);
    let renderer_caps = display_renderer_caps(display_tid);

    let mut state = CompositorState::new(
        display_tid,
        display_width,
        display_height,
        display_stride,
        display_format,
        input_subscribed,
        renderer_caps,
    );
    let _ = composite_and_present(
        &state.surfaces,
        &state.windows,
        state.keyboard_focus,
        &mut state.present_frame,
        state.display_tid,
        state.display_width,
        state.display_height,
        state.display_stride,
        state.display_format,
        state.cursor_x,
        state.cursor_y,
        state.cursor_visible && !state.hardware_cursor,
        &state.cursor_image,
        None,
    );
    let mut pending_msg: Option<u64> = None;
    let mut pending_buf = [0u8; 4128];
    loop {
        let buf = unsafe {
            core::slice::from_raw_parts_mut(core::ptr::addr_of_mut!(IPC_BUF).cast::<u8>(), 4128)
        };
        let msg = if let Some(msg) = pending_msg.take() {
            let len = ((msg & 0xffff_ffff) as usize).min(buf.len());
            buf[..len].copy_from_slice(&pending_buf[..len]);
            msg
        } else {
            match platform::ipc::try_wait(buf) {
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
                                &state.windows,
                                state.keyboard_focus,
                                &mut state.present_frame,
                                state.display_tid,
                                state.display_width,
                                state.display_height,
                                state.display_stride,
                                state.display_format,
                                state.cursor_x,
                                state.cursor_y,
                                state.cursor_visible && !state.hardware_cursor,
                                &state.cursor_image,
                                None,
                            );
                        }
                    }
                    sleep_one_tick();
                    continue;
                }
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
            let input_damage = if is_pointer_motion(&event) {
                update_pointer_position(
                    &mut state.pointer_x,
                    &mut state.pointer_y,
                    state.display_width,
                    state.display_height,
                    &event,
                );
                // Give the input pipeline one scheduling turn to accumulate motion
                // before the synchronous display transfer starts.
                platform::thread::yield_now();
                while let Ok(next_msg) = platform::ipc::try_wait(buf) {
                    let next_len = (next_msg & 0xffff_ffff) as usize;
                    if next_len == core::mem::size_of::<platform::input::InputEvent>() {
                        let next_event = unsafe {
                            core::ptr::read_unaligned(
                                buf.as_ptr().cast::<platform::input::InputEvent>(),
                            )
                        };
                        if is_pointer_motion(&next_event) {
                            update_pointer_position(
                                &mut state.pointer_x,
                                &mut state.pointer_y,
                                state.display_width,
                                state.display_height,
                                &next_event,
                            );
                            continue;
                        }
                    }
                    let copy_len = next_len.min(buf.len());
                    pending_buf[..copy_len].copy_from_slice(&buf[..copy_len]);
                    pending_msg = Some(next_msg);
                    break;
                }
                finish_coalesced_pointer_motion(&mut state)
            } else {
                process_input_event(&mut state, &event, None)
            };
            if input_damage.is_some() {
                let _ = composite_and_present(
                    &state.surfaces,
                    &state.windows,
                    state.keyboard_focus,
                    &mut state.present_frame,
                    state.display_tid,
                    state.display_width,
                    state.display_height,
                    state.display_stride,
                    state.display_format,
                    state.cursor_x,
                    state.cursor_y,
                    state.cursor_visible && !state.hardware_cursor,
                    &state.cursor_image,
                    input_damage,
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
            &mut state.pointer_grab,
            state.pointer_x,
            state.pointer_y,
            client,
            sender,
            &buf[..len],
            &mut needs_present,
            &mut present_damage,
            &mut state.cursor_x,
            &mut state.cursor_y,
            &mut state.cursor_visible,
            &mut state.cursor_image,
            &mut state.hardware_cursor,
            state.display_tid,
            state.display_width,
            state.display_height,
            state.display_stride,
            state.display_format,
            state.renderer_caps,
            &mut state.context_menu,
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
            state.context_menu.cleanup_client(client);
        } else {
            if needs_present {
                let status = composite_and_present(
                    &state.surfaces,
                    &state.windows,
                    state.keyboard_focus,
                    &mut state.present_frame,
                    state.display_tid,
                    state.display_width,
                    state.display_height,
                    state.display_stride,
                    state.display_format,
                    state.cursor_x,
                    state.cursor_y,
                    state.cursor_visible && !state.hardware_cursor,
                    &state.cursor_image,
                    present_damage,
                );
                if status == 0 {
                    for surface in state.surfaces.iter().filter(|surface| surface.live) {
                        send_frame_done(surface);
                    }
                }
            }
        }
    }
}
