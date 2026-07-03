#![no_std]
#![no_main]

use core::arch::global_asm;
use mochi_user_platform as platform;

global_asm!(
    r#"
    .global _start
_start:
    xor rbp, rbp
    mov rdi, rsp
    and rsp, -16
    call service_main
1:
    hlt
    jmp 1b
"#
);

fn parse_decimal_u64(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() {
        return None;
    }
    let mut out = 0u64;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        out = out.checked_mul(10)?;
        out = out.checked_add(u64::from(b - b'0'))?;
    }
    Some(out)
}

unsafe fn c_string_len(ptr: *const u8) -> usize {
    let mut len = 0usize;
    loop {
        let ch = unsafe { core::ptr::read_volatile(ptr.add(len)) };
        if ch == 0 {
            return len;
        }
        len += 1;
    }
}

unsafe fn parse_endpoint_args(sp: *const usize) -> [u64; 2] {
    let stack = unsafe { platform::runtime::InitialStack::parse(sp) };
    let mut out = [0u64; 2];
    let mut idx = 0usize;
    for &arg_ptr in stack.argv {
        if idx >= out.len() || arg_ptr.is_null() {
            continue;
        }
        let len = unsafe { c_string_len(arg_ptr) };
        let arg = unsafe { core::slice::from_raw_parts(arg_ptr, len) };
        if let Some(value) = parse_decimal_u64(arg) {
            out[idx] = value;
            idx += 1;
        }
    }
    out
}

fn decode_alpha(scancode: u8, shift: bool, caps: bool) -> Option<char> {
    let ch = match scancode {
        0x10 => 'q',
        0x11 => 'w',
        0x12 => 'e',
        0x13 => 'r',
        0x14 => 't',
        0x15 => 'y',
        0x16 => 'u',
        0x17 => 'i',
        0x18 => 'o',
        0x19 => 'p',
        0x1e => 'a',
        0x1f => 's',
        0x20 => 'd',
        0x21 => 'f',
        0x22 => 'g',
        0x23 => 'h',
        0x24 => 'j',
        0x25 => 'k',
        0x26 => 'l',
        0x2c => 'z',
        0x2d => 'x',
        0x2e => 'c',
        0x2f => 'v',
        0x30 => 'b',
        0x31 => 'n',
        0x32 => 'm',
        _ => return None,
    };
    Some(if shift ^ caps {
        ch.to_ascii_uppercase()
    } else {
        ch
    })
}

fn decode_symbol(scancode: u8, shift: bool) -> Option<char> {
    Some(match (scancode, shift) {
        (0x02, false) => '1',
        (0x03, false) => '2',
        (0x04, false) => '3',
        (0x05, false) => '4',
        (0x06, false) => '5',
        (0x07, false) => '6',
        (0x08, false) => '7',
        (0x09, false) => '8',
        (0x0a, false) => '9',
        (0x0b, false) => '0',
        (0x02, true) => '!',
        (0x03, true) => '@',
        (0x04, true) => '#',
        (0x05, true) => '$',
        (0x06, true) => '%',
        (0x07, true) => '^',
        (0x08, true) => '&',
        (0x09, true) => '*',
        (0x0a, true) => '(',
        (0x0b, true) => ')',
        (0x0c, false) => '-',
        (0x0c, true) => '_',
        (0x0d, false) => '=',
        (0x0d, true) => '+',
        (0x1a, false) => '[',
        (0x1a, true) => '{',
        (0x1b, false) => ']',
        (0x1b, true) => '}',
        (0x27, false) => ';',
        (0x27, true) => ':',
        (0x28, false) => '\'',
        (0x28, true) => '"',
        (0x29, false) => '`',
        (0x29, true) => '~',
        (0x2b, false) => '\\',
        (0x2b, true) => '|',
        (0x33, false) => ',',
        (0x33, true) => '<',
        (0x34, false) => '.',
        (0x34, true) => '>',
        (0x35, false) => '/',
        (0x35, true) => '?',
        (0x39, _) => ' ',
        _ => return None,
    })
}

fn keycode_for_scancode(scancode: u8, extended: bool) -> Option<u16> {
    use platform::input::*;
    Some(match (scancode, extended) {
        (0x01, false) => KEY_ESC,
        (0x0e, false) => KEY_BACKSPACE,
        (0x0f, false) => KEY_TAB,
        (0x1c, false) => KEY_ENTER,
        (0x1d, false) => KEY_LEFT_CTRL,
        (0x1d, true) => KEY_RIGHT_CTRL,
        (0x2a, false) => KEY_LEFT_SHIFT,
        (0x36, false) => KEY_RIGHT_SHIFT,
        (0x38, false) => KEY_LEFT_ALT,
        (0x38, true) => KEY_RIGHT_ALT,
        (0x3a, false) => KEY_CAPS_LOCK,
        (0x39, false) => KEY_SPACE,
        (0x10, false) => KEY_Q,
        (0x11, false) => KEY_W,
        (0x12, false) => KEY_E,
        (0x13, false) => KEY_R,
        (0x14, false) => KEY_T,
        (0x15, false) => KEY_Y,
        (0x16, false) => KEY_U,
        (0x17, false) => KEY_I,
        (0x18, false) => KEY_O,
        (0x19, false) => KEY_P,
        (0x1e, false) => KEY_A,
        (0x1f, false) => KEY_S,
        (0x20, false) => KEY_D,
        (0x21, false) => KEY_F,
        (0x22, false) => KEY_G,
        (0x23, false) => KEY_H,
        (0x24, false) => KEY_J,
        (0x25, false) => KEY_K,
        (0x26, false) => KEY_L,
        (0x2c, false) => KEY_Z,
        (0x2d, false) => KEY_X,
        (0x2e, false) => KEY_C,
        (0x2f, false) => KEY_V,
        (0x30, false) => KEY_B,
        (0x31, false) => KEY_N,
        (0x32, false) => KEY_M,
        (0x02, false) => KEY_1,
        (0x03, false) => KEY_2,
        (0x04, false) => KEY_3,
        (0x05, false) => KEY_4,
        (0x06, false) => KEY_5,
        (0x07, false) => KEY_6,
        (0x08, false) => KEY_7,
        (0x09, false) => KEY_8,
        (0x0a, false) => KEY_9,
        (0x0b, false) => KEY_0,
        (0x0c, false) => KEY_MINUS,
        (0x0d, false) => KEY_EQUAL,
        (0x1a, false) => KEY_LEFT_BRACKET,
        (0x1b, false) => KEY_RIGHT_BRACKET,
        (0x27, false) => KEY_SEMICOLON,
        (0x28, false) => KEY_APOSTROPHE,
        (0x29, false) => KEY_GRAVE,
        (0x2b, false) => KEY_BACKSLASH,
        (0x33, false) => KEY_COMMA,
        (0x34, false) => KEY_DOT,
        (0x35, false) => KEY_SLASH,
        _ => return None,
    })
}

#[derive(Clone, Copy, Default)]
struct KeyboardState {
    shift: bool,
    ctrl: bool,
    alt: bool,
    caps_lock: bool,
    extended_prefix: bool,
}

impl KeyboardState {
    fn modifiers(self) -> u32 {
        let mut out = 0u32;
        if self.shift {
            out |= platform::input::MOD_SHIFT;
        }
        if self.ctrl {
            out |= platform::input::MOD_CTRL;
        }
        if self.alt {
            out |= platform::input::MOD_ALT;
        }
        if self.caps_lock {
            out |= platform::input::MOD_CAPS_LOCK;
        }
        out
    }
}

const INPUT_EVENT_SIZE: usize = core::mem::size_of::<platform::input::InputEvent>();

fn encode_input_event(
    kind: u16,
    flags: u16,
    keycode: u16,
    detail: u16,
    codepoint: u32,
    value_x: i32,
    value_y: i32,
    value_z: i32,
    modifiers: u32,
) -> [u8; INPUT_EVENT_SIZE] {
    let mut out = [0u8; INPUT_EVENT_SIZE];
    out[0..2].copy_from_slice(&kind.to_le_bytes());
    out[2..4].copy_from_slice(&flags.to_le_bytes());
    out[4..6].copy_from_slice(&keycode.to_le_bytes());
    out[6..8].copy_from_slice(&detail.to_le_bytes());
    out[8..12].copy_from_slice(&codepoint.to_le_bytes());
    out[12..16].copy_from_slice(&value_x.to_le_bytes());
    out[16..20].copy_from_slice(&value_y.to_le_bytes());
    out[20..24].copy_from_slice(&value_z.to_le_bytes());
    out[24..28].copy_from_slice(&modifiers.to_le_bytes());
    out
}

fn send_event(subscriber: u64, bytes: &[u8]) {
    if subscriber != 0 {
        let _ = platform::ipc::send(subscriber, bytes);
    }
}

fn process_keyboard_byte(byte: u8, state: &mut KeyboardState, subscriber: u64) {
    use platform::input::*;

    if byte == 0xe0 {
        state.extended_prefix = true;
        return;
    }

    let is_break = (byte & 0x80) != 0;
    let scancode = byte & 0x7f;
    let extended = state.extended_prefix;
    state.extended_prefix = false;

    match (scancode, extended) {
        (0x2a | 0x36, false) => state.shift = !is_break,
        (0x1d, _) => state.ctrl = !is_break,
        (0x38, _) => state.alt = !is_break,
        (0x3a, false) if !is_break => state.caps_lock = !state.caps_lock,
        _ => {}
    }

    let Some(keycode) = keycode_for_scancode(scancode, extended) else {
        return;
    };

    let mut codepoint = 0u32;

    if !is_break {
        if let Some(ch) = decode_alpha(scancode, state.shift, state.caps_lock)
            .or_else(|| decode_symbol(scancode, state.shift))
        {
            codepoint = ch as u32;
        }
    }

    let event = encode_input_event(
        EVENT_KIND_KEY,
        if is_break { FLAG_RELEASE } else { FLAG_PRESS },
        keycode,
        0,
        codepoint,
        0,
        0,
        0,
        state.modifiers(),
    );
    send_event(subscriber, &event);
}

fn handle_subscribe_message(subscriber: &mut u64, buf: &[u8]) {
    if buf.len() < 16 {
        return;
    }
    let opcode = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if opcode != platform::input::SUBSCRIBE_OPCODE {
        return;
    }
    *subscriber = u64::from_le_bytes([
        buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
    ]);
}

#[unsafe(no_mangle)]
pub extern "C" fn service_main(sp: *const usize) -> ! {
    unsafe {
        let _ = platform::logger::init_from_initial_stack(sp);
    }
    platform::println!("input.service: start");

    let endpoint = match platform::ipc::create() {
        Ok(endpoint) => endpoint,
        Err(_) => {
            platform::println!("input.service: endpoint create failed");
            platform::process::exit(1);
        }
    };
    let _ = unsafe { parse_endpoint_args(sp) };
    if endpoint == 0 {
        platform::println!("input.service: missing endpoint");
        platform::process::exit(1);
    }

    let mut keyboard = KeyboardState::default();
    let mut subscriber = 0u64;
    let mut keyboard_log_budget = 8usize;
    let mut buf = [0u8; 32];

    loop {
        let Ok(msg) = platform::ipc::wait(endpoint, &mut buf) else {
            platform::thread::yield_now();
            continue;
        };
        let sender = msg >> 32;
        let len = (msg & 0xffff_ffff) as usize;
        if len == 0 || len > buf.len() {
            let _ = platform::ipc::reply(sender, &[0]);
            continue;
        }

        if len >= 16
            && u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]])
                == platform::input::SUBSCRIBE_OPCODE
        {
            handle_subscribe_message(&mut subscriber, &buf[..len]);
            let _ = platform::ipc::reply(sender, &[0]);
            continue;
        }

        if len >= 8 {
            match buf[0] {
                platform::input::RAW_KIND_KEYBOARD => {
                    if keyboard_log_budget > 0 {
                        platform::println!("input.service: raw key=0x{:02x}", buf[4]);
                        keyboard_log_budget -= 1;
                    }
                    process_keyboard_byte(buf[4], &mut keyboard, subscriber);
                }
                platform::input::RAW_KIND_MOUSE_PACKET => {}
                _ => {}
            }
        }
        let _ = platform::ipc::reply(sender, &[0]);
    }
}
