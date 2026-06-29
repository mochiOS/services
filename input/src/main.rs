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

unsafe fn parse_endpoint_arg(sp: *const usize) -> Option<u64> {
    let stack = unsafe { platform::runtime::InitialStack::parse(sp) };
    for &arg_ptr in stack.argv {
        if arg_ptr.is_null() {
            continue;
        }
        let len = unsafe { c_string_len(arg_ptr) };
        let arg = unsafe { core::slice::from_raw_parts(arg_ptr, len) };
        if let Some(value) = parse_decimal_u64(arg) {
            return Some(value);
        }
    }
    None
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
    let upper = shift ^ caps;
    Some(if upper { ch.to_ascii_uppercase() } else { ch })
}

fn decode_symbol(scancode: u8, shift: bool) -> Option<char> {
    let ch = match (scancode, shift) {
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
    };
    Some(ch)
}

#[unsafe(no_mangle)]
pub extern "C" fn service_main(sp: *const usize) -> ! {
    platform::println!("input.service: start");

    let endpoint = unsafe { parse_endpoint_arg(sp) }.unwrap_or(0);
    if endpoint == 0 {
        platform::println!("input.service: missing endpoint");
        platform::process::exit(1);
    }

    let mut shift = false;
    let mut caps_lock = false;
    let mut buf = [0u8; 16];

    loop {
        let Ok(msg) = platform::ipc::wait(endpoint, &mut buf) else {
            platform::thread::yield_now();
            continue;
        };
        let len = (msg & 0xffff_ffff) as usize;
        if len == 0 {
            continue;
        }

        for &raw in &buf[..len] {
            let is_break = (raw & 0x80) != 0;
            let scancode = raw & 0x7f;
            match scancode {
                0x2a | 0x36 => {
                    shift = !is_break;
                }
                0x3a if !is_break => {
                    caps_lock = !caps_lock;
                    platform::println!("input.service: key=<CapsLock>");
                }
                0x1c if !is_break => platform::println!("input.service: key=<Enter>"),
                0x0e if !is_break => platform::println!("input.service: key=<Backspace>"),
                0x0f if !is_break => platform::println!("input.service: key=<Tab>"),
                0x01 if !is_break => platform::println!("input.service: key=<Esc>"),
                _ if is_break => {}
                _ => {
                    if let Some(ch) = decode_alpha(scancode, shift, caps_lock)
                        .or_else(|| decode_symbol(scancode, shift))
                    {
                        platform::println!("input.service: key={}", ch);
                    }
                }
            }
        }
    }
}
