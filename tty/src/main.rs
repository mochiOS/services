#![no_std]
#![no_main]

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
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

const MSH_PATH: &str = "/bin/msh";
const CAPABILITY_SERVICE_NAME: &str = "capability.service";
const INPUT_SERVICE_NAME: &str = "input.service";
const RESOLVE_CAPS_OPCODE: u32 = 0x4341_5053;
const INPUT_EVENT_SIZE: usize = core::mem::size_of::<platform::input::InputEvent>();
const TTY_IPC_BUFFER_SIZE: usize = 2048;
const TTY_OUTPUT_MAGIC: &[u8; 4] = b"TOUT";

static mut CAPABILITY_REPLY_BUF: [u8; 1024] = [0; 1024];
static mut INPUT_SUBSCRIBE_REPLY_BUF: [u8; 8] = [0; 8];
static mut TTY_IPC_BUF: [u8; TTY_IPC_BUFFER_SIZE] = [0; TTY_IPC_BUFFER_SIZE];

fn capability_reply_buf() -> &'static mut [u8] {
    unsafe {
        core::slice::from_raw_parts_mut(
            core::ptr::addr_of_mut!(CAPABILITY_REPLY_BUF).cast::<u8>(),
            core::mem::size_of::<[u8; 1024]>(),
        )
    }
}

fn input_subscribe_reply_buf() -> &'static mut [u8] {
    unsafe {
        core::slice::from_raw_parts_mut(
            core::ptr::addr_of_mut!(INPUT_SUBSCRIBE_REPLY_BUF).cast::<u8>(),
            core::mem::size_of::<[u8; 8]>(),
        )
    }
}

fn tty_ipc_buf() -> &'static mut [u8] {
    unsafe {
        core::slice::from_raw_parts_mut(
            core::ptr::addr_of_mut!(TTY_IPC_BUF).cast::<u8>(),
            TTY_IPC_BUFFER_SIZE,
        )
    }
}

fn is_tty_output(bytes: &[u8]) -> bool {
    bytes.len() >= TTY_OUTPUT_MAGIC.len() && &bytes[..TTY_OUTPUT_MAGIC.len()] == TTY_OUTPUT_MAGIC
}

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

fn encode_spawn_args(items: &[String]) -> Vec<u8> {
    let mut out = Vec::with_capacity(512);
    out.resize(512, 0);
    let mut cursor = 0usize;
    for item in items {
        let bytes = item.as_bytes();
        if cursor + bytes.len() + 2 > out.len() {
            break;
        }
        out[cursor..cursor + bytes.len()].copy_from_slice(bytes);
        cursor += bytes.len();
        out[cursor] = 0;
        cursor += 1;
    }
    out
}

fn resolve_capabilities(entry_path: &str) -> Result<Vec<u8>, mochi_user_syscall::SysError> {
    let service_tid = platform::process::find_by_name(CAPABILITY_SERVICE_NAME)?;
    if service_tid == 0 {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::ENOENT as i64,
        ));
    }
    let mut request = Vec::with_capacity(4 + entry_path.len());
    request.extend_from_slice(&RESOLVE_CAPS_OPCODE.to_le_bytes());
    request.extend_from_slice(entry_path.as_bytes());
    let reply = capability_reply_buf();
    reply.fill(0);
    let msg = platform::ipc::call(service_tid, &request, reply)?;
    let len = (msg & 0xffff_ffff) as usize;
    if len < 8 || len > reply.len() {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EIO as i64,
        ));
    }
    let status =
        u64::from_le_bytes(reply[..8].try_into().map_err(|_| {
            mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64)
        })?);
    if status != 0 {
        return Err(mochi_user_syscall::SysError::from_raw(status as i64));
    }
    Ok(reply[8..len].to_vec())
}

fn spawn_msh(tty_endpoint: u64) -> Result<u64, mochi_user_syscall::SysError> {
    let caps_nul = resolve_capabilities(MSH_PATH)?;
    let arg = tty_endpoint.to_string();
    let args = ["__MOCHI_EXEC_ENV=MOCHI_STDIO_DIRECT=1".to_string(), arg];
    let args_nul = encode_spawn_args(&args);
    platform::service::spawn_manifest(
        MSH_PATH,
        platform::service::ROLE_APPLICATION,
        Some(args_nul.as_slice()),
        Some(caps_nul.as_slice()),
    )
}

fn find_input_service() -> Option<u64> {
    for _ in 0..4096 {
        if let Ok(tid) = platform::process::find_by_name(INPUT_SERVICE_NAME) {
            if tid != 0 {
                return Some(tid);
            }
        }
        platform::thread::yield_now();
    }
    None
}

fn subscribe_input_events(tty_endpoint: u64) -> bool {
    let Some(input_tid) = find_input_service() else {
        return false;
    };
    let subscribe = platform::input::SubscribeRequest {
        opcode: platform::input::SUBSCRIBE_OPCODE,
        reserved: 0,
        endpoint: tty_endpoint,
    };
    let subscribe_reply = input_subscribe_reply_buf();
    subscribe_reply.fill(0);
    platform::ipc::call(
        input_tid,
        platform::input::bytes_of(&subscribe),
        subscribe_reply,
    )
    .is_ok()
}

#[unsafe(no_mangle)]
pub extern "C" fn service_main(sp: *const usize) -> ! {
    unsafe {
        let _ = platform::logger::init_from_initial_stack(sp);
    }
    let _ = unsafe { parse_endpoint_arg(sp) };

    let tty_endpoint = match platform::ipc::create() {
        Ok(handle) => handle,
        Err(_) => platform::process::exit(1),
    };

    while !subscribe_input_events(tty_endpoint) {
        platform::thread::yield_now();
    }

    if spawn_msh(tty_endpoint).is_err() {
        platform::process::exit(1);
    }

    let mut shell_endpoint = 0u64;
    let mut shell_thread = 0u64;
    loop {
        let buf = tty_ipc_buf();
        buf.fill(0);
        let Ok(msg) = platform::ipc::wait(tty_endpoint, buf) else {
            platform::thread::yield_now();
            continue;
        };
        let len = (msg & 0xffff_ffff) as usize;
        let sender = msg >> 32;
        let len = len.min(buf.len());
        if len == core::mem::size_of::<u64>() {
            shell_endpoint = u64::from_le_bytes([
                buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
            ]);
            continue;
        }
        if len == core::mem::size_of::<u64>() * 2 {
            shell_endpoint = u64::from_le_bytes([
                buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
            ]);
            shell_thread = u64::from_le_bytes([
                buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
            ]);
            continue;
        }
        if is_tty_output(&buf[..len]) {
            if shell_endpoint != 0 {
                let _ = platform::ipc::send(shell_endpoint, &buf[..len]);
            }
            if shell_thread != 0 && shell_thread != shell_endpoint {
                let _ = platform::ipc::send(shell_thread, &buf[..len]);
            }
            let status = 0u64;
            let _ = platform::ipc::reply(sender, &status.to_le_bytes());
            continue;
        }
        if len != INPUT_EVENT_SIZE {
            continue;
        }
        if shell_endpoint != 0 {
            let _ = platform::ipc::send(shell_endpoint, &buf[..len]);
        }
        if shell_thread != 0 && shell_thread != shell_endpoint {
            let _ = platform::ipc::send(shell_thread, &buf[..len]);
        }
    }
}
