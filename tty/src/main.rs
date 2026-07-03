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
    let mut reply = [0u8; 1024];
    let msg = platform::ipc::call(service_tid, &request, &mut reply)?;
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

fn spawn_msh(shell_endpoint: u64) -> Result<u64, mochi_user_syscall::SysError> {
    let caps_nul = resolve_capabilities(MSH_PATH)?;
    let arg = shell_endpoint.to_string();
    let args = [arg];
    let args_nul = encode_spawn_args(&args);
    platform::service::spawn_manifest(
        MSH_PATH,
        platform::service::ROLE_APPLICATION,
        Some(args_nul.as_slice()),
        Some(caps_nul.as_slice()),
    )
}

fn find_input_service() -> Option<u64> {
    for _ in 0..64 {
        if let Ok(tid) = platform::process::find_by_name(INPUT_SERVICE_NAME) {
            if tid != 0 {
                return Some(tid);
            }
        }
        platform::thread::yield_now();
    }
    None
}

#[unsafe(no_mangle)]
pub extern "C" fn service_main(sp: *const usize) -> ! {
    unsafe {
        let _ = platform::logger::init_from_initial_stack(sp);
    }
    let _ = unsafe { parse_endpoint_arg(sp) };

    let input_endpoint = match platform::ipc::create() {
        Ok(handle) => handle,
        Err(_) => platform::process::exit(1),
    };
    let shell_endpoint = match platform::ipc::create() {
        Ok(handle) => handle,
        Err(_) => platform::process::exit(1),
    };

    let subscribe = platform::input::SubscribeRequest {
        opcode: platform::input::SUBSCRIBE_OPCODE,
        reserved: 0,
        endpoint: input_endpoint,
    };
    let Some(input_tid) = find_input_service() else {
        platform::process::exit(1);
    };
    let mut reply = [0u8; 8];
    let _ = platform::ipc::call(
        input_tid,
        platform::input::bytes_of(&subscribe),
        &mut reply,
    );

    if spawn_msh(shell_endpoint).is_err() {
        platform::process::exit(1);
    }

    let mut buf = [0u8; core::mem::size_of::<platform::input::InputEvent>()];
    loop {
        let Ok(msg) = platform::ipc::wait(input_endpoint, &mut buf) else {
            platform::thread::yield_now();
            continue;
        };
        let len = (msg & 0xffff_ffff) as usize;
        if len < buf.len() {
            continue;
        }
        let _ = platform::ipc::send(shell_endpoint, &buf);
    }
}
