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

const SIG_SERVICE_NAME: &str = "signature.service";
const VERIFY_PACKAGE_OPCODE: u32 = 0x5645_5246;
const INSTALL_REQUEST_OPCODE: u32 = 0x494e_5354;
const REPLY_OK: u64 = 0;
const O_WRONLY: u64 = 0o1;
const O_CREAT: u64 = 0o100;
const O_TRUNC: u64 = 0o1000;
const FILE_MODE_644: u64 = 0o644;
const FILE_MODE_755: u64 = 0o755;

#[derive(Clone)]
struct MpkgHeader {
    header_size: usize,
    compression: u8,
    _flags: u8,
    expanded_size: usize,
}

#[derive(Clone)]
struct TarEntry {
    path: String,
    kind: u8,
    data: Vec<u8>,
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

unsafe fn parse_initial_arg(sp: *const usize) -> Option<String> {
    let stack = unsafe { platform::runtime::InitialStack::parse(sp) };
    let mut seen_argv0 = false;
    for &arg_ptr in stack.argv {
        if arg_ptr.is_null() {
            continue;
        }
        if !seen_argv0 {
            seen_argv0 = true;
            continue;
        }
        let len = unsafe { c_string_len(arg_ptr) };
        let arg = unsafe { core::slice::from_raw_parts(arg_ptr, len) };
        if parse_decimal_u64(arg).is_some() {
            continue;
        }
        if let Ok(text) = core::str::from_utf8(arg) {
            if !text.is_empty() {
                return Some(text.to_string());
            }
        }
    }
    None
}

fn parse_octal(bytes: &[u8]) -> Option<usize> {
    let mut out = 0usize;
    let mut seen = false;
    for &b in bytes {
        if b == 0 || b == b' ' {
            break;
        }
        if !(b'0'..=b'7').contains(&b) {
            return None;
        }
        seen = true;
        out = out.checked_mul(8)?;
        out = out.checked_add((b - b'0') as usize)?;
    }
    if seen { Some(out) } else { Some(0) }
}

fn trim_cstr(bytes: &[u8]) -> &[u8] {
    let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    &bytes[..len]
}

fn is_valid_rel_path(path: &str) -> bool {
    if path.is_empty()
        || path.starts_with('/')
        || path.contains('\\')
        || path.contains('\0')
        || path.contains("//")
    {
        return false;
    }
    let mut last_was_slash = false;
    for seg in path.split('/') {
        if seg.is_empty() {
            if last_was_slash {
                return false;
            }
            last_was_slash = true;
            continue;
        }
        last_was_slash = false;
        if seg == "." || seg == ".." {
            return false;
        }
    }
    !path.ends_with('/')
}

fn join_path(prefix: &str, suffix: &str) -> String {
    if prefix.is_empty() {
        return suffix.to_string();
    }
    if suffix.is_empty() {
        return prefix.to_string();
    }
    alloc::format!("{}/{}", prefix.trim_end_matches('/'), suffix.trim_start_matches('/'))
}

fn parse_header(bytes: &[u8]) -> Option<MpkgHeader> {
    if bytes.len() < 32 {
        return None;
    }
    if &bytes[..4] != b"MPKG" {
        return None;
    }
    let major = u16::from_le_bytes([bytes[4], bytes[5]]);
    let _minor = u16::from_le_bytes([bytes[6], bytes[7]]);
    let header_size = u16::from_le_bytes([bytes[8], bytes[9]]) as usize;
    let compression = bytes[10];
    let flags = bytes[11];
    let expanded_size = u64::from_le_bytes([
        bytes[12], bytes[13], bytes[14], bytes[15], bytes[16], bytes[17], bytes[18], bytes[19],
    ]) as usize;
    if major != 1 || header_size != 32 || flags != 0 || compression > 1 {
        return None;
    }
    if bytes[20..32].iter().any(|&b| b != 0) {
        return None;
    }
    Some(MpkgHeader {
        header_size,
        compression,
        _flags: flags,
        expanded_size,
    })
}

fn parse_tar_stream(bytes: &[u8]) -> Option<Vec<TarEntry>> {
    let mut entries = Vec::new();
    let mut offset = 0usize;
    while offset + 512 <= bytes.len() {
        let block = &bytes[offset..offset + 512];
        if block.iter().all(|&b| b == 0) {
            break;
        }
        let name = trim_cstr(&block[0..100]);
        let prefix = trim_cstr(&block[345..500]);
        let mut path = String::new();
        if !prefix.is_empty() {
            path.push_str(core::str::from_utf8(prefix).ok()?);
            path.push('/');
        }
        path.push_str(core::str::from_utf8(name).ok()?);
        if !is_valid_rel_path(&path) {
            return None;
        }
        let size = parse_octal(&block[124..136])?;
        let kind = block[156];
        let payload_start = offset + 512;
        let payload_end = payload_start.checked_add(size)?;
        if payload_end > bytes.len() {
            return None;
        }
        let data = bytes[payload_start..payload_end].to_vec();
        if kind != b'0' && kind != 0 && kind != b'5' {
            return None;
        }
        if entries.iter().any(|entry: &TarEntry| entry.path == path) {
            return None;
        }
        if path != "manifest.toml"
            && !path.starts_with("signatures/")
            && !path.starts_with("payload/")
        {
            return None;
        }
        entries.push(TarEntry { path, kind, data });
        offset = payload_end.div_ceil(512) * 512;
    }
    Some(entries)
}

fn entry_by_path<'a>(entries: &'a [TarEntry], path: &str) -> Option<&'a TarEntry> {
    entries.iter().find(|entry| entry.path == path)
}

fn verify_with_signature_service(mpkg_path: &str) -> Result<(), mochi_user_syscall::SysError> {
    if !mpkg_path.starts_with('/') || mpkg_path.as_bytes().contains(&0) {
        return Err(mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64));
    }
    let service_tid = platform::process::find_by_name(SIG_SERVICE_NAME)?;
    if service_tid == 0 {
        return Err(mochi_user_syscall::SysError::from_raw(mochi_user_syscall::ENOENT as i64));
    }
    let mut request = Vec::with_capacity(4 + mpkg_path.len());
    request.extend_from_slice(&VERIFY_PACKAGE_OPCODE.to_le_bytes());
    request.extend_from_slice(mpkg_path.as_bytes());
    let mut reply = [0u8; 8];
    let msg = platform::ipc::call(service_tid, &request, &mut reply)?;
    let len = (msg & 0xffff_ffff) as usize;
    if len < 8 {
        return Err(mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EIO as i64));
    }
    let status = u64::from_le_bytes(reply);
    if status == 0 {
        Ok(())
    } else {
        Err(mochi_user_syscall::SysError::from_raw(status as i64))
    }
}

fn write_file(path: &str, data: &[u8], mode: u64) -> Result<(), mochi_user_syscall::SysError> {
    if let Some(parent) = path.rsplit_once('/').map(|(parent, _)| parent) {
        if !parent.is_empty() {
            let mut current = String::from("/");
            for seg in parent.split('/').filter(|seg| !seg.is_empty()) {
                if current.len() > 1 {
                    current.push('/');
                }
                current.push_str(seg);
                match platform::file::create_dir(&current, FILE_MODE_755) {
                    Ok(_) => {}
                    Err(err) if err.errno() == Some(mochi_user_syscall::EEXIST) => {}
                    Err(err) => return Err(err),
                }
            }
        }
    }
    let fd = platform::file::openat_path(
        -100,
        path,
        O_WRONLY | O_CREAT | O_TRUNC,
        mode,
    )?;
    let mut offset = 0usize;
    while offset < data.len() {
        let wrote = platform::file::write(fd, data[offset..].as_ptr() as u64, (data.len() - offset) as u64)?;
        if wrote == 0 {
            break;
        }
        offset += wrote as usize;
    }
    let _ = platform::file::close(fd);
    if offset != data.len() {
        return Err(mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EIO as i64));
    }
    Ok(())
}

fn install_package(mpkg_path: &str) -> Result<(), mochi_user_syscall::SysError> {
    verify_with_signature_service(mpkg_path)?;

    let bytes = platform::file::read_to_end_path(mpkg_path)?;
    let header = parse_header(&bytes).ok_or_else(|| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64))?;
    if header.compression != 0 {
        return Err(mochi_user_syscall::SysError::from_raw(mochi_user_syscall::ENOTSUP as i64));
    }
    let tar = bytes.get(header.header_size..).ok_or_else(|| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64))?;
    if tar.len() != header.expanded_size {
        return Err(mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64));
    }
    let entries = parse_tar_stream(tar).ok_or_else(|| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64))?;
    let manifest_entry = entry_by_path(&entries, "manifest.toml")
        .ok_or_else(|| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::ENOENT as i64))?;
    let manifest_text = core::str::from_utf8(&manifest_entry.data).map_err(|_| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64))?;
    let manifest = platform::package::parse_manifest(manifest_text)
        .ok_or_else(|| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64))?;
    match manifest.package_kind.as_deref() {
        None | Some("binary") | Some("application") => {}
        _ => return Err(mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64)),
    }

    let package_root = alloc::format!("/system/packages/{}", manifest.package_id);
    let manifest_path = alloc::format!("{}/manifest.toml", package_root);
    write_file(&manifest_path, &manifest_entry.data, FILE_MODE_644)?;

    let install_root = if manifest.package_kind.as_deref() == Some("application") {
        alloc::format!("/applications/{}.app", manifest.package_name)
    } else {
        String::new()
    };

    for entry in entries {
        if entry.path == "manifest.toml" || entry.path.starts_with("signatures/") {
            continue;
        }
        if entry.kind != b'0' && entry.kind != 0 && entry.kind != b'5' {
            return Err(mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64));
        }
        if entry.kind == b'5' {
            continue;
        }
        let target = if let Some(rel) = entry.path.strip_prefix("payload/root/") {
            join_path("/", rel)
        } else if let Some(rel) = entry.path.strip_prefix("payload/bundle/") {
            if install_root.is_empty() {
                return Err(mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64));
            }
            join_path(&install_root, rel)
        } else {
            return Err(mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64));
        };
        if !target.starts_with('/') {
            return Err(mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64));
        }
        let allowed = target.starts_with("/bin/")
            || target.starts_with("/libraries/")
            || target.starts_with("/binary/services/")
            || target.starts_with("/binary/resources/")
            || target.starts_with("/system/services/")
            || (target.starts_with("/applications/") && install_root.starts_with("/applications/"));
        if !allowed {
            return Err(mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64));
        }
        let mode = if target.ends_with(".toml")
            || target.ends_with(".txt")
            || target.ends_with(".bdf")
            || target.ends_with(".png")
            || target.ends_with(".json")
        {
            FILE_MODE_644
        } else {
            FILE_MODE_755
        };
        write_file(&target, &entry.data, mode)?;
    }
    Ok(())
}

fn parse_install_request(buf: &[u8]) -> Result<String, mochi_user_syscall::SysError> {
    if buf.len() < 4 {
        return Err(mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64));
    }
    let opcode = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if opcode != INSTALL_REQUEST_OPCODE {
        return Err(mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64));
    }
    let path_bytes = &buf[4..];
    if path_bytes.is_empty() || path_bytes.contains(&0) {
        return Err(mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64));
    }
    let path = core::str::from_utf8(path_bytes)
        .map_err(|_| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64))?;
    if !path.starts_with('/') {
        return Err(mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64));
    }
    Ok(path.to_string())
}

fn reply_status(sender: u64, result: Result<(), mochi_user_syscall::SysError>) {
    let status = match result {
        Ok(_) => REPLY_OK,
        Err(err) => err.errno().unwrap_or(mochi_user_syscall::EIO),
    };
    let _ = platform::ipc::reply(sender, &status.to_le_bytes());
}

fn run_server() -> ! {
    platform::println!("package.service: ready");
    let endpoint = match platform::ipc::create() {
        Ok(endpoint) => endpoint,
        Err(err) => {
            platform::println!(
                "package.service: endpoint create failed errno={}",
                err.errno().unwrap_or(0)
            );
            platform::process::exit(1);
        }
    };
    let mut buf = [0u8; 512];
    loop {
        let msg = match platform::ipc::wait(endpoint, &mut buf) {
            Ok(msg) => msg,
            Err(_) => {
                platform::thread::yield_now();
                continue;
            }
        };
        let sender = msg >> 32;
        let len = (msg & 0xffff_ffff) as usize;
        let request = parse_install_request(&buf[..len]).and_then(|path| install_package(&path));
        reply_status(sender, request);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn service_main(sp: *const usize) -> ! {
    unsafe {
        let _ = platform::logger::init_from_initial_stack(sp);
    }
    if let Some(mpkg_path) = unsafe { parse_initial_arg(sp) } {
        platform::println!("package.service: start {}", mpkg_path);
        match install_package(&mpkg_path) {
            Ok(_) => {
                platform::println!("package.service: installed {}", mpkg_path);
                platform::process::exit(0);
            }
            Err(err) => {
                platform::println!(
                    "package.service: install failed errno={}",
                    err.errno().unwrap_or(0)
                );
                platform::process::exit(1);
            }
        }
    }

    run_server()
}
