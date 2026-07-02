#![no_std]
#![no_main]

extern crate alloc;

use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::arch::global_asm;
use core::convert::TryInto;
use ed25519_dalek::{Signature, VerifyingKey};
use mochi_user_platform as platform;
use sha2::{Digest, Sha256};

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

const VERIFY_PACKAGE_OPCODE: u32 = 0x5645_5246;
const REPLY_OK: u64 = 0;

#[derive(Clone)]
struct MpkgHeader {
    header_size: usize,
    compression: u8,
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
    for seg in path.split('/') {
        if seg.is_empty() || seg == "." || seg == ".." {
            return false;
        }
    }
    !path.ends_with('/')
}

fn parse_header(bytes: &[u8]) -> Option<MpkgHeader> {
    if bytes.len() < 32 || &bytes[..4] != b"MPKG" {
        return None;
    }
    let major = u16::from_le_bytes([bytes[4], bytes[5]]);
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
        entries.push(TarEntry {
            path,
            kind,
            data: bytes[payload_start..payload_end].to_vec(),
        });
        offset = payload_end.div_ceil(512) * 512;
    }
    Some(entries)
}

fn entry_by_path<'a>(entries: &'a [TarEntry], path: &str) -> Option<&'a TarEntry> {
    entries.iter().find(|entry| entry.path == path)
}

fn decode_cert(bytes: &[u8]) -> Option<VerifyingKey> {
    if bytes.len() == 32 {
        let mut key = [0u8; 32];
        key.copy_from_slice(bytes);
        return VerifyingKey::from_bytes(&key).ok();
    }
    let text = core::str::from_utf8(bytes).ok()?.trim();
    if text.len() != 64 {
        return None;
    }
    let mut key = [0u8; 32];
    for idx in 0..32 {
        let hi = u8::from_str_radix(&text[idx * 2..idx * 2 + 1], 16).ok()?;
        let lo = u8::from_str_radix(&text[idx * 2 + 1..idx * 2 + 2], 16).ok()?;
        key[idx] = (hi << 4) | lo;
    }
    VerifyingKey::from_bytes(&key).ok()
}

fn decode_sha256_digest(text: &str) -> Option<[u8; 32]> {
    let hex = text.strip_prefix("sha256:")?;
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for idx in 0..32 {
        let hi = u8::from_str_radix(&hex[idx * 2..idx * 2 + 1], 16).ok()?;
        let lo = u8::from_str_radix(&hex[idx * 2 + 1..idx * 2 + 2], 16).ok()?;
        out[idx] = (hi << 4) | lo;
    }
    Some(out)
}

fn manifest_payload_path(kind: Option<&str>, path: &str) -> Option<String> {
    if path.starts_with('/') {
        return Some(alloc::format!("payload/root{}", path));
    }
    let rel = path.strip_prefix("$/")?;
    match kind {
        Some("application") => Some(alloc::format!("payload/bundle/{}", rel)),
        None | Some("binary") => Some(alloc::format!("payload/root/bin/{}", rel)),
        _ => None,
    }
}

fn verify_payload_files(
    manifest: &platform::package::PackageManifest,
    entries: &[TarEntry],
) -> Result<(), mochi_user_syscall::SysError> {
    if manifest.files.is_empty() {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EINVAL as i64,
        ));
    }

    let mut expected_paths = Vec::new();
    for file in &manifest.files {
        let payload_path = manifest_payload_path(manifest.package_kind.as_deref(), &file.path)
            .ok_or_else(|| {
                mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64)
            })?;
        let entry = entry_by_path(entries, &payload_path).ok_or_else(|| {
            mochi_user_syscall::SysError::from_raw(mochi_user_syscall::ENOENT as i64)
        })?;
        if entry.kind != b'0' && entry.kind != 0 {
            return Err(mochi_user_syscall::SysError::from_raw(
                mochi_user_syscall::EINVAL as i64,
            ));
        }
        if entry.data.len() as u64 != file.size {
            return Err(mochi_user_syscall::SysError::from_raw(
                mochi_user_syscall::EINVAL as i64,
            ));
        }
        let expected = decode_sha256_digest(&file.digest).ok_or_else(|| {
            mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64)
        })?;
        let actual = Sha256::digest(&entry.data);
        if actual.as_slice() != expected {
            return Err(mochi_user_syscall::SysError::from_raw(
                mochi_user_syscall::EACCES as i64,
            ));
        }
        expected_paths.push(payload_path);
    }

    for entry in entries {
        if !entry.path.starts_with("payload/") || entry.kind == b'5' {
            continue;
        }
        if !expected_paths.iter().any(|path| path == &entry.path) {
            return Err(mochi_user_syscall::SysError::from_raw(
                mochi_user_syscall::EINVAL as i64,
            ));
        }
    }
    Ok(())
}

fn verify_package(mpkg_path: &str) -> Result<(), mochi_user_syscall::SysError> {
    let bytes = platform::file::read_to_end_path(mpkg_path)?;
    let header = parse_header(&bytes)
        .ok_or_else(|| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64))?;
    if header.compression != 0 {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::ENOTSUP as i64,
        ));
    }
    let tar = bytes
        .get(header.header_size..)
        .ok_or_else(|| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64))?;
    if tar.len() != header.expanded_size {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EINVAL as i64,
        ));
    }
    let entries = parse_tar_stream(tar)
        .ok_or_else(|| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64))?;
    let manifest = entry_by_path(&entries, "manifest.toml")
        .ok_or_else(|| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::ENOENT as i64))?;
    let sig = entry_by_path(&entries, "signatures/manifest.sig")
        .ok_or_else(|| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::ENOENT as i64))?;
    let cert = entry_by_path(&entries, "signatures/developer.cert")
        .ok_or_else(|| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::ENOENT as i64))?;
    let manifest_text = core::str::from_utf8(&manifest.data)
        .map_err(|_| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64))?;
    let manifest = platform::package::parse_manifest(manifest_text)
        .ok_or_else(|| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64))?;
    match manifest.package_kind.as_deref() {
        None | Some("binary") | Some("application") => {}
        _ => {
            return Err(mochi_user_syscall::SysError::from_raw(
                mochi_user_syscall::EINVAL as i64,
            ));
        }
    }
    if manifest.package_id.is_empty() {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EINVAL as i64,
        ));
    }
    let verifier = decode_cert(&cert.data)
        .ok_or_else(|| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64))?;
    let signature_bytes: [u8; 64] =
        sig.data.as_slice().try_into().map_err(|_| {
            mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64)
        })?;
    let signature = Signature::from_bytes(&signature_bytes);
    let digest = Sha256::digest(manifest_text.as_bytes());
    let mut msg = Vec::with_capacity(32 + digest.len());
    msg.extend_from_slice(b"mochios-mpkg-manifest-v1\0");
    msg.extend_from_slice(&digest);
    verifier
        .verify_strict(&msg, &signature)
        .map_err(|_| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EACCES as i64))?;
    verify_payload_files(&manifest, &entries)?;
    Ok(())
}

fn parse_verify_request(buf: &[u8]) -> Result<String, mochi_user_syscall::SysError> {
    if buf.len() < 4 {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EINVAL as i64,
        ));
    }
    let opcode = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if opcode != VERIFY_PACKAGE_OPCODE {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EINVAL as i64,
        ));
    }
    let path_bytes = &buf[4..];
    if path_bytes.is_empty() || path_bytes.contains(&0) {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EINVAL as i64,
        ));
    }
    let path = core::str::from_utf8(path_bytes)
        .map_err(|_| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64))?;
    if !path.starts_with('/') {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EINVAL as i64,
        ));
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
    platform::println!("signature.service: ready");
    let endpoint = match platform::ipc::create() {
        Ok(endpoint) => endpoint,
        Err(err) => {
            platform::println!(
                "signature.service: endpoint create failed errno={}",
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
        let result = parse_verify_request(&buf[..len]).and_then(|path| verify_package(&path));
        reply_status(sender, result);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn service_main(sp: *const usize) -> ! {
    unsafe {
        let _ = platform::logger::init_from_initial_stack(sp);
    }
    let Some(mpkg_path) = (unsafe { parse_initial_arg(sp) }) else {
        run_server();
    };

    platform::println!("signature.service: start {}", mpkg_path);
    match verify_package(&mpkg_path) {
        Ok(_) => {
            platform::println!("signature.service: verified {}", mpkg_path);
            platform::process::exit(0);
        }
        Err(err) => {
            platform::println!(
                "signature.service: verify failed errno={}",
                err.errno().unwrap_or(0)
            );
            platform::process::exit(1);
        }
    }
}
