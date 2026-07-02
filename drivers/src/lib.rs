#![no_std]

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::str;

use ed25519_dalek::{Signature, VerifyingKey};
use mochi_user_platform as platform;
use mochi_user_syscall as syscall;
use sha2::{Digest, Sha256};

const SIGNATURE_DB_PATH: &str = "/signature.db";
const DRIVER_BUNDLE_ROOTS: &[&str] = &["/bin/drivers/usb", "/bin/drivers/ps2"];
const INPUT_SERVICE_PATH: &str = "/system/services/input.service";
const INPUT_SERVICE_MANIFEST_PATH: &str = "/system/services/input.service.toml";
const TTY_SERVICE_PATH: &str = "/system/services/tty.service";
const TTY_SERVICE_MANIFEST_PATH: &str = "/system/services/tty.service.toml";
const I8042_DRIVER_ID: &str = "com.mochios.ps2.i8042";

#[derive(Clone, Debug, Default)]
struct BundleManifest {
    package_id: String,
    package_name: String,
    version: String,
    entry: String,
    api_version: u32,
    driver_class: String,
    match_bus: String,
    match_class: String,
    capabilities: Vec<String>,
}

#[derive(Clone)]
struct SignatureRecord {
    path: String,
    digest: [u8; 32],
    signature: [u8; 64],
}

struct SignatureDatabase {
    verifying_key: VerifyingKey,
    records: Vec<SignatureRecord>,
}

fn trim_comment(line: &str) -> &str {
    let mut in_string = false;
    let mut escape = false;
    for (idx, ch) in line.char_indices() {
        match ch {
            '"' if !escape => in_string = !in_string,
            '#' if !in_string => return line[..idx].trim_end(),
            '\\' if !escape => escape = true,
            _ => escape = false,
        }
    }
    line.trim_end()
}

fn split_kv(line: &str) -> Option<(&str, &str)> {
    let (k, v) = line.split_once('=')?;
    Some((k.trim(), v.trim()))
}

fn unquote(value: &str) -> Option<String> {
    let value = value.trim();
    if !value.starts_with('"') || !value.ends_with('"') || value.len() < 2 {
        return None;
    }
    let mut out = String::new();
    let mut chars = value[1..value.len() - 1].chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next()? {
            '"' => out.push('"'),
            '\\' => out.push('\\'),
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            other => out.push(other),
        }
    }
    Some(out)
}

fn parse_u32_like(value: &str) -> Option<u32> {
    let value = if value.trim().starts_with('"') {
        unquote(value)?
    } else {
        value.trim().to_string()
    };
    if let Some(hex) = value.strip_prefix("0x") {
        return u32::from_str_radix(hex, 16).ok();
    }
    if let Some(hex) = value.strip_prefix("0X") {
        return u32::from_str_radix(hex, 16).ok();
    }
    value.parse::<u32>().ok()
}

fn parse_about(text: &str) -> Option<BundleManifest> {
    let mut manifest = BundleManifest::default();
    let mut section = "";
    let mut collecting_caps = false;

    for raw_line in text.lines() {
        let line = trim_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line;
            collecting_caps = false;
            continue;
        }
        let Some((key, value)) = split_kv(line) else {
            if section == "[capabilities]" && collecting_caps {
                collect_capability_line(&mut manifest.capabilities, line);
            }
            continue;
        };
        match section {
            "[driver]" => match key {
                "id" => manifest.package_id = unquote(value).unwrap_or_else(|| value.to_string()),
                "name" => {
                    manifest.package_name = unquote(value).unwrap_or_else(|| value.to_string())
                }
                "version" => manifest.version = unquote(value).unwrap_or_else(|| value.to_string()),
                "entry" => manifest.entry = unquote(value).unwrap_or_else(|| value.to_string()),
                _ => {}
            },
            "[plugkit]" => match key {
                "api" => manifest.api_version = parse_u32_like(value).unwrap_or(1),
                "driver_class" => {
                    manifest.driver_class = unquote(value).unwrap_or_else(|| value.to_string())
                }
                _ => {}
            },
            "[[match]]" => match key {
                "bus" => manifest.match_bus = unquote(value).unwrap_or_else(|| value.to_string()),
                "class" => {
                    manifest.match_class = unquote(value).unwrap_or_else(|| value.to_string())
                }
                _ => {}
            },
            "[capabilities]" => {
                if key == "requires" {
                    collecting_caps = true;
                    collect_capability_line(&mut manifest.capabilities, value);
                }
            }
            _ => {}
        }
    }

    if manifest.package_id.is_empty() {
        return None;
    }
    if manifest.entry.is_empty() {
        manifest.entry = "entry.elf".to_string();
    }
    Some(manifest)
}

fn collect_capability_line(out: &mut Vec<String>, line: &str) {
    for part in line.split(',') {
        let item = part
            .trim()
            .trim_matches(|ch| ch == '[' || ch == ']' || ch == '"');
        if !item.is_empty() {
            out.push(item.to_string());
        }
    }
}

fn parse_capability_requires(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_caps = false;
    let mut collecting = false;

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            in_caps = line == "[capabilities]";
            collecting = false;
            continue;
        }
        if !in_caps {
            continue;
        }
        let Some((key, value)) = split_kv(line) else {
            if collecting {
                collect_capability_line(&mut out, line);
            }
            continue;
        };
        if key == "requires" {
            collecting = true;
            collect_capability_line(&mut out, value);
        }
    }

    out
}

fn hex_val(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn decode_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    let bytes = text.as_bytes();
    if bytes.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    let mut idx = 0usize;
    while idx < N {
        let hi = hex_val(bytes[idx * 2])?;
        let lo = hex_val(bytes[idx * 2 + 1])?;
        out[idx] = (hi << 4) | lo;
        idx += 1;
    }
    Some(out)
}

fn parse_signature_db(bytes: &[u8]) -> Option<SignatureDatabase> {
    let text = str::from_utf8(bytes).ok()?;
    let mut lines = text.lines();
    let header = lines.next()?.trim();
    if header != "mnu-signature-db v1" {
        return None;
    }

    let pubkey_line = lines.next()?.trim();
    let pubkey_hex = pubkey_line.strip_prefix("pubkey ")?;
    let pubkey = decode_hex::<32>(pubkey_hex)?;
    let verifying_key = VerifyingKey::from_bytes(&pubkey).ok()?;

    let mut records = Vec::new();
    for line in lines {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some(rest) = line.strip_prefix("record ") else {
            return None;
        };
        let mut parts = rest.split_whitespace();
        let path = parts.next()?.to_string();
        let digest_hex = parts.next()?;
        let sig_hex = parts.next()?;
        if parts.next().is_some() {
            return None;
        }
        records.push(SignatureRecord {
            path,
            digest: decode_hex::<32>(digest_hex)?,
            signature: decode_hex::<64>(sig_hex)?,
        });
    }

    Some(SignatureDatabase {
        verifying_key,
        records,
    })
}

fn open_path(path: &str) -> Option<u64> {
    platform::file::open_path(path, 0).ok()
}

fn read_text_file(path: &str) -> Option<String> {
    let bytes = read_file_bytes(path)?;
    String::from_utf8(bytes).ok()
}

fn read_file_bytes(path: &str) -> Option<Vec<u8>> {
    let fd = open_path(path)?;
    let mut data = Vec::new();
    let mut buf = Vec::with_capacity(512);
    buf.resize(512, 0);
    loop {
        let read = platform::file::read(fd, buf.as_mut_ptr() as u64, buf.len() as u64).ok()?;
        if read == 0 {
            break;
        }
        let n = read as usize;
        data.extend_from_slice(&buf[..n]);
        if n < buf.len() {
            break;
        }
    }
    let _ = platform::file::close(fd);
    Some(data)
}

fn read_dir_names(path: &str) -> Vec<String> {
    let mut out = Vec::new();
    let Some(fd) = open_path(path) else {
        platform::println!("drivers.service: open dir failed {}", path);
        return out;
    };
    let mut buf = [0u8; 4096];
    loop {
        let read = syscall::call3(
            syscall::SyscallNumber::FileReadDir,
            fd,
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
        );
        let Ok(read) = read else {
            platform::println!("drivers.service: readdir error fd={}", fd);
            break;
        };
        if read == 0 {
            break;
        }
        let bytes = &buf[..read as usize];
        for raw in bytes.split(|&b| b == 0 || b == b'\n') {
            if raw.is_empty() {
                continue;
            }
            if let Ok(name) = core::str::from_utf8(raw) {
                let name = name.trim_matches(|ch: char| ch.is_ascii_control() || ch.is_ascii_whitespace());
                if !name.is_empty() {
                    out.push(name.to_string());
                }
            }
        }
        if (read as usize) < buf.len() {
            break;
        }
    }
    let _ = platform::file::close(fd);
    out
}

fn verify_bundle(entry_path: &str) -> bool {
    let Some(db_bytes) = read_text_file(SIGNATURE_DB_PATH) else {
        platform::println!("drivers.service: missing signature db");
        return false;
    };
    let Some(db) = parse_signature_db(db_bytes.as_bytes()) else {
        platform::println!("drivers.service: invalid signature db");
        return false;
    };

    let Some(bytes) = read_file_bytes(entry_path) else {
        platform::println!("drivers.service: missing entry {}", entry_path);
        return false;
    };
    let digest = Sha256::digest(bytes.as_slice());
    let mut digest_bytes = [0u8; 32];
    digest_bytes.copy_from_slice(&digest);

    for record in &db.records {
        if record.path != entry_path || record.digest != digest_bytes {
            continue;
        }
        let signature = Signature::from_bytes(&record.signature);
        let mut msg = Vec::with_capacity(32 + entry_path.len() + 1 + digest_bytes.len());
        msg.extend_from_slice(b"mnu-signature-v1\0");
        msg.extend_from_slice(entry_path.as_bytes());
        msg.push(0);
        msg.extend_from_slice(&digest_bytes);
        if db.verifying_key.verify_strict(&msg, &signature).is_ok() {
            return true;
        }
    }

    platform::println!("drivers.service: signature verification failed for {}", entry_path);
    false
}

fn encode_nul_list(items: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    for item in items {
        out.extend_from_slice(item.as_bytes());
        out.push(0);
    }
    out
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

fn spawn_bundle(
    entry_path: &str,
    args: Option<&[u8]>,
    capabilities: &[String],
    logger_endpoint: u64,
) -> Option<u64> {
    let caps_nul = encode_nul_list(capabilities);
    let mut spawn_args = Vec::new();
    if let Some(args) = args {
        let text = core::str::from_utf8(args).ok()?;
        for part in text.split('\0') {
            if !part.is_empty() {
                spawn_args.push(part.to_string());
            }
        }
    }
    if logger_endpoint != 0 {
        spawn_args.push(logger_endpoint.to_string());
    }
    let args_nul = encode_spawn_args(&spawn_args);
    platform::service::spawn_manifest(
        entry_path,
        platform::service::ROLE_DRIVER,
        Some(args_nul.as_slice()),
        Some(caps_nul.as_slice()),
    )
        .ok()
}

fn spawn_input_service(
    raw_endpoint_handle: u64,
    control_endpoint_handle: u64,
    logger_endpoint: u64,
) -> Option<u64> {
    let manifest_text = read_text_file(INPUT_SERVICE_MANIFEST_PATH)?;
    let caps = parse_capability_requires(&manifest_text);
    let args = vec![
        raw_endpoint_handle.to_string(),
        control_endpoint_handle.to_string(),
        logger_endpoint.to_string(),
    ];
    let args_nul = encode_spawn_args(&args);
    let caps_nul = encode_nul_list(&caps);
    platform::service::spawn_manifest(
        INPUT_SERVICE_PATH,
        platform::service::ROLE_SERVICE,
        Some(args_nul.as_slice()),
        Some(caps_nul.as_slice()),
    )
    .ok()
}

fn spawn_tty_service(control_endpoint_handle: u64, logger_endpoint: u64) -> Option<u64> {
    let manifest_text = read_text_file(TTY_SERVICE_MANIFEST_PATH)?;
    let caps = parse_capability_requires(&manifest_text);
    let args = vec![control_endpoint_handle.to_string(), logger_endpoint.to_string()];
    let args_nul = encode_spawn_args(&args);
    let caps_nul = encode_nul_list(&caps);
    platform::service::spawn_manifest(
        TTY_SERVICE_PATH,
        platform::service::ROLE_SERVICE,
        Some(args_nul.as_slice()),
        Some(caps_nul.as_slice()),
    )
        .ok()
}

fn maybe_spawn_bundle(bundle_root: &str, raw_input_endpoint_handle: u64, logger_endpoint: u64) {
    let about_path = alloc::format!("{}/about.toml", bundle_root);
    let Some(about_text) = read_text_file(&about_path) else {
        platform::println!("drivers.service: missing {}", about_path);
        return;
    };
    let Some(manifest) = parse_about(&about_text) else {
        platform::println!("drivers.service: invalid {}", about_path);
        return;
    };
    let entry_path = if manifest.entry.starts_with('/') {
        manifest.entry.clone()
    } else {
        alloc::format!("{}/{}", bundle_root, manifest.entry)
    };

    platform::println!(
        "drivers.service: bundle {} {} api={} class={} match={}/{}",
        manifest.package_id,
        manifest.package_name,
        manifest.api_version,
        manifest.driver_class,
        manifest.match_bus,
        manifest.match_class
    );

    if !verify_bundle(&entry_path) {
        return;
    }
    platform::println!("drivers.service: bundle verified {}", entry_path);
    let args = if manifest.package_id == I8042_DRIVER_ID && raw_input_endpoint_handle != 0 {
        let args = vec![raw_input_endpoint_handle.to_string()];
        Some(encode_spawn_args(&args))
    } else {
        None
    };
    match spawn_bundle(
        &entry_path,
        args.as_deref(),
        &manifest.capabilities,
        logger_endpoint,
    ) {
        Some(pid) => {
            platform::println!("drivers.service: spawned driver pid={}", pid);
        }
        None => {
            platform::println!("drivers.service: spawn failed {}", entry_path);
        }
    }
}

pub fn run(sp: *const usize) -> ! {
    unsafe {
        let _ = platform::logger::init_from_initial_stack(sp);
    }
    platform::println!("drivers.service: start");
    let raw_input_endpoint_handle = platform::ipc::create().ok().unwrap_or(0);
    let input_control_endpoint_handle = platform::ipc::create().ok().unwrap_or(0);
    let logger_endpoint = platform::logger::endpoint().unwrap_or(0);
    if raw_input_endpoint_handle != 0 && input_control_endpoint_handle != 0 {
        match spawn_input_service(
            raw_input_endpoint_handle,
            input_control_endpoint_handle,
            logger_endpoint,
        ) {
            Some(pid) => platform::println!("drivers.service: input.service spawned pid={}", pid),
            None => platform::println!("drivers.service: input.service spawn failed"),
        }
        match spawn_tty_service(input_control_endpoint_handle, logger_endpoint) {
            Some(pid) => platform::println!("drivers.service: tty.service spawned pid={}", pid),
            None => platform::println!("drivers.service: tty.service spawn failed"),
        }
    } else {
        platform::println!("drivers.service: input endpoint create failed");
    }
    for bundle_root_path in DRIVER_BUNDLE_ROOTS {
        let bundle_roots = read_dir_names(bundle_root_path);
        for bundle in bundle_roots {
            if !bundle.ends_with(".driver") {
                continue;
            }
            let bundle_root = alloc::format!("{}/{}", bundle_root_path, bundle);
            maybe_spawn_bundle(&bundle_root, raw_input_endpoint_handle, logger_endpoint);
        }
    }

    loop {
        platform::thread::yield_now();
    }
}
