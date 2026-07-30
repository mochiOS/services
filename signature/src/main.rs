extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::convert::TryInto;
use ed25519_dalek::{Signature, VerifyingKey};
use mochi_user_platform as platform;
use mochios_certificate::DeveloperCertificate;
use mochios_signature_protocol::{
    ErrorResponse, Opcode, StatusResponse, UpdateNotification, VerifiedResponse, VerifyBegin,
    VerifyChunk, VerifyFinish, decode_opcode,
};
use sha2::{Digest, Sha256};

use signature::database::{ActiveDatabase, DatabaseError};

const MAX_PACKAGE_LEN: usize = 256 * 1024 * 1024;
const IPC_BUFFER_LEN: usize = 4128;
const PACKAGE_VERIFY_CAPABILITY: &str = "package.install";
const DATABASE_UPDATE_CAPABILITY: &str = "signature.db.write";

include!(concat!(env!("OUT_DIR"), "/trust_anchor.rs"));

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

struct Verification {
    developer_id: String,
    certificate_serial: u64,
    subject_key_id: [u8; 32],
    verified_package_id: String,
    allowed_capabilities: Vec<String>,
    manifest_digest: [u8; 32],
    package_digest: [u8; 32],
}

struct Transfer {
    sender: u64,
    request_id: u64,
    expected_len: usize,
    expected_digest: [u8; 32],
    bytes: Vec<u8>,
}

fn diagnostic(message: &str) {
    platform::println!("{}", message);
    let _ = platform::io::stderr(message.as_bytes());
    let _ = platform::io::stderr(b"\n");
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

fn tar_header_checksum(block: &[u8]) -> u64 {
    block
        .iter()
        .enumerate()
        .map(|(index, byte)| {
            if (148..156).contains(&index) {
                u64::from(b' ')
            } else {
                u64::from(*byte)
            }
        })
        .sum()
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
    let minor = u16::from_le_bytes([bytes[6], bytes[7]]);
    let header_size = u16::from_le_bytes([bytes[8], bytes[9]]) as usize;
    let compression = bytes[10];
    let flags = bytes[11];
    let expanded_size = u64::from_le_bytes([
        bytes[12], bytes[13], bytes[14], bytes[15], bytes[16], bytes[17], bytes[18], bytes[19],
    ]) as usize;
    if major != 1 || minor != 0 || header_size != 32 || flags != 0 || compression > 1 {
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
            return if bytes[offset..].iter().all(|&b| b == 0) {
                Some(entries)
            } else {
                None
            };
        }
        if &block[257..263] != b"ustar\0" || &block[263..265] != b"00" {
            return None;
        }
        let expected_checksum = parse_octal(&block[148..156])? as u64;
        if expected_checksum != tar_header_checksum(block) {
            return None;
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
    if offset != bytes.len() && bytes[offset..].iter().any(|&b| b != 0) {
        return None;
    }
    Some(entries)
}

fn entry_by_path<'a>(entries: &'a [TarEntry], path: &str) -> Option<&'a TarEntry> {
    entries.iter().find(|entry| entry.path == path)
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

fn verify_package(
    mpkg_path: &str,
    database: &ActiveDatabase,
    now_utc: u64,
) -> Result<Verification, mochi_user_syscall::SysError> {
    let bytes = platform::file::read_to_end_path(mpkg_path)?;
    verify_package_bytes(&bytes, database, now_utc)
}

fn verify_package_bytes(
    bytes: &[u8],
    database: &ActiveDatabase,
    now_utc: u64,
) -> Result<Verification, mochi_user_syscall::SysError> {
    let header = parse_header(bytes)
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
    if entries.iter().any(|entry| {
        entry.path.starts_with("signatures/chain/")
            || (entry.path.starts_with("signatures/")
                && entry.path != "signatures/manifest.sig"
                && entry.path != "signatures/developer.cert")
    }) {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EINVAL as i64,
        ));
    }
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
    let certificate = DeveloperCertificate::decode(&cert.data)
        .map_err(|_| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64))?;
    let issuer_public_key = database
        .issuer_public_key(&certificate, now_utc)
        .map_err(database_verify_error)?;
    certificate
        .verify(&issuer_public_key, now_utc, &manifest.package_id)
        .map_err(|_| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EACCES as i64))?;
    let verifier = VerifyingKey::from_bytes(&certificate.subject_public_key)
        .map_err(|_| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64))?;
    let signature_bytes: [u8; 64] =
        sig.data.as_slice().try_into().map_err(|_| {
            mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64)
        })?;
    let signature = Signature::from_bytes(&signature_bytes);
    let manifest_hash = Sha256::digest(manifest_text.as_bytes());
    let mut msg = Vec::with_capacity(32 + manifest_hash.len());
    msg.extend_from_slice(b"mochios-mpkg-manifest-v1\0");
    msg.extend_from_slice(&manifest_hash);
    verifier
        .verify_strict(&msg, &signature)
        .map_err(|_| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EACCES as i64))?;
    verify_payload_files(&manifest, &entries)?;
    let mut manifest_digest = [0; 32];
    manifest_digest.copy_from_slice(&manifest_hash);
    let mut package_digest = [0; 32];
    package_digest.copy_from_slice(&Sha256::digest(bytes));
    Ok(Verification {
        developer_id: certificate.developer_id,
        certificate_serial: certificate.serial_number,
        subject_key_id: certificate.subject_key_id,
        verified_package_id: manifest.package_id,
        allowed_capabilities: certificate.allowed_capabilities,
        manifest_digest,
        package_digest,
    })
}

fn database_verify_error(error: DatabaseError) -> mochi_user_syscall::SysError {
    let errno = match error {
        DatabaseError::Expired
        | DatabaseError::MissingTrust
        | DatabaseError::MissingRevocations => mochi_user_syscall::EAGAIN,
        _ => mochi_user_syscall::EACCES,
    };
    mochi_user_syscall::SysError::from_raw(errno as i64)
}

fn reply_transfer_status(sender: u64, request_id: u64, status: i32) {
    let mut buffer = [0; mochios_signature_protocol::ERROR_LEN];
    let response = StatusResponse { request_id, status };
    if let Ok(length) = response.encode(&mut buffer) {
        let _ = platform::ipc::reply(sender, &buffer[..length]);
    }
}

fn reply_error(sender: u64, request_id: u64, status: u64) {
    let raw_status = status as i64;
    let status = if raw_status > 0 {
        -(raw_status as i32)
    } else {
        raw_status as i32
    };
    diagnostic(&alloc::format!(
        "signature.service: request failed id={} status={}",
        request_id,
        status
    ));
    let mut buffer = [0; mochios_signature_protocol::ERROR_LEN];
    let response = ErrorResponse { request_id, status };
    if let Ok(length) = response.encode(&mut buffer) {
        let _ = platform::ipc::reply(sender, &buffer[..length]);
    }
}

fn reply_verified(sender: u64, request_id: u64, verification: &Verification) {
    let mut capabilities = Vec::new();
    if capabilities
        .try_reserve_exact(verification.allowed_capabilities.len())
        .is_err()
    {
        reply_error(sender, request_id, mochi_user_syscall::ENOMEM);
        return;
    }
    capabilities.extend(verification.allowed_capabilities.iter().map(String::as_str));
    let response = VerifiedResponse {
        request_id,
        certificate_serial: verification.certificate_serial,
        subject_key_id: verification.subject_key_id,
        manifest_digest: verification.manifest_digest,
        package_digest: verification.package_digest,
        developer_id: &verification.developer_id,
        verified_package_id: &verification.verified_package_id,
        allowed_capabilities: &capabilities,
    };
    let mut buffer = [0; IPC_BUFFER_LEN];
    match response.encode(&mut buffer) {
        Ok(length) => {
            let _ = platform::ipc::reply(sender, &buffer[..length]);
        }
        Err(_) => reply_error(sender, request_id, mochi_user_syscall::ERANGE),
    }
}

fn run_server() -> ! {
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
    let mut database = load_active_database();
    platform::println!("signature.service: ready");
    let mut transfer: Option<Transfer> = None;
    let mut buf = [0u8; IPC_BUFFER_LEN];
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
        let request = &buf[..len];
        if matches!(
            decode_opcode(request),
            Ok(Opcode::TrustUpdated | Opcode::RevocationsUpdated)
        ) {
            handle_update_notification(sender, request, &mut database);
            continue;
        }
        if platform::capability::check_thread(sender, PACKAGE_VERIFY_CAPABILITY) != Ok(1) {
            reply_error(sender, 0, mochi_user_syscall::EACCES);
            continue;
        }
        match decode_opcode(request) {
            Ok(Opcode::VerifyBegin) => match VerifyBegin::decode(request) {
                Ok(begin) => {
                    let expected_len = usize::try_from(begin.package_len).unwrap_or(usize::MAX);
                    if expected_len == 0 || expected_len > MAX_PACKAGE_LEN {
                        reply_error(sender, begin.request_id, mochi_user_syscall::ERANGE);
                        continue;
                    }
                    let mut bytes = Vec::new();
                    if bytes.try_reserve_exact(expected_len).is_err() {
                        reply_error(sender, begin.request_id, mochi_user_syscall::ENOMEM);
                        continue;
                    }
                    transfer = Some(Transfer {
                        sender,
                        request_id: begin.request_id,
                        expected_len,
                        expected_digest: begin.package_digest,
                        bytes,
                    });
                    reply_transfer_status(sender, begin.request_id, 0);
                }
                Err(_) => reply_error(sender, 0, mochi_user_syscall::EINVAL),
            },
            Ok(Opcode::VerifyChunk) => match VerifyChunk::decode(request) {
                Ok(chunk) => {
                    let Some(active) = transfer.as_mut() else {
                        reply_error(sender, chunk.request_id, mochi_user_syscall::EINVAL);
                        continue;
                    };
                    let offset = usize::try_from(chunk.offset).unwrap_or(usize::MAX);
                    let valid = active.sender == sender
                        && active.request_id == chunk.request_id
                        && offset == active.bytes.len()
                        && active
                            .bytes
                            .len()
                            .checked_add(chunk.bytes.len())
                            .is_some_and(|length| length <= active.expected_len);
                    if !valid {
                        transfer = None;
                        reply_error(sender, chunk.request_id, mochi_user_syscall::EINVAL);
                        continue;
                    }
                    active.bytes.extend_from_slice(chunk.bytes);
                    reply_transfer_status(sender, chunk.request_id, 0);
                }
                Err(_) => reply_error(sender, 0, mochi_user_syscall::EINVAL),
            },
            Ok(Opcode::VerifyFinish) => match VerifyFinish::decode(request) {
                Ok(finish) => {
                    let Some(active) = transfer.take() else {
                        reply_error(sender, finish.request_id, mochi_user_syscall::EINVAL);
                        continue;
                    };
                    if active.sender != sender
                        || active.request_id != finish.request_id
                        || active.bytes.len() != active.expected_len
                        || Sha256::digest(&active.bytes).as_slice() != active.expected_digest
                    {
                        reply_error(sender, finish.request_id, mochi_user_syscall::EACCES);
                        continue;
                    }
                    let Some(database) = database.as_ref() else {
                        reply_error(sender, finish.request_id, mochi_user_syscall::EAGAIN);
                        continue;
                    };
                    let now_utc = match platform::time::utc_seconds() {
                        Ok(now) => now,
                        Err(_) => {
                            reply_error(sender, finish.request_id, mochi_user_syscall::EAGAIN);
                            continue;
                        }
                    };
                    match verify_package_bytes(&active.bytes, database, now_utc) {
                        Ok(verification) => {
                            reply_verified(sender, finish.request_id, &verification)
                        }
                        Err(error) => reply_error(sender, finish.request_id, error.raw() as u64),
                    }
                }
                Err(_) => reply_error(sender, 0, mochi_user_syscall::EINVAL),
            },
            _ => reply_error(sender, 0, mochi_user_syscall::EINVAL),
        }
    }
}

fn load_active_database() -> Option<ActiveDatabase> {
    match ActiveDatabase::load(ROOT_PUBLIC_KEYS) {
        Ok(database) => {
            let state = database.state();
            platform::println!(
                "signature.service: certificate database trust={} revocations={} generation={} recovered={}",
                state.trust.snapshot_version,
                state.revocations.snapshot_version,
                state.generation,
                database.recovered()
            );
            Some(database)
        }
        Err(error) => {
            diagnostic(&alloc::format!(
                "signature.service: certificate database unavailable error={error:?}"
            ));
            None
        }
    }
}

fn handle_update_notification(sender: u64, request: &[u8], database: &mut Option<ActiveDatabase>) {
    if platform::capability::check_thread(sender, DATABASE_UPDATE_CAPABILITY) != Ok(1) {
        platform::println!("signature.service: update notification denied");
        return;
    }
    let notification = match UpdateNotification::decode(request) {
        Ok(notification) => notification,
        Err(error) => {
            platform::println!(
                "signature.service: invalid update notification error={:?}",
                error
            );
            return;
        }
    };
    let Some(reloaded) = load_active_database() else {
        platform::println!("signature.service: update reload rejected");
        return;
    };
    let state = reloaded.state();
    let generation = state.generation;
    let snapshot_version = match notification.opcode {
        Opcode::TrustUpdated => state.trust.snapshot_version,
        Opcode::RevocationsUpdated => state.revocations.snapshot_version,
        _ => return,
    };
    if generation < notification.generation || snapshot_version < notification.snapshot_version {
        platform::println!(
            "signature.service: update notification state mismatch opcode={:?}",
            notification.opcode
        );
        return;
    }
    *database = Some(reloaded);
    platform::println!(
        "signature.service: certificate database reloaded opcode={:?} version={} generation={}",
        notification.opcode,
        snapshot_version,
        generation
    );
}

fn main() {
    let mut mpkg_path = None;
    for argument in std::env::args().skip(1) {
        if let Ok(endpoint) = argument.parse::<u64>() {
            platform::logger::init(endpoint);
        } else if !argument.is_empty() && mpkg_path.is_none() {
            mpkg_path = Some(argument);
        }
    }
    platform::println!("signature.service: trust domain {}", TRUST_DOMAIN);
    let Some(mpkg_path) = mpkg_path else {
        run_server();
    };

    platform::println!("signature.service: start {}", mpkg_path);
    let Some(database) = load_active_database() else {
        platform::println!(
            "signature.service: verify failed errno={}",
            mochi_user_syscall::EAGAIN
        );
        platform::process::exit(1);
    };
    let now_utc = match platform::time::utc_seconds() {
        Ok(now) => now,
        Err(_) => {
            platform::println!(
                "signature.service: verify failed errno={}",
                mochi_user_syscall::EAGAIN
            );
            platform::process::exit(1);
        }
    };
    match verify_package(&mpkg_path, &database, now_utc) {
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
