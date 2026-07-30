extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use mochi_user_platform as platform;
use mochios_signature_protocol::{
    ErrorResponse, Opcode, StatusResponse, VerifiedResponse, VerifiedView, VerifyBegin,
    VerifyChunk, VerifyFinish, decode_opcode,
};
use sha2::{Digest, Sha256};

const SIG_SERVICE_NAME: &str = "signature.service";
const INSTALL_REQUEST_OPCODE: u32 = 0x494e_5354;
const REPLY_OK: u64 = 0;
const O_WRONLY: u64 = 0o1;
const O_CREAT: u64 = 0o100;
const O_EXCL: u64 = 0o200;
const FILE_MODE_644: u64 = 0o644;
const FILE_MODE_755: u64 = 0o755;
const SIGNATURE_CHUNK_LEN: usize = 4096;
const SIGNATURE_REPLY_LEN: usize = 4128;

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

struct VerifiedPackage {
    developer_id: String,
    certificate_serial: u64,
    subject_key_id: [u8; 32],
    verified_package_id: String,
    allowed_capabilities: Vec<String>,
    manifest_digest: [u8; 32],
    package_digest: [u8; 32],
}

fn diagnostic(message: &str) {
    platform::println!("{}", message);
    let _ = platform::io::stderr(message.as_bytes());
    let _ = platform::io::stderr(b"\n");
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

fn parse_initial_arg() -> Option<String> {
    for argument in std::env::args().skip(1) {
        if parse_decimal_u64(argument.as_bytes()).is_some() {
            continue;
        }
        if !argument.is_empty() {
            return Some(argument);
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

fn is_valid_abs_path(path: &str) -> bool {
    path.starts_with('/')
        && !path.contains('\\')
        && !path.contains('\0')
        && !path.contains("//")
        && !path.ends_with('/')
        && path[1..]
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

fn join_path(prefix: &str, suffix: &str) -> String {
    if prefix.is_empty() {
        return suffix.to_string();
    }
    if suffix.is_empty() {
        return prefix.to_string();
    }
    alloc::format!(
        "{}/{}",
        prefix.trim_end_matches('/'),
        suffix.trim_start_matches('/')
    )
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

fn manifest_target_path(kind: Option<&str>, package_name: &str, path: &str) -> Option<String> {
    if path.starts_with('/') {
        return Some(path.to_string());
    }
    let rel = path.strip_prefix("$/")?;
    match kind {
        Some("application") => Some(join_path(
            &alloc::format!("/applications/{}.app", package_name),
            rel,
        )),
        None | Some("binary") => Some(join_path("/bin", rel)),
        _ => None,
    }
}

fn parse_header(bytes: &[u8]) -> Option<MpkgHeader> {
    if bytes.len() < 32 {
        return None;
    }
    if &bytes[..4] != b"MPKG" {
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
    if offset != bytes.len() && bytes[offset..].iter().any(|&b| b != 0) {
        return None;
    }
    Some(entries)
}

fn entry_by_path<'a>(entries: &'a [TarEntry], path: &str) -> Option<&'a TarEntry> {
    entries.iter().find(|entry| entry.path == path)
}

fn verify_with_signature_service(
    package_bytes: &[u8],
    package_digest: &[u8; 32],
) -> Result<VerifiedPackage, mochi_user_syscall::SysError> {
    let service_tid = platform::process::find_by_name(SIG_SERVICE_NAME)?;
    if service_tid == 0 {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::ENOENT as i64,
        ));
    }
    let request_id = platform::time::ticks().unwrap_or(0)
        ^ u64::from_le_bytes(package_digest[..8].try_into().unwrap_or([0; 8]));
    let begin = VerifyBegin {
        request_id,
        package_len: u64::try_from(package_bytes.len()).map_err(|_| {
            mochi_user_syscall::SysError::from_raw(mochi_user_syscall::ERANGE as i64)
        })?,
        package_digest: *package_digest,
    };
    let mut request = [0; SIGNATURE_REPLY_LEN];
    let mut reply = [0; SIGNATURE_REPLY_LEN];
    let begin_len = begin
        .encode(&mut request)
        .map_err(|_| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64))?;
    call_for_status(service_tid, request_id, &request[..begin_len], &mut reply)?;

    let mut offset = 0usize;
    while offset < package_bytes.len() {
        let end = core::cmp::min(offset + SIGNATURE_CHUNK_LEN, package_bytes.len());
        let chunk = VerifyChunk {
            request_id,
            offset: offset as u64,
            bytes: &package_bytes[offset..end],
        };
        let length = chunk.encode(&mut request).map_err(|_| {
            mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64)
        })?;
        call_for_status(service_tid, request_id, &request[..length], &mut reply)?;
        offset = end;
    }

    let finish = VerifyFinish { request_id };
    let finish_len = finish
        .encode(&mut request)
        .map_err(|_| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64))?;
    let message = platform::ipc::call(service_tid, &request[..finish_len], &mut reply)?;
    let reply_len = (message & 0xffff_ffff) as usize;
    let response = reply
        .get(..reply_len)
        .ok_or_else(|| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EIO as i64))?;
    match decode_opcode(response) {
        Ok(Opcode::Verified) => {
            let verified = VerifiedView::decode(response).map_err(|_| {
                mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64)
            })?;
            if verified.request_id != request_id || verified.package_digest != *package_digest {
                return Err(mochi_user_syscall::SysError::from_raw(
                    mochi_user_syscall::EACCES as i64,
                ));
            }
            let mut allowed_capabilities = Vec::new();
            for capability in verified.allowed_capabilities() {
                allowed_capabilities.push(
                    capability
                        .map_err(|_| {
                            mochi_user_syscall::SysError::from_raw(
                                mochi_user_syscall::EINVAL as i64,
                            )
                        })?
                        .to_string(),
                );
            }
            Ok(VerifiedPackage {
                developer_id: verified.developer_id.to_string(),
                certificate_serial: verified.certificate_serial,
                subject_key_id: verified.subject_key_id,
                verified_package_id: verified.verified_package_id.to_string(),
                allowed_capabilities,
                manifest_digest: verified.manifest_digest,
                package_digest: verified.package_digest,
            })
        }
        Ok(Opcode::Error) => {
            let error = ErrorResponse::decode(response).map_err(|_| {
                mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64)
            })?;
            Err(mochi_user_syscall::SysError::from_raw(error.status as i64))
        }
        other => {
            diagnostic(&alloc::format!(
                "package.service: invalid signature finish response len={} opcode={:?}",
                reply_len,
                other
            ));
            Err(mochi_user_syscall::SysError::from_raw(
                mochi_user_syscall::EINVAL as i64,
            ))
        }
    }
}

fn call_for_status(
    service_tid: u64,
    request_id: u64,
    request: &[u8],
    reply: &mut [u8],
) -> Result<(), mochi_user_syscall::SysError> {
    let message = platform::ipc::call(service_tid, request, reply).map_err(|error| {
        diagnostic(&alloc::format!(
            "package.service: signature IPC call failed errno={}",
            error.errno().unwrap_or(0)
        ));
        error
    })?;
    let length = (message & 0xffff_ffff) as usize;
    let response = reply
        .get(..length)
        .ok_or_else(|| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EIO as i64))?;
    match decode_opcode(response) {
        Ok(Opcode::Status) => {
            let status = StatusResponse::decode(response).map_err(|_| {
                mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64)
            })?;
            if status.request_id != request_id || status.status != 0 {
                return Err(mochi_user_syscall::SysError::from_raw(status.status as i64));
            }
            Ok(())
        }
        Ok(Opcode::Error) => {
            let error = ErrorResponse::decode(response).map_err(|_| {
                mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64)
            })?;
            Err(mochi_user_syscall::SysError::from_raw(error.status as i64))
        }
        other => {
            diagnostic(&alloc::format!(
                "package.service: invalid signature status response len={} opcode={:?}",
                length,
                other
            ));
            Err(mochi_user_syscall::SysError::from_raw(
                mochi_user_syscall::EINVAL as i64,
            ))
        }
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
                    Err(err) if err.errno() == Some(mochi_user_syscall::EEXIST.wrapping_neg()) => {}
                    Err(err) => {
                        diagnostic(&alloc::format!(
                            "package.service: parent directory create failed path={} errno={}",
                            current,
                            err.errno().unwrap_or(0)
                        ));
                        return Err(err);
                    }
                }
            }
        }
    }
    let fd = platform::file::openat_path(-100, path, O_WRONLY | O_CREAT | O_EXCL, mode).map_err(
        |error| {
            diagnostic(&alloc::format!(
                "package.service: open for write failed path={} errno={}",
                path,
                error.errno().unwrap_or(0)
            ));
            error
        },
    )?;
    let mut offset = 0usize;
    while offset < data.len() {
        let wrote = match platform::file::write(
            fd,
            data[offset..].as_ptr() as u64,
            (data.len() - offset) as u64,
        ) {
            Ok(wrote) => wrote,
            Err(error) => {
                diagnostic(&alloc::format!(
                    "package.service: write failed path={} offset={} errno={}",
                    path,
                    offset,
                    error.errno().unwrap_or(0)
                ));
                let _ = platform::file::close(fd);
                return Err(error);
            }
        };
        if wrote == 0 {
            diagnostic(&alloc::format!(
                "package.service: zero-byte write path={} offset={} requested={}",
                path,
                offset,
                data.len() - offset
            ));
            break;
        }
        offset += wrote as usize;
    }
    let close_result = platform::file::close(fd);
    if offset != data.len() {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EIO as i64,
        ));
    }
    close_result.map(|_| ())
}

fn rollback_created_files(paths: &[String]) {
    for path in paths.iter().rev() {
        if let Err(error) = platform::file::remove(path) {
            if error.errno() != Some(mochi_user_syscall::ENOENT.wrapping_neg()) {
                diagnostic(&alloc::format!(
                    "package.service: rollback failed path={} errno={}",
                    path,
                    error.errno().unwrap_or(0)
                ));
            }
        }
    }
}

fn require_path_absent(path: &str) -> Result<(), mochi_user_syscall::SysError> {
    match platform::file::open_path(path, 0) {
        Ok(fd) => {
            let _ = platform::file::close(fd);
            Err(mochi_user_syscall::SysError::from_raw(
                mochi_user_syscall::EEXIST as i64,
            ))
        }
        Err(error) if error.errno() == Some(mochi_user_syscall::ENOENT.wrapping_neg()) => Ok(()),
        Err(error) => Err(error),
    }
}

fn install_package(mpkg_path: &str) -> Result<(), mochi_user_syscall::SysError> {
    let bytes = platform::file::read_to_end_path(mpkg_path)?;
    let digest = Sha256::digest(&bytes);
    let mut digest_bytes = [0u8; 32];
    digest_bytes.copy_from_slice(&digest);
    let verification = verify_with_signature_service(&bytes, &digest_bytes)?;

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
    let manifest_entry = entry_by_path(&entries, "manifest.toml")
        .ok_or_else(|| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::ENOENT as i64))?;
    let manifest_text = core::str::from_utf8(&manifest_entry.data)
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
    if verification.verified_package_id != manifest.package_id
        || verification.package_digest != digest_bytes
    {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EACCES as i64,
        ));
    }

    let package_root = alloc::format!("/system/packages/{}", manifest.package_id);
    let manifest_path = alloc::format!("{}/manifest.toml", package_root);
    let verification_path = alloc::format!("{}/verification.bin", package_root);
    let capability_refs = verification
        .allowed_capabilities
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let verification_record = VerifiedResponse {
        request_id: 0,
        certificate_serial: verification.certificate_serial,
        subject_key_id: verification.subject_key_id,
        manifest_digest: verification.manifest_digest,
        package_digest: verification.package_digest,
        developer_id: &verification.developer_id,
        verified_package_id: &verification.verified_package_id,
        allowed_capabilities: &capability_refs,
    };
    let mut verification_bytes = Vec::new();
    verification_bytes
        .try_reserve_exact(verification_record.encoded_len())
        .map_err(|_| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::ENOMEM as i64))?;
    verification_bytes.resize(verification_record.encoded_len(), 0);
    verification_record
        .encode(&mut verification_bytes)
        .map_err(|_| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64))?;
    if manifest.files.is_empty() {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EINVAL as i64,
        ));
    }

    let mut installed_payloads = Vec::new();
    let mut install_files = Vec::new();
    for file in &manifest.files {
        let payload_path = manifest_payload_path(manifest.package_kind.as_deref(), &file.path)
            .ok_or_else(|| {
                mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64)
            })?;
        let target = manifest_target_path(
            manifest.package_kind.as_deref(),
            &manifest.package_name,
            &file.path,
        )
        .ok_or_else(|| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64))?;
        let entry = entry_by_path(&entries, &payload_path).ok_or_else(|| {
            mochi_user_syscall::SysError::from_raw(mochi_user_syscall::ENOENT as i64)
        })?;
        if entry.kind != b'0' && entry.kind != 0 {
            return Err(mochi_user_syscall::SysError::from_raw(
                mochi_user_syscall::EINVAL as i64,
            ));
        }
        if !is_valid_abs_path(&target) {
            return Err(mochi_user_syscall::SysError::from_raw(
                mochi_user_syscall::EINVAL as i64,
            ));
        }
        let allowed = target.starts_with("/bin/")
            || target.starts_with("/libraries/")
            || target.starts_with("/binary/services/")
            || target.starts_with("/binary/resources/")
            || target.starts_with("/system/services/")
            || (target.starts_with("/applications/")
                && manifest.package_kind.as_deref() == Some("application"));
        if !allowed {
            return Err(mochi_user_syscall::SysError::from_raw(
                mochi_user_syscall::EINVAL as i64,
            ));
        }
        if file.mode & !0o777 != 0 {
            return Err(mochi_user_syscall::SysError::from_raw(
                mochi_user_syscall::EINVAL as i64,
            ));
        }
        installed_payloads.push(payload_path.clone());
        install_files.push((target, entry.data.as_slice(), file.mode as u64));
    }

    for entry in &entries {
        if entry.kind == b'5' || !entry.path.starts_with("payload/") {
            continue;
        }
        if !installed_payloads.iter().any(|path| path == &entry.path) {
            return Err(mochi_user_syscall::SysError::from_raw(
                mochi_user_syscall::EINVAL as i64,
            ));
        }
    }
    for (target, _, _) in &install_files {
        require_path_absent(target)?;
    }
    require_path_absent(&verification_path)?;
    require_path_absent(&manifest_path)?;
    let mut created_paths = Vec::new();
    for (target, data, mode) in install_files {
        if let Err(error) = write_file(&target, data, mode) {
            let _ = platform::file::remove(&target);
            rollback_created_files(&created_paths);
            diagnostic(&alloc::format!(
                "package.service: payload write failed path={} errno={}",
                target,
                error.errno().unwrap_or(0)
            ));
            return Err(error);
        }
        created_paths.push(target);
    }
    if let Err(error) = write_file(&verification_path, &verification_bytes, FILE_MODE_644) {
        let _ = platform::file::remove(&verification_path);
        rollback_created_files(&created_paths);
        diagnostic(&alloc::format!(
            "package.service: verification record write failed errno={}",
            error.errno().unwrap_or(0)
        ));
        return Err(error);
    }
    created_paths.push(verification_path.clone());
    if let Err(error) = write_file(&manifest_path, &manifest_entry.data, FILE_MODE_644) {
        let _ = platform::file::remove(&manifest_path);
        rollback_created_files(&created_paths);
        diagnostic(&alloc::format!(
            "package.service: manifest write failed errno={}",
            error.errno().unwrap_or(0)
        ));
        return Err(error);
    }
    Ok(())
}

fn parse_install_request(buf: &[u8]) -> Result<String, mochi_user_syscall::SysError> {
    if buf.len() < 4 {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EINVAL as i64,
        ));
    }
    let opcode = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if opcode != INSTALL_REQUEST_OPCODE {
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
        if let Err(error) = request {
            diagnostic(&alloc::format!(
                "package.service: install request failed errno={}",
                error.errno().unwrap_or(0)
            ));
        }
        reply_status(sender, request);
    }
}

fn main() {
    let _ = platform::logger::init_from_env();
    if let Some(mpkg_path) = parse_initial_arg() {
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
