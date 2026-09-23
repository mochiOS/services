extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use mochi_user_platform as platform;
use mochios_linux_gui_protocol::{
    PREPARE_BUNDLE_RESPONSE_LEN, PrepareBundleRequest, PrepareBundleResponse,
};
use mochios_signature_protocol::{
    ErrorResponse, InstallProvenance, InstallRecord, InstallRecordView, Opcode, VerifiedResponse,
    VerifiedView, VerifyFile, decode_opcode,
};
use sha2::{Digest, Sha256};

const SIG_SERVICE_NAME: &str = "signature.service";
const LINUX_SERVICE_NAME: &str = "linux.service";
const CAPABILITY_SERVICE_NAME: &str = "capability.service";
const INSTALL_REQUEST_OPCODE: u32 = 0x494e_5354;
const UPDATE_REQUEST_OPCODE: u32 = 0x5550_4454;
const REMOVE_REQUEST_OPCODE: u32 = 0x524d_4f56;
const REPLY_OK: u64 = 0;
const O_WRONLY: u64 = 0o1;
const O_CREAT: u64 = 0o100;
const O_EXCL: u64 = 0o200;
const FILE_MODE_644: u64 = 0o644;
const FILE_MODE_755: u64 = 0o755;
const FILE_WRITE_CHUNK_LEN: usize = 256 * 1024;
const SIGNATURE_REPLY_LEN: usize = 4128;
const SIGNATURE_SYNC_RETRY_DELAY_MS: u64 = 250;
const SIGNATURE_SYNC_RETRY_ATTEMPTS: usize = 480;

struct VerifiedPackage {
    provenance: InstallProvenance,
    developer_id: String,
    certificate_serial: u64,
    subject_key_id: [u8; 32],
    verified_package_id: String,
    allowed_capabilities: Vec<String>,
    manifest_digest: [u8; 32],
    package_digest: [u8; 32],
}

fn diagnostic(message: &str) {
    platform::logln!("{}", message);
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

fn decode_sha256_digest(value: &str) -> Option<[u8; 32]> {
    let value = value.strip_prefix("sha256:")?;
    if value.len() != 64 {
        return None;
    }
    let mut digest = [0u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_value(pair[0])?;
        let low = hex_value(pair[1])?;
        digest[index] = high << 4 | low;
    }
    Some(digest)
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
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

fn verify_with_signature_service(
    package_path: &str,
) -> Result<VerifiedPackage, mochi_user_syscall::SysError> {
    let service_tid = platform::process::find_by_name(SIG_SERVICE_NAME)?;
    if service_tid == 0 {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::ENOENT as i64,
        ));
    }
    let request_id = platform::time::ticks().unwrap_or(1);
    let request = VerifyFile {
        request_id,
        package_len: 0,
        package_digest: [0; 32],
        path: package_path,
    };
    let mut request_bytes = [0; SIGNATURE_REPLY_LEN];
    let mut reply = [0; SIGNATURE_REPLY_LEN];
    let request_len = request
        .encode(&mut request_bytes)
        .map_err(|_| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64))?;
    let message = platform::ipc::call(service_tid, &request_bytes[..request_len], &mut reply)?;
    let reply_len = (message & 0xffff_ffff) as usize;
    let response = reply
        .get(..reply_len)
        .ok_or_else(|| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EIO as i64))?;
    match decode_opcode(response) {
        Ok(Opcode::Verified) => {
            let verified = VerifiedView::decode(response).map_err(|_| {
                mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64)
            })?;
            if verified.request_id != request_id {
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
                provenance: verified.provenance,
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
                "package.service: invalid signature response len={} opcode={:?}",
                reply_len,
                other
            ));
            Err(mochi_user_syscall::SysError::from_raw(
                mochi_user_syscall::EINVAL as i64,
            ))
        }
    }
}

fn verify_when_database_ready(
    package_path: &str,
) -> Result<VerifiedPackage, mochi_user_syscall::SysError> {
    for attempt in 0..=SIGNATURE_SYNC_RETRY_ATTEMPTS {
        match verify_with_signature_service(package_path) {
            Err(error) if error.errno() == Some(mochi_user_syscall::EAGAIN) => {
                if attempt == SIGNATURE_SYNC_RETRY_ATTEMPTS {
                    return Err(error);
                }
                let _ = platform::thread::sleep_milliseconds(SIGNATURE_SYNC_RETRY_DELAY_MS);
            }
            result => return result,
        }
    }
    Err(mochi_user_syscall::SysError::from_raw(
        mochi_user_syscall::EAGAIN as i64,
    ))
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
        let end = core::cmp::min(offset + FILE_WRITE_CHUNK_LEN, data.len());
        let wrote = match platform::file::write(
            fd,
            data[offset..].as_ptr() as u64,
            (end - offset) as u64,
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
    let sync_result = if offset == data.len() {
        platform::file::sync(fd).map(|_| ())
    } else {
        Ok(())
    };
    let close_result = platform::file::close(fd);
    if offset != data.len() {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EIO as i64,
        ));
    }
    sync_result?;
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

fn notify_package_index_changed() -> Result<(), mochi_user_syscall::SysError> {
    let service = platform::process::find_by_name(CAPABILITY_SERVICE_NAME)?;
    if service == 0 {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::ENOENT as i64,
        ));
    }
    let request = platform::capability::PACKAGE_INDEX_CHANGED_OPCODE.to_le_bytes();
    let mut reply = [0u8; 8];
    let message = platform::ipc::call(service, &request, &mut reply)?;
    if (message & 0xffff_ffff) as usize != reply.len() {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EIO as i64,
        ));
    }
    let status = u64::from_le_bytes(reply);
    if status != 0 {
        return Err(mochi_user_syscall::SysError::from_raw(status as i64));
    }
    Ok(())
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

fn require_path_present(path: &str) -> Result<(), mochi_user_syscall::SysError> {
    let fd = platform::file::open_path(path, 0)?;
    platform::file::close(fd).map(|_| ())
}

struct StagedUpdate {
    target: String,
    temporary: String,
    backup: String,
}

fn manifest_physical_targets(
    manifest: &platform::package::PackageManifest,
) -> Result<Vec<String>, mochi_user_syscall::SysError> {
    let linux_rootfs = manifest
        .linux
        .as_ref()
        .map(|linux| linux.rootfs_file.as_str());
    let mut targets = Vec::new();
    for file in &manifest.files {
        if linux_rootfs == Some(file.id.as_str()) {
            continue;
        }
        let target = manifest_target_path(
            manifest.package_kind.as_deref(),
            &manifest.package_name,
            &file.path,
        )
        .ok_or_else(|| {
            mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64)
        })?;
        targets.push(target);
    }
    targets.sort();
    Ok(targets)
}

fn rollback_update(staged: &[StagedUpdate], committed: usize) {
    for entry in staged[..committed].iter().rev() {
        let _ = platform::file::remove(&entry.target);
        if let Err(error) = platform::file::rename(&entry.backup, &entry.target) {
            diagnostic(&alloc::format!(
                "package.service: update restore failed path={} errno={}",
                entry.target,
                error.errno().unwrap_or(0)
            ));
        }
    }
    for entry in &staged[committed..] {
        let _ = platform::file::remove(&entry.temporary);
    }
}

fn update_package_files(
    mpkg_path: &str,
    manifest: &platform::package::PackageManifest,
    install_files: Vec<(String, u64, u64, u64, String)>,
    verification_path: &str,
    verification_bytes: &[u8],
    manifest_path: &str,
    manifest_bytes: &[u8],
) -> Result<(), mochi_user_syscall::SysError> {
    let existing_manifest_bytes = platform::file::read_to_end_path(manifest_path)?;
    let existing_manifest_text = core::str::from_utf8(&existing_manifest_bytes)
        .map_err(|_| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EACCES as i64))?;
    let existing_manifest = platform::package::parse_manifest(existing_manifest_text)
        .ok_or_else(|| {
            mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EACCES as i64)
        })?;
    if manifest_physical_targets(&existing_manifest)? != manifest_physical_targets(manifest)? {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EACCES as i64,
        ));
    }

    let mut staged = Vec::new();
    for (target, offset, size, mode, digest) in install_files {
        let data = platform::package::read_mpkg_range(mpkg_path, offset, size)?;
        let expected = decode_sha256_digest(&digest).ok_or_else(|| {
            mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64)
        })?;
        if Sha256::digest(&data).as_slice() != expected {
            rollback_update(&staged, 0);
            return Err(mochi_user_syscall::SysError::from_raw(
                mochi_user_syscall::EACCES as i64,
            ));
        }
        stage_update_file(&mut staged, &target, &data, mode)?;
    }
    stage_update_file(
        &mut staged,
        verification_path,
        verification_bytes,
        FILE_MODE_644,
    )?;
    stage_update_file(
        &mut staged,
        manifest_path,
        manifest_bytes,
        FILE_MODE_644,
    )?;

    let mut committed = 0usize;
    for entry in &staged {
        if let Err(error) = platform::file::rename(&entry.target, &entry.backup) {
            rollback_update(&staged, committed);
            return Err(error);
        }
        if let Err(error) = platform::file::rename(&entry.temporary, &entry.target) {
            let _ = platform::file::rename(&entry.backup, &entry.target);
            rollback_update(&staged, committed);
            return Err(error);
        }
        committed += 1;
    }
    if let Err(error) = notify_package_index_changed() {
        rollback_update(&staged, committed);
        let _ = notify_package_index_changed();
        return Err(error);
    }
    for entry in &staged {
        let _ = platform::file::remove(&entry.backup);
    }
    Ok(())
}

fn stage_update_file(
    staged: &mut Vec<StagedUpdate>,
    target: &str,
    data: &[u8],
    mode: u64,
) -> Result<(), mochi_user_syscall::SysError> {
    let temporary = alloc::format!("{target}.mochi-new");
    let backup = alloc::format!("{target}.mochi-old");
    if temporary.len() >= 256 || backup.len() >= 256 {
        rollback_update(staged, 0);
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::ERANGE as i64,
        ));
    }
    let preparation = (|| {
        require_path_present(target)?;
        require_path_absent(&temporary)?;
        require_path_absent(&backup)?;
        write_file(&temporary, data, mode)
    })();
    if let Err(error) = preparation {
        rollback_update(staged, 0);
        return Err(error);
    }
    staged.push(StagedUpdate {
        target: target.to_string(),
        temporary,
        backup,
    });
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SignerContinuity {
    NewInstall,
    SameSigningKey,
    // Reserved for a future issuer-authorized key-rotation proof. Merely
    // sharing a Package ID never selects this state.
    AuthorizedKeyRotation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PackageMutation {
    Install,
    Update,
}

fn validate_update_owner(
    verification_path: &str,
    incoming: &VerifiedPackage,
) -> Result<SignerContinuity, mochi_user_syscall::SysError> {
    let bytes = match platform::file::read_to_end_path(verification_path) {
        Ok(bytes) => bytes,
        Err(error) if error.errno() == Some(mochi_user_syscall::ENOENT.wrapping_neg()) => {
            return Ok(SignerContinuity::NewInstall);
        }
        Err(error) => return Err(error),
    };
    let existing = InstallRecordView::decode(&bytes)
        .map_err(|_| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EACCES as i64))?;
    let identity = existing.application_identity();
    if identity.package_id != incoming.verified_package_id
        || identity.developer_id != incoming.developer_id
        || identity.subject_key_id != incoming.subject_key_id
    {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EACCES as i64,
        ));
    }
    Ok(SignerContinuity::SameSigningKey)
}

fn install_package(
    mpkg_path: &str,
    mutation: PackageMutation,
) -> Result<(), mochi_user_syscall::SysError> {
    diagnostic(&alloc::format!(
        "package.service: package read start path={}",
        mpkg_path
    ));
    let index = platform::package::index_mpkg(mpkg_path).map_err(|error| {
        diagnostic(&alloc::format!(
            "package.service: package read failed path={} errno={}",
            mpkg_path,
            error.errno().unwrap_or(0)
        ));
        error
    })?;
    diagnostic(&alloc::format!(
        "package.service: package index complete bytes={} entries={}",
        index.file_len,
        index.entries.len()
    ));
    let verification = verify_when_database_ready(mpkg_path)?;
    diagnostic("package.service: signature verification complete");
    let manifest_text = core::str::from_utf8(&index.manifest)
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
    if manifest.linux.is_none()
        && (manifest.package_architecture.as_deref() != Some("x86_64")
            || manifest.package_abi.as_deref() != Some("mochios-1"))
    {
        diagnostic(&alloc::format!(
            "package.service: incompatible native package architecture={:?} abi={:?}",
            manifest.package_architecture, manifest.package_abi
        ));
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::ENOTSUP as i64,
        ));
    }
    if verification.verified_package_id != manifest.package_id
        || verification.package_digest != verification.manifest_digest
    {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EACCES as i64,
        ));
    }

    require_path_absent(&alloc::format!("/system/packages/{}/manifest.toml", manifest.package_id))?;
    let package_root = alloc::format!("/var/lib/packages/{}", manifest.package_id);
    let manifest_path = alloc::format!("{}/manifest.toml", package_root);
    let verification_path = alloc::format!("{}/verification.bin", package_root);
    let signer_continuity = validate_update_owner(&verification_path, &verification)?;
    match (mutation, signer_continuity) {
        (PackageMutation::Install, SignerContinuity::NewInstall) => {}
        (PackageMutation::Install, _) => {
            return Err(mochi_user_syscall::SysError::from_raw(
                mochi_user_syscall::EEXIST as i64,
            ));
        }
        (PackageMutation::Update, SignerContinuity::NewInstall) => {
            return Err(mochi_user_syscall::SysError::from_raw(
                mochi_user_syscall::ENOENT as i64,
            ));
        }
        (PackageMutation::Update, SignerContinuity::SameSigningKey)
        | (PackageMutation::Update, SignerContinuity::AuthorizedKeyRotation) => {}
    }
    if signer_continuity != SignerContinuity::NewInstall {
        diagnostic(&alloc::format!(
            "package.service: signer continuity accepted id={} continuity={:?}",
            manifest.package_id,
            signer_continuity
        ));
    }
    let capability_refs = verification
        .allowed_capabilities
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let verification_record = InstallRecord {
        provenance: verification.provenance,
        verification: VerifiedResponse {
            request_id: 0,
            provenance: verification.provenance,
            certificate_serial: verification.certificate_serial,
            subject_key_id: verification.subject_key_id,
            manifest_digest: verification.manifest_digest,
            package_digest: verification.package_digest,
            developer_id: &verification.developer_id,
            verified_package_id: &verification.verified_package_id,
            allowed_capabilities: &capability_refs,
        },
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
    let mut install_targets = Vec::new();
    let linux_rootfs_id = manifest
        .linux
        .as_ref()
        .map(|linux| linux.rootfs_file.as_str());
    let mut linux_stage = None;
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
        let entry = index.entry(&payload_path).ok_or_else(|| {
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
        install_targets.push(target.clone());
        if linux_rootfs_id == Some(file.id.as_str()) {
            let digest = file.digest.strip_prefix("sha256:").filter(|digest| {
                digest.len() == 64
                    && digest
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            });
            let digest = digest.ok_or_else(|| {
                mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64)
            })?;
            linux_stage = Some((entry.offset, entry.size, digest.to_string()));
        } else {
            install_files.push((
                target,
                entry.offset,
                entry.size,
                file.mode as u64,
                file.digest.clone(),
            ));
        }
    }

    for entry in &index.entries {
        if entry.kind == b'5' || !entry.path.starts_with("payload/") {
            continue;
        }
        if !installed_payloads.iter().any(|path| path == &entry.path) {
            return Err(mochi_user_syscall::SysError::from_raw(
                mochi_user_syscall::EINVAL as i64,
            ));
        }
    }
    if mutation == PackageMutation::Update {
        if linux_stage.is_some() {
            return Err(mochi_user_syscall::SysError::from_raw(
                mochi_user_syscall::ENOTSUP as i64,
            ));
        }
        return update_package_files(
            mpkg_path,
            &manifest,
            install_files,
            &verification_path,
            &verification_bytes,
            &manifest_path,
            &index.manifest,
        );
    }
    for target in &install_targets {
        require_path_absent(target)?;
    }
    require_path_absent(&verification_path)?;
    require_path_absent(&manifest_path)?;
    let mut created_paths = Vec::new();
    for (target, offset, size, mode, digest) in install_files {
        let data = platform::package::read_mpkg_range(mpkg_path, offset, size)?;
        let expected = decode_sha256_digest(&digest).ok_or_else(|| {
            mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64)
        })?;
        if Sha256::digest(&data).as_slice() != expected {
            rollback_created_files(&created_paths);
            return Err(mochi_user_syscall::SysError::from_raw(
                mochi_user_syscall::EACCES as i64,
            ));
        }
        if let Err(error) = write_file(&target, &data, mode) {
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
    if let Err(error) = write_file(&manifest_path, &index.manifest, FILE_MODE_644) {
        let _ = platform::file::remove(&manifest_path);
        rollback_created_files(&created_paths);
        diagnostic(&alloc::format!(
            "package.service: manifest write failed errno={}",
            error.errno().unwrap_or(0)
        ));
        return Err(error);
    }
    created_paths.push(manifest_path.clone());
    if let Some((offset, size, digest)) = linux_stage
        && let Err(error) =
            prepare_linux_bundle(&manifest.package_id, mpkg_path, offset, size, &digest)
    {
        rollback_created_files(&created_paths);
        diagnostic(&alloc::format!(
            "package.service: Linux bundle staging failed id={} errno={}",
            manifest.package_id,
            error.errno().unwrap_or(0)
        ));
        return Err(error);
    }
    if let Err(error) = notify_package_index_changed() {
        rollback_created_files(&created_paths);
        let _ = notify_package_index_changed();
        diagnostic(&alloc::format!(
            "package.service: package index refresh failed id={} errno={}",
            manifest.package_id,
            error.errno().unwrap_or(0)
        ));
        return Err(error);
    }
    Ok(())
}

fn prepare_linux_bundle(
    bundle_id: &str,
    source_path: &str,
    rootfs_offset: u64,
    rootfs_size: u64,
    rootfs_digest: &str,
) -> Result<(), mochi_user_syscall::SysError> {
    let service = platform::process::find_by_name(LINUX_SERVICE_NAME)?;
    if service == 0 {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::ENOENT as i64,
        ));
    }
    let request = PrepareBundleRequest {
        request_id: platform::time::ticks().unwrap_or(1),
        bundle_id,
        source_path,
        rootfs_offset,
        rootfs_size,
        rootfs_digest,
    };
    let mut encoded = [0u8; 512];
    let length = request
        .encode(&mut encoded)
        .map_err(|_| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64))?;
    let mut reply = [0u8; PREPARE_BUNDLE_RESPONSE_LEN];
    let message = match platform::ipc::call(service, &encoded[..length], &mut reply) {
        Ok(message) => message,
        Err(error) if error.raw() == mochi_user_syscall::EAGAIN as i64 => loop {
            match platform::ipc::try_wait(&mut reply) {
                Ok(message) => break message,
                Err(error) if error.raw() == mochi_user_syscall::EAGAIN as i64 => {
                    platform::thread::yield_now();
                }
                Err(error) => return Err(error),
            }
        },
        Err(error) => return Err(error),
    };
    let reply_length = (message & 0xffff_ffff) as usize;
    let response = reply
        .get(..reply_length)
        .ok_or_else(|| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EIO as i64))
        .and_then(|bytes| {
            PrepareBundleResponse::decode(bytes).map_err(|_| {
                mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64)
            })
        })?;
    if response.request_id != request.request_id || response.status > 0 {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EINVAL as i64,
        ));
    }
    if response.status < 0 {
        return Err(mochi_user_syscall::SysError::from_raw(i64::from(
            response.status,
        )));
    }
    Ok(())
}

enum PackageRequest {
    Install(String),
    Update(String),
    Remove(String),
}

fn parse_package_request(buf: &[u8]) -> Result<PackageRequest, mochi_user_syscall::SysError> {
    if buf.len() < 4 {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EINVAL as i64,
        ));
    }
    let opcode = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let is_remove = match opcode {
        INSTALL_REQUEST_OPCODE | UPDATE_REQUEST_OPCODE => false,
        REMOVE_REQUEST_OPCODE => true,
        _ => {
            return Err(mochi_user_syscall::SysError::from_raw(
                mochi_user_syscall::EINVAL as i64,
            ));
        }
    };
    let value_bytes = &buf[4..];
    if value_bytes.is_empty() || value_bytes.contains(&0) {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EINVAL as i64,
        ));
    }
    let value = core::str::from_utf8(value_bytes)
        .map_err(|_| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EINVAL as i64))?;
    if is_remove {
        if value.len() > 128
            || value == "."
            || value == ".."
            || value.bytes().any(|byte| {
                !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
            })
        {
            return Err(mochi_user_syscall::SysError::from_raw(
                mochi_user_syscall::EINVAL as i64,
            ));
        }
        return Ok(PackageRequest::Remove(value.to_string()));
    }
    if !value.starts_with('/') {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EINVAL as i64,
        ));
    }
    if opcode == INSTALL_REQUEST_OPCODE {
        Ok(PackageRequest::Install(value.to_string()))
    } else {
        Ok(PackageRequest::Update(value.to_string()))
    }
}

fn reply_status(sender: u64, result: Result<(), mochi_user_syscall::SysError>) {
    let status = match result {
        Ok(_) => REPLY_OK,
        Err(err) => err.errno().unwrap_or(mochi_user_syscall::EIO),
    };
    let _ = platform::ipc::reply(sender, &status.to_le_bytes());
}

fn rollback_removal(staged: &[(String, String)]) {
    for (target, backup) in staged.iter().rev() {
        if let Err(error) = platform::file::rename(backup, target) {
            diagnostic(&alloc::format!(
                "package.service: remove rollback failed path={} errno={}",
                target,
                error.errno().unwrap_or(0)
            ));
        }
    }
}

fn remove_package(package_id: &str) -> Result<(), mochi_user_syscall::SysError> {
    let package_root = alloc::format!("/var/lib/packages/{package_id}");
    let manifest_path = alloc::format!("{package_root}/manifest.toml");
    let verification_path = alloc::format!("{package_root}/verification.bin");
    let manifest_bytes = platform::file::read_to_end_path(&manifest_path)?;
    let manifest_text = core::str::from_utf8(&manifest_bytes)
        .map_err(|_| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EACCES as i64))?;
    let manifest = platform::package::parse_manifest(manifest_text)
        .ok_or_else(|| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EACCES as i64))?;
    if manifest.package_id != package_id || manifest.linux.is_some() {
        return Err(mochi_user_syscall::SysError::from_raw(
            if manifest.linux.is_some() {
                mochi_user_syscall::ENOTSUP as i64
            } else {
                mochi_user_syscall::EACCES as i64
            },
        ));
    }
    let verification_bytes = platform::file::read_to_end_path(&verification_path)?;
    let install_record = InstallRecordView::decode(&verification_bytes)
        .map_err(|_| mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EACCES as i64))?;
    if install_record.provenance == InstallProvenance::BuiltIn
        || install_record.verification.verified_package_id != package_id
    {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EACCES as i64,
        ));
    }

    let mut targets = manifest_physical_targets(&manifest)?;
    targets.push(verification_path);
    targets.push(manifest_path);
    targets.sort();
    targets.dedup();
    let mut staged = Vec::new();
    for target in targets {
        let backup = alloc::format!("{target}.mochi-remove");
        if backup.len() >= 256 {
            rollback_removal(&staged);
            return Err(mochi_user_syscall::SysError::from_raw(
                mochi_user_syscall::ERANGE as i64,
            ));
        }
        if let Err(error) = require_path_absent(&backup)
            .and_then(|_| require_path_present(&target))
            .and_then(|_| platform::file::rename(&target, &backup).map(|_| ()))
        {
            rollback_removal(&staged);
            return Err(error);
        }
        staged.push((target, backup));
    }
    if let Err(error) = notify_package_index_changed() {
        rollback_removal(&staged);
        let _ = notify_package_index_changed();
        return Err(error);
    }
    for (_, backup) in &staged {
        if let Err(error) = platform::file::remove(backup) {
            diagnostic(&alloc::format!(
                "package.service: removed package cleanup failed path={} errno={}",
                backup,
                error.errno().unwrap_or(0)
            ));
        }
    }
    diagnostic(&alloc::format!(
        "package.service: removed id={package_id} files={}",
        staged.len()
    ));
    Ok(())
}

fn run_server() -> ! {
    platform::logln!("package.service: ready");
    let endpoint = match platform::ipc::create() {
        Ok(endpoint) => endpoint,
        Err(err) => {
            platform::logln!(
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
        let request = parse_package_request(&buf[..len]).and_then(|request| {
            let required = match &request {
                PackageRequest::Install(_) => "package.install",
                PackageRequest::Update(_) => "package.update",
                PackageRequest::Remove(_) => "package.remove",
            };
            if platform::capability::check_thread(sender, required) != Ok(1) {
                return Err(mochi_user_syscall::SysError::from_raw(
                    mochi_user_syscall::EACCES as i64,
                ));
            }
            match request {
                PackageRequest::Install(path) => {
                    install_package(&path, PackageMutation::Install)
                }
                PackageRequest::Update(path) => {
                    install_package(&path, PackageMutation::Update)
                }
                PackageRequest::Remove(package_id) => remove_package(&package_id),
            }
        });
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
    run_server()
}
