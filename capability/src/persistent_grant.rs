use alloc::string::String;

use mochi_user_platform as platform;
use sha2::{Digest, Sha256};

use crate::dynamic_grant::{read_request_str, transfer_user_grant};
use crate::package_index::PackageIndex;
use crate::policy::is_known_capability;

const GRANTS_PATH: &str = "/system/policy/capability-grants.db";
const O_WRONLY: u64 = 0o1;
const O_CREAT: u64 = 0o100;
const O_TRUNC: u64 = 0o1000;
const FILE_MODE_644: u64 = 0o644;

fn hex_digest(digest: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn ensure_policy_dir() {
    let _ = platform::file::create_dir("/system", 0o755);
    let _ = platform::file::create_dir("/system/policy", 0o755);
}

fn write_file(path: &str, bytes: &[u8]) -> Result<(), mochi_user_syscall::SysError> {
    let fd = platform::file::openat_path(-100, path, O_WRONLY | O_CREAT | O_TRUNC, FILE_MODE_644)?;
    let mut written = 0usize;
    while written < bytes.len() {
        let n = platform::file::write(
            fd,
            bytes[written..].as_ptr() as u64,
            (bytes.len() - written) as u64,
        )? as usize;
        if n == 0 {
            let _ = platform::file::close(fd);
            return Err(mochi_user_syscall::SysError::from_raw(
                mochi_user_syscall::EIO as i64,
            ));
        }
        written += n;
    }
    let _ = platform::file::close(fd);
    Ok(())
}

pub(crate) fn append_persistent_grant(
    executable: &str,
    digest: &[u8; 32],
    capability: &str,
    resource: Option<&str>,
    all_user_grantable: bool,
) -> Result<(), mochi_user_syscall::SysError> {
    ensure_policy_dir();
    let mut data = platform::file::read_to_end_path(GRANTS_PATH).unwrap_or_default();
    data.extend_from_slice(executable.as_bytes());
    data.push(b'\t');
    data.extend_from_slice(hex_digest(digest).as_bytes());
    data.push(b'\t');
    data.extend_from_slice(capability.as_bytes());
    data.push(b'\t');
    data.extend_from_slice(if all_user_grantable {
        b"all-user"
    } else {
        b"single"
    });
    data.push(b'\t');
    if let Some(resource) = resource {
        data.extend_from_slice(resource.as_bytes());
    }
    data.push(b'\n');
    write_file(GRANTS_PATH, &data)
}

fn grant_db_matches(
    executable: &str,
    digest: &[u8; 32],
    capability: &str,
    resource: Option<&str>,
) -> bool {
    let Ok(data) = platform::file::read_to_end_path(GRANTS_PATH) else {
        return false;
    };
    let digest_hex = hex_digest(digest);
    for line in data.split(|b| *b == b'\n') {
        if line.is_empty() {
            continue;
        }
        let mut fields = line.split(|b| *b == b'\t');
        let Some(path) = fields.next().and_then(|v| core::str::from_utf8(v).ok()) else {
            continue;
        };
        let Some(hash) = fields.next().and_then(|v| core::str::from_utf8(v).ok()) else {
            continue;
        };
        let Some(grant_cap) = fields.next().and_then(|v| core::str::from_utf8(v).ok()) else {
            continue;
        };
        let Some(scope) = fields.next().and_then(|v| core::str::from_utf8(v).ok()) else {
            continue;
        };
        let grant_resource = fields
            .next()
            .and_then(|v| core::str::from_utf8(v).ok())
            .unwrap_or("");
        if path != executable || hash != digest_hex {
            continue;
        }
        if scope == "all-user" {
            return true;
        }
        if scope == "single" && grant_cap == capability {
            let resource_matches = match resource {
                Some(resource) => grant_resource == resource,
                None => grant_resource.is_empty(),
            };
            if resource_matches {
                return true;
            }
        }
    }
    false
}

pub(crate) fn authorize_persistent_capability(
    index: &PackageIndex,
    requester_thread: u64,
    request: &platform::capability::CapabilityRequest,
) -> Result<(), mochi_user_syscall::SysError> {
    if request.opcode != platform::capability::CAPABILITY_PERSISTENT_QUERY_OPCODE
        || request.process_id == 0
        || requester_thread == 0
    {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EINVAL as i64,
        ));
    }
    if request.capability_class != platform::capability::CapabilityClass::UserGrantable {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EACCES as i64,
        ));
    }

    let executable = read_request_str(&request.executable.path, request.executable.path_len)?;
    if index.by_binary.contains_key(executable) {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EACCES as i64,
        ));
    }
    let executable_bytes = platform::file::read_to_end_path(executable)?;
    let actual_digest = Sha256::digest(&executable_bytes);
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&actual_digest);
    if request.executable.digest != [0; 32] && request.executable.digest != digest {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EACCES as i64,
        ));
    }

    let capability = read_request_str(&request.capability, request.capability_len)?;
    if !is_known_capability(capability)
        || platform::capability::capability_from_string(capability)
            != platform::capability::CapabilityClass::UserGrantable
    {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EACCES as i64,
        ));
    }
    let resource = if request.resource.path_len == 0 {
        None
    } else {
        Some(read_request_str(
            &request.resource.path,
            request.resource.path_len,
        )?)
    };
    if !grant_db_matches(executable, &digest, capability, resource) {
        return Err(mochi_user_syscall::SysError::from_raw(
            mochi_user_syscall::EACCES as i64,
        ));
    }

    transfer_user_grant(requester_thread, capability, executable)
}
