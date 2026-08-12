use std::fs;
use std::path::Path;

use mochi_user_platform as platform;
use mochios_linux_portal_protocol::{
    Access, GRANT_RESPONSE_LEN, GrantDirectoryRequest, GrantDirectoryResponse,
};

use crate::host::{HostClient, HostError};

const SERVICE_MANAGER_NAME: &str = "service-manager.service";
const REQUEST_BUFFER_LEN: usize = 1024;

pub(crate) fn prepare_read_only(
    host: &mut HostClient,
    instance: u64,
    bundle_id: &str,
    user: &str,
    read_paths: &[String],
    write_paths: &[String],
) -> Result<(), i32> {
    if !write_paths.is_empty() {
        return Err(-(mochi_user_syscall::ENOTSUP as i32));
    }
    host.portal_reset(instance).map_err(host_status)?;
    if read_paths.is_empty() {
        return Ok(());
    }
    let session_id = std::env::var("MOCHI_SESSION_ID")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value != 0)
        .ok_or(-(mochi_user_syscall::EPERM as i32))?;
    for (index, declared) in read_paths.iter().enumerate() {
        let path = resolve_user_path(declared, user)?;
        let request_id = instance
            .wrapping_mul(257)
            .wrapping_add(index as u64)
            .wrapping_add(1)
            .max(1);
        let grant = request_grant(request_id, session_id, bundle_id, user, &path)?;
        host.portal_grant(instance, grant, &path)
            .map_err(host_status)?;
        copy_directory(host, instance, grant, Path::new(&path))?;
    }
    Ok(())
}

fn request_grant(
    request_id: u64,
    session_id: u64,
    bundle_id: &str,
    user: &str,
    path: &str,
) -> Result<u64, i32> {
    let service = platform::process::find_by_name(SERVICE_MANAGER_NAME)
        .map_err(|_| -(mochi_user_syscall::ENOENT as i32))?;
    if service == 0 {
        return Err(-(mochi_user_syscall::ENOENT as i32));
    }
    let request = GrantDirectoryRequest {
        request_id,
        session_id,
        access: Access::READ,
        bundle_id,
        user,
        path,
    };
    let mut encoded = [0u8; REQUEST_BUFFER_LEN];
    let length = request
        .encode(&mut encoded)
        .map_err(|_| -(mochi_user_syscall::EINVAL as i32))?;
    let mut reply = [0u8; GRANT_RESPONSE_LEN];
    let received = platform::ipc::call(service, &encoded[..length], &mut reply)
        .map_err(|_| -(mochi_user_syscall::EIO as i32))?;
    let reply_length = (received & 0xffff_ffff) as usize;
    let response = GrantDirectoryResponse::decode(
        reply
            .get(..reply_length)
            .ok_or(-(mochi_user_syscall::EINVAL as i32))?,
    )
    .map_err(|_| -(mochi_user_syscall::EINVAL as i32))?;
    if response.request_id != request_id {
        return Err(-(mochi_user_syscall::EPERM as i32));
    }
    if response.status != 0 {
        return Err(response.status);
    }
    Ok(response.grant_id)
}

fn copy_directory(
    host: &mut HostClient,
    instance: u64,
    grant: u64,
    root: &Path,
) -> Result<(), i32> {
    let metadata = fs::symlink_metadata(root).map_err(io_status)?;
    if !metadata.is_dir() {
        return Err(-(mochi_user_syscall::ENOTDIR as i32));
    }
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let mut entries = fs::read_dir(&directory)
            .map_err(io_status)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(io_status)?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(io_status)?;
            let target = path_text(&path)?;
            if metadata.file_type().is_symlink() {
                return Err(-(mochi_user_syscall::EACCES as i32));
            }
            if metadata.is_dir() {
                host.portal_mkdir(instance, grant, target)
                    .map_err(host_status)?;
                pending.push(path);
            } else if metadata.is_file() {
                host.portal_file(instance, grant, target, target, metadata.len())
                    .map_err(host_status)?;
            } else {
                return Err(-(mochi_user_syscall::ENOTSUP as i32));
            }
        }
    }
    Ok(())
}

fn resolve_user_path(path: &str, user: &str) -> Result<String, i32> {
    if path == "/home/$USER" {
        return Ok(format!("/home/{user}"));
    }
    if let Some(suffix) = path.strip_prefix("/home/$USER/") {
        return Ok(format!("/home/{user}/{suffix}"));
    }
    if path == "/applications"
        || path.starts_with("/applications/")
        || path == "/libraries"
        || path.starts_with("/libraries/")
    {
        return Ok(path.to_string());
    }
    Err(-(mochi_user_syscall::EINVAL as i32))
}

fn path_text(path: &Path) -> Result<&str, i32> {
    path.to_str().ok_or(-(mochi_user_syscall::EINVAL as i32))
}

fn io_status(error: std::io::Error) -> i32 {
    error
        .raw_os_error()
        .map_or(-(mochi_user_syscall::EIO as i32), |errno| -errno)
}

fn host_status(error: HostError) -> i32 {
    match error {
        HostError::Unavailable => -(mochi_user_syscall::EIO as i32),
        HostError::InvalidReply => -(mochi_user_syscall::EINVAL as i32),
        HostError::Rejected(_) => -(mochi_user_syscall::EPERM as i32),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_placeholder_uses_the_authenticated_name() {
        assert_eq!(
            resolve_user_path("/home/$USER/Develop", "alice"),
            Ok(String::from("/home/alice/Develop"))
        );
        assert!(resolve_user_path("/home/bob", "alice").is_err());
        assert!(resolve_user_path("/system", "alice").is_err());
    }
}
