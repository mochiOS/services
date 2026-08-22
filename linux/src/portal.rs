use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use mochi_user_platform as platform;
use mochios_linux_portal_protocol::{
    Access, GRANT_RESPONSE_LEN, GrantDirectoryRequest, GrantDirectoryResponse,
    NETWORK_RESPONSE_LEN, RequestNetworkRequest, RequestNetworkResponse,
};

use crate::host::{HostClient, HostError, PortalEntryKind};

const SERVICE_MANAGER_NAME: &str = "service-manager.service";
const REQUEST_BUFFER_LEN: usize = 1024;

pub(crate) fn request_network(instance: u64, bundle_id: &str, user: &str) -> Result<(), i32> {
    let session_id = session_id()?;
    let service = service_manager()?;
    let request_id = instance.wrapping_mul(257).wrapping_add(0x80).max(1);
    let request = RequestNetworkRequest {
        request_id,
        session_id,
        bundle_id,
        user,
    };
    let mut encoded = [0u8; REQUEST_BUFFER_LEN];
    let length = request
        .encode(&mut encoded)
        .map_err(|_| -(mochi_user_syscall::EINVAL as i32))?;
    let mut reply = [0u8; NETWORK_RESPONSE_LEN];
    let received = platform::ipc::call(service, &encoded[..length], &mut reply)
        .map_err(|_| -(mochi_user_syscall::EIO as i32))?;
    let response = RequestNetworkResponse::decode(
        reply
            .get(..(received as u32 as usize))
            .ok_or(-(mochi_user_syscall::EINVAL as i32))?,
    )
    .map_err(|_| -(mochi_user_syscall::EINVAL as i32))?;
    if response.request_id != request_id {
        return Err(-(mochi_user_syscall::EPERM as i32));
    }
    (response.status == 0).then_some(()).ok_or(response.status)
}

pub(crate) struct WriteGrant {
    id: u64,
    path: String,
}

struct RequestedPath {
    path: String,
    writable: bool,
}

pub(crate) fn prepare(
    host: &mut HostClient,
    instance: u64,
    bundle_id: &str,
    user: &str,
    read_paths: &[String],
    write_paths: &[String],
) -> Result<Vec<WriteGrant>, i32> {
    host.portal_reset(instance).map_err(host_status)?;
    let requested = requested_paths(read_paths, write_paths, user)?;
    if requested.is_empty() {
        return Ok(Vec::new());
    }
    let session_id = session_id()?;
    let mut write_grants = Vec::new();
    for (index, requested) in requested.iter().enumerate() {
        let request_id = instance
            .wrapping_mul(257)
            .wrapping_add(index as u64)
            .wrapping_add(1)
            .max(1);
        let access = if requested.writable {
            Access::READ_WRITE
        } else {
            Access::READ
        };
        let grant = request_grant(
            request_id,
            session_id,
            bundle_id,
            user,
            &requested.path,
            access,
        )?;
        let root_metadata = fs::symlink_metadata(&requested.path).map_err(io_status)?;
        let root_mode = root_metadata.permissions().mode() & 0o777;
        host.portal_grant(
            instance,
            grant,
            &requested.path,
            requested.writable,
            root_mode,
        )
        .map_err(host_status)?;
        copy_directory(host, instance, grant, Path::new(&requested.path))?;
        if requested.writable {
            write_grants.push(WriteGrant {
                id: grant,
                path: requested.path.clone(),
            });
        }
    }
    Ok(write_grants)
}

pub(crate) fn write_back(
    host: &mut HostClient,
    instance: u64,
    grants: &[WriteGrant],
) -> Result<(), i32> {
    for grant in grants {
        write_back_grant(host, instance, grant)?;
    }
    host.portal_release(instance).map_err(host_status)
}

fn requested_paths(
    read_paths: &[String],
    write_paths: &[String],
    user: &str,
) -> Result<Vec<RequestedPath>, i32> {
    let home = format!("/home/{user}");
    let mut requested = Vec::<RequestedPath>::new();
    for declared in read_paths {
        requested.push(RequestedPath {
            path: resolve_user_path(declared, user)?,
            writable: false,
        });
    }
    for declared in write_paths {
        let path = resolve_user_path(declared, user)?;
        if path == home {
            return Err(-(mochi_user_syscall::ENOTSUP as i32));
        }
        if let Some(existing) = requested
            .iter_mut()
            .find(|candidate| candidate.path == path)
        {
            existing.writable = true;
        } else {
            requested.push(RequestedPath {
                path,
                writable: true,
            });
        }
    }
    if requested.iter().enumerate().any(|(index, candidate)| {
        requested[index + 1..]
            .iter()
            .any(|other| paths_overlap(&candidate.path, &other.path))
    }) {
        return Err(-(mochi_user_syscall::EINVAL as i32));
    }
    Ok(requested)
}

fn write_back_grant(host: &mut HostClient, instance: u64, grant: &WriteGrant) -> Result<(), i32> {
    let root = Path::new(&grant.path);
    let parent = root.parent().ok_or(-(mochi_user_syscall::EINVAL as i32))?;
    let name = root
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(-(mochi_user_syscall::EINVAL as i32))?;
    let temporary = parent.join(format!(".{name}.mochios-portal.partial"));
    let backup = parent.join(format!(".{name}.mochios-portal.backup"));
    recover_swap(root, &temporary, &backup)?;
    fs::create_dir(&temporary).map_err(io_status)?;

    let (entries, root_mode) = match host.portal_export_begin(instance, grant.id) {
        Ok(export) => export,
        Err(error) => {
            let _ = remove_path(&temporary);
            return Err(host_status(error));
        }
    };
    let transfer = transfer_export(host, instance, entries, &temporary);
    if transfer.is_err() {
        let _ = host.portal_export_end(instance);
        let _ = remove_path(&temporary);
        return transfer;
    }
    fs::set_permissions(&temporary, fs::Permissions::from_mode(root_mode)).map_err(io_status)?;
    host.portal_export_end(instance).map_err(host_status)?;

    fs::rename(root, &backup).map_err(io_status)?;
    if let Err(error) = fs::rename(&temporary, root) {
        let _ = fs::rename(&backup, root);
        let _ = remove_path(&temporary);
        return Err(io_status(error));
    }
    remove_path(&backup)?;
    Ok(())
}

fn transfer_export(
    host: &mut HostClient,
    instance: u64,
    entries: usize,
    temporary: &Path,
) -> Result<(), i32> {
    let mut directory_modes = Vec::new();
    for index in 0..entries {
        let entry = host
            .portal_export_entry(instance, index)
            .map_err(host_status)?;
        if !valid_relative_path(&entry.path) {
            return Err(-(mochi_user_syscall::EINVAL as i32));
        }
        let destination = temporary.join(&entry.path);
        match entry.kind {
            PortalEntryKind::Directory => {
                if entry.size != 0 {
                    return Err(-(mochi_user_syscall::EINVAL as i32));
                }
                fs::create_dir_all(&destination).map_err(io_status)?;
                directory_modes.push((destination, entry.mode));
            }
            PortalEntryKind::File => {
                let parent = destination
                    .parent()
                    .ok_or(-(mochi_user_syscall::EINVAL as i32))?;
                fs::create_dir_all(parent).map_err(io_status)?;
                let mut output = OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(destination)
                    .map_err(io_status)?;
                let mut offset = 0u64;
                while offset < entry.size {
                    let (total, bytes) = host
                        .portal_export_chunk(instance, index, offset)
                        .map_err(host_status)?;
                    if total != entry.size
                        || bytes.is_empty()
                        || offset.saturating_add(bytes.len() as u64) > entry.size
                    {
                        return Err(-(mochi_user_syscall::EINVAL as i32));
                    }
                    output.write_all(&bytes).map_err(io_status)?;
                    offset += bytes.len() as u64;
                }
                output.sync_all().map_err(io_status)?;
                fs::set_permissions(
                    temporary.join(&entry.path),
                    fs::Permissions::from_mode(entry.mode),
                )
                .map_err(io_status)?;
            }
        }
    }
    for (directory, mode) in directory_modes.into_iter().rev() {
        fs::set_permissions(directory, fs::Permissions::from_mode(mode)).map_err(io_status)?;
    }
    Ok(())
}

fn recover_swap(root: &Path, temporary: &Path, backup: &Path) -> Result<(), i32> {
    if backup.exists() && !root.exists() {
        fs::rename(backup, root).map_err(io_status)?;
    }
    if backup.exists() {
        remove_path(backup)?;
    }
    if temporary.exists() {
        remove_path(temporary)?;
    }
    Ok(())
}

fn remove_path(path: &Path) -> Result<(), i32> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(io_status(error)),
    };
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        remove_directory_tree(path, 0)
    } else {
        fs::remove_file(path).map_err(io_status)
    }
}

fn remove_directory_tree(path: &Path, depth: usize) -> Result<(), i32> {
    if depth > 128 {
        return Err(-(mochi_user_syscall::EINVAL as i32));
    }
    let entries = fs::read_dir(path)
        .map_err(io_status)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(io_status)?;
    for entry in entries {
        let child = entry.path();
        let metadata = fs::symlink_metadata(&child).map_err(io_status)?;
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            remove_directory_tree(&child, depth + 1)?;
        } else {
            fs::remove_file(child).map_err(io_status)?;
        }
    }
    fs::remove_dir(path).map_err(io_status)
}

fn request_grant(
    request_id: u64,
    session_id: u64,
    bundle_id: &str,
    user: &str,
    path: &str,
    access: Access,
) -> Result<u64, i32> {
    let service = service_manager()?;
    let request = GrantDirectoryRequest {
        request_id,
        session_id,
        access,
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

fn session_id() -> Result<u64, i32> {
    std::env::var("MOCHI_SESSION_ID")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value != 0)
        .ok_or(-(mochi_user_syscall::EPERM as i32))
}

fn service_manager() -> Result<u64, i32> {
    platform::process::find_by_name(SERVICE_MANAGER_NAME)
        .map_err(|_| -(mochi_user_syscall::ENOENT as i32))?
        .checked_sub(0)
        .filter(|service| *service != 0)
        .ok_or(-(mochi_user_syscall::ENOENT as i32))
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
        let mut entries = platform::file::read_dir_names(path_text(&directory)?)
            .map_err(|error| -(error.raw().unsigned_abs().min(i32::MAX as u64) as i32))?;
        entries.sort();
        for entry in entries {
            let path = directory.join(entry);
            let metadata = fs::symlink_metadata(&path).map_err(io_status)?;
            let target = path_text(&path)?;
            if metadata.file_type().is_symlink() {
                return Err(-(mochi_user_syscall::EACCES as i32));
            }
            if metadata.is_dir() {
                host.portal_mkdir(
                    instance,
                    grant,
                    target,
                    metadata.permissions().mode() & 0o777,
                )
                .map_err(host_status)?;
                pending.push(path);
            } else if metadata.is_file() {
                host.portal_file(
                    instance,
                    grant,
                    target,
                    target,
                    metadata.len(),
                    metadata.permissions().mode() & 0o777,
                )
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

fn paths_overlap(left: &str, right: &str) -> bool {
    left == right
        || right
            .strip_prefix(left)
            .is_some_and(|suffix| suffix.starts_with('/'))
        || left
            .strip_prefix(right)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn valid_relative_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.ends_with('/')
        && !path.contains("//")
        && !path.contains('\\')
        && path
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..")
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

    #[test]
    fn write_grant_upgrades_an_identical_read_grant() {
        let requested = requested_paths(
            &[String::from("/home/$USER/Develop")],
            &[String::from("/home/$USER/Develop")],
            "alice",
        );
        assert!(requested.as_ref().is_ok_and(|paths| {
            paths.len() == 1 && paths[0].writable && paths[0].path == "/home/alice/Develop"
        }));
    }

    #[test]
    fn write_grant_rejects_home_root_and_overlap() {
        assert!(requested_paths(&[], &[String::from("/home/$USER")], "alice").is_err());
        assert!(
            requested_paths(
                &[String::from("/home/$USER/Develop")],
                &[String::from("/home/$USER/Develop/src")],
                "alice",
            )
            .is_err()
        );
    }

    #[test]
    fn exported_paths_cannot_escape_the_temporary_tree() {
        assert!(valid_relative_path("src/main.c"));
        for path in [
            "",
            "/etc/passwd",
            "../root",
            "src/../../root",
            "src//main.c",
        ] {
            assert!(!valid_relative_path(path), "accepted {path}");
        }
    }
}
