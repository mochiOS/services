use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use mochi_user_platform::syscall::{self, SysError};

/// Read every manifest path, allowing only the Data package root to be absent.
/// Failed traversal must not silently replace the live policy with a partial index.
pub(crate) fn manifest_paths(
    read_directory: impl FnMut(&str) -> Result<Vec<String>, SysError>,
) -> Result<Vec<String>, SysError> {
    collect_manifest_paths(read_directory, true)
}

/// The immutable boot generation contains built-ins only. Mutable Data policy
/// is indexed by refresh_package_index after the POSIX endpoint handoff.
pub(crate) fn bootstrap_manifest_paths(
    read_directory: impl FnMut(&str) -> Result<Vec<String>, SysError>,
) -> Result<Vec<String>, SysError> {
    collect_manifest_paths(read_directory, false)
}

fn collect_manifest_paths(
    mut read_directory: impl FnMut(&str) -> Result<Vec<String>, SysError>,
    include_data: bool,
) -> Result<Vec<String>, SysError> {
    fn walk(
        path: &str,
        depth: usize,
        optional_root: bool,
        paths: &mut Vec<String>,
        read_directory: &mut impl FnMut(&str) -> Result<Vec<String>, SysError>,
    ) -> Result<(), SysError> {
        if depth > 64 {
            return Err(SysError::from_raw(syscall::EOVERFLOW as i64));
        }
        let entries = match read_directory(path) {
            Ok(entries) => entries,
            Err(error) if depth > 0 && error.raw() == syscall::ENOTDIR as i64 => {
                return Ok(());
            }
            Err(error) if depth == 0 && optional_root && error.raw() == syscall::ENOENT as i64 => {
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        for name in entries {
            // Only a single directory entry component may cross this boundary.
            if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\0']) {
                return Err(SysError::from_raw(syscall::EIO as i64));
            }
            let child = format!("{}/{}", path.trim_end_matches('/'), name);
            if name == "manifest.toml" {
                paths.push(child);
            } else {
                walk(&child, depth + 1, false, paths, read_directory)?;
            }
        }
        Ok(())
    }
    let mut paths = Vec::new();
    walk(
        "/system/packages",
        0,
        false,
        &mut paths,
        &mut read_directory,
    )?;
    if include_data {
        walk(
            "/var/lib/packages",
            0,
            true,
            &mut paths,
            &mut read_directory,
        )?;
    }
    Ok(paths)
}
