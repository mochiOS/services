extern crate alloc;

#[path = "../../capability/src/package_walk.rs"]
mod package_walk;

use mochi_user_platform::syscall::{self, SysError};

#[test]
fn initial_boot_index_reads_only_the_immutable_generation() {
    let paths = package_walk::bootstrap_manifest_paths(|path| match path {
        "/system/packages" => Ok(vec!["manifest.toml".into()]),
        _ => panic!("bootstrap must not consult mutable Data: {path}"),
    })
    .unwrap();
    assert_eq!(paths, ["/system/packages/manifest.toml"]);
    assert_eq!(
        package_walk::bootstrap_manifest_paths(|_| Err(error(syscall::EIO))),
        Err(error(syscall::EIO))
    );
}

fn error(errno: u64) -> SysError {
    SysError::from_raw(errno as i64)
}

#[test]
fn collects_both_roots_and_ignores_non_directory_children() {
    let paths = package_walk::manifest_paths(|path| match path {
        "/system/packages" => Ok(vec!["core".into(), "notes.txt".into()]),
        "/system/packages/core" => Ok(vec!["manifest.toml".into()]),
        "/system/packages/notes.txt" => Err(error(mochios_posix_protocol::STATUS_ENOTDIR as u64)),
        "/var/lib/packages" => Ok(vec!["app".into()]),
        "/var/lib/packages/app" => Ok(vec!["manifest.toml".into()]),
        _ => panic!("unexpected read {path}"),
    })
    .unwrap();
    assert_eq!(
        paths,
        [
            "/system/packages/core/manifest.toml",
            "/var/lib/packages/app/manifest.toml"
        ]
    );
}

#[test]
fn only_an_absent_data_root_is_optional() {
    let paths = package_walk::manifest_paths(|path| match path {
        "/system/packages" => Ok(vec!["manifest.toml".into()]),
        "/var/lib/packages" => Err(error(syscall::ENOENT)),
        _ => panic!("unexpected read {path}"),
    })
    .unwrap();
    assert_eq!(paths, ["/system/packages/manifest.toml"]);
    for errno in [
        syscall::ENOENT,
        mochios_posix_protocol::STATUS_ENOTDIR as u64,
        syscall::EACCES,
        syscall::EIO,
    ] {
        assert_eq!(
            package_walk::manifest_paths(|_| Err(error(errno))),
            Err(error(errno))
        );
    }
    for errno in [
        mochios_posix_protocol::STATUS_ENOTDIR as u64,
        syscall::EACCES,
        syscall::EIO,
    ] {
        assert_eq!(
            package_walk::manifest_paths(|path| {
                if path == "/system/packages" {
                    Ok(vec![])
                } else {
                    Err(error(errno))
                }
            }),
            Err(error(errno))
        );
    }
}

#[test]
fn missing_nested_data_directory_cannot_publish_a_partial_index() {
    assert_eq!(
        package_walk::manifest_paths(|path| match path {
            "/system/packages" => Ok(vec!["manifest.toml".into()]),
            "/var/lib/packages" => Ok(vec!["manifest.toml".into(), "vanished".into()]),
            "/var/lib/packages/vanished" => Err(error(syscall::ENOENT)),
            _ => panic!("unexpected read {path}"),
        }),
        Err(error(syscall::ENOENT))
    );
}

#[test]
fn bounds_recursion_and_rejects_non_component_directory_names() {
    let mut calls = 0;
    assert_eq!(
        package_walk::manifest_paths(|_| {
            calls += 1;
            Ok(vec!["loop".into()])
        }),
        Err(error(syscall::EOVERFLOW))
    );
    assert_eq!(calls, 65);
    for name in ["", ".", "..", "../escape", "a/b", "a\0b"] {
        assert_eq!(
            package_walk::manifest_paths(|_| Ok(vec![name.into()])),
            Err(error(syscall::EIO))
        );
    }
}
