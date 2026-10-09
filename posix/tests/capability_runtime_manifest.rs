extern crate alloc;

#[path = "../../capability/src/runtime_manifest.rs"]
mod runtime_manifest;

use mochi_user_platform::syscall::{self, SysError};

#[test]
fn manifest_read_preserves_io_errors_and_calls_the_reader_once() {
    for status in [
        syscall::EAGAIN,
        syscall::EACCES,
        syscall::ENOENT,
        syscall::EIO,
    ] {
        let mut calls = 0;
        let error =
            runtime_manifest::read_manifest("/var/lib/packages/test/manifest.toml", |path| {
                calls += 1;
                assert_eq!(path, "/var/lib/packages/test/manifest.toml");
                Err(SysError::from_raw(status as i64))
            })
            .err()
            .unwrap();
        assert_eq!(calls, 1);
        assert_eq!(error.raw(), status as i64);
    }
}

#[test]
fn malformed_manifest_is_not_reported_as_an_io_failure() {
    for bytes in [vec![0xff], b"not a manifest".to_vec(), vec![]] {
        let error = runtime_manifest::read_manifest("/test", |_| Ok(bytes))
            .err()
            .unwrap();
        assert_eq!(error.raw(), syscall::EINVAL as i64);
    }
}

#[test]
fn valid_manifest_is_parsed_from_the_provided_file_bytes() {
    let bytes = include_bytes!("../../capability/manifest.toml").to_vec();
    let manifest = runtime_manifest::read_manifest("/test", |_| Ok(bytes)).unwrap();
    assert_eq!(manifest.package_id, "org.mochios.capability");
}

#[test]
fn application_and_dynamic_grant_readers_do_not_use_kernel_path_file_apis() {
    for source in [
        include_str!("../../capability/src/app_spawn.rs"),
        include_str!("../../capability/src/dynamic_grant.rs"),
    ] {
        assert!(!source.contains("platform::package::read_manifest("));
        assert!(!source.contains("platform::file::"));
        assert!(source.contains("crate::runtime_manifest::read_manifest("));
        assert!(source.contains("crate::persistent_grant::read_file,"));
    }
}
