#[path = "../../linux/src/error.rs"]
mod error;
#[path = "../../linux/src/manifest_io.rs"]
mod manifest_io;

use mochi_user_platform::syscall;

#[test]
fn runtime_manifest_preserves_native_posix_io_status_and_does_not_retry() {
    for errno in [2, 5, 13, 11] {
        let mut calls = 0;
        let error = manifest_io::read_manifest("/var/lib/packages/test/manifest.toml", |path| {
            calls += 1;
            assert_eq!(path, "/var/lib/packages/test/manifest.toml");
            Err(std::io::Error::from_raw_os_error(errno))
        })
        .err()
        .unwrap();
        assert_eq!(error, -errno.abs());
        assert_eq!(calls, 1);
    }
    let error =
        manifest_io::read_manifest("/test", |_| Err(std::io::Error::other("transport failure")))
            .err()
            .unwrap();
    assert_eq!(error, syscall::EIO as i32);
    for errno in [0, -13, i32::MIN] {
        let error =
            manifest_io::read_manifest("/test", |_| Err(std::io::Error::from_raw_os_error(errno)))
                .err()
                .unwrap();
        assert_eq!(error, syscall::EIO as i32);
    }
}

#[test]
fn runtime_manifest_parses_actual_package_data_and_rejects_invalid_encoding() {
    let manifest = manifest_io::read_manifest("/test", |_| {
        Ok(b"[package]\nid = \"org.mochios.test\"\nname = \"Test\"\nversion = \"1\"\n".to_vec())
    })
    .unwrap();
    assert_eq!(manifest.package_id, "org.mochios.test");
    for data in [vec![0xff], b"this is not a manifest".to_vec()] {
        assert_eq!(
            manifest_io::read_manifest("/test", |_| Ok(data)).err(),
            Some(syscall::EINVAL as i32)
        );
    }
}

#[test]
fn runtime_consumers_do_not_use_the_bootstrap_manifest_file_api() {
    let runtime = include_str!("../../linux/src/runtime.rs");
    let portal = include_str!("../../service-manager/src/portal.rs");
    for source in [runtime, portal] {
        assert!(!source.contains("platform::package::read_manifest("));
        assert!(!source.contains("platform::file::"));
    }
    assert!(runtime.contains("crate::manifest_io::read_manifest"));
    assert!(portal.contains("std::fs::read_to_string(path)"));
}
