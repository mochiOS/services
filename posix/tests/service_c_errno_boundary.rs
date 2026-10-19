//! Exercise the production host branch normally and the mochiOS/newlib branch
//! with rustc's explicit target_os cfg on the host. No native syscall is used.

#[path = "../../user/src/status.rs"]
mod account_status;
#[path = "../../linux/src/error.rs"]
mod error;
#[path = "../../linux/src/manifest_io.rs"]
mod manifest_io;
#[path = "../../workspace/src/error.rs"]
mod workspace_error;

fn cases() -> &'static [(i32, i32)] {
    #[cfg(target_os = "mochios")]
    {
        &[
            (91, -36),  // ENAMETOOLONG, not wire EPROTOTYPE
            (88, -38),  // ENOSYS, not wire ENOTSOCK
            (134, -95), // ENOTSUP
            (95, -95),  // EOPNOTSUPP aliases generic unsupported on the wire
            (139, -75), // EOVERFLOW
            (45, -35),  // EDEADLK
            (35, -42),  // ENOMSG, not wire EDEADLK
            (122, -90), // EMSGSIZE, not wire EDQUOT
            (90, -39),  // ENOTEMPTY, not wire EMSGSIZE
            (142, -130),
            (141, -131),
        ]
    }
    #[cfg(not(target_os = "mochios"))]
    {
        &[(36, -36), (38, -38), (75, -75), (95, -95)]
    }
}

#[test]
fn service_boundaries_preserve_error_meaning_in_the_wire_namespace() {
    for &(c_errno, wire) in cases() {
        assert_eq!(
            error::io_status(std::io::Error::from_raw_os_error(c_errno)),
            wire,
            "linux C errno {c_errno}"
        );
        assert_eq!(
            workspace_error::io_errno(std::io::Error::from_raw_os_error(c_errno)),
            u64::from(wire.unsigned_abs()),
            "workspace C errno {c_errno}"
        );
        assert_eq!(
            account_status::io_status(&std::io::Error::from_raw_os_error(c_errno)),
            wire,
            "account C errno {c_errno}"
        );
    }
}

#[test]
fn invalid_c_errno_cannot_be_reinterpreted_as_a_native_or_wire_status() {
    for raw in [
        0,
        -13,
        -91,
        i32::MIN,
        mochi_user_platform::syscall::NativeError::LimitExceeded.into_raw() as i32,
    ] {
        assert_eq!(error::io_status(std::io::Error::from_raw_os_error(raw)), -5);
        assert_eq!(
            workspace_error::io_errno(std::io::Error::from_raw_os_error(raw)),
            5
        );
        assert_eq!(
            account_status::io_status(&std::io::Error::from_raw_os_error(raw)),
            -5
        );
    }
    assert_eq!(error::io_status(std::io::Error::other("no C errno")), -5);
    assert_eq!(
        workspace_error::io_errno(std::io::Error::other("no C errno")),
        5
    );
}

#[test]
fn linux_manifest_read_uses_the_same_boundary_without_retrying() {
    for &(c_errno, wire) in cases() {
        let mut calls = 0;
        let result = manifest_io::read_manifest("/test/manifest.toml", |path| {
            assert_eq!(path, "/test/manifest.toml");
            calls += 1;
            Err(std::io::Error::from_raw_os_error(c_errno))
        });
        assert_eq!(result.err(), Some(wire));
        assert_eq!(calls, 1);
    }
}

#[cfg(target_os = "mochios")]
#[test]
fn newlib_client_decodes_the_original_c_error_after_wire_conversion() {
    use mochios_posix_client::newlib_errno;
    for &(c_errno, wire) in cases() {
        let decoded = newlib_errno::from_status(i64::from(wire));
        let expected = if c_errno == newlib_errno::EOPNOTSUPP {
            newlib_errno::ENOTSUP
        } else {
            c_errno
        };
        assert_eq!(decoded, expected);
    }
}
