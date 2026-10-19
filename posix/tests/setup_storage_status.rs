#[path = "../../secure-ui/src/storage_status.rs"]
mod storage_status;

use std::io;

#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn production_setup_error_path_uses_the_newlib_branch_without_starting_gui() {
    let mut program = String::from(
        "#![allow(dead_code)]\nextern crate self as mochios_posix_client;\nuse std::io;\npub mod newlib_errno {\n",
    );
    program.push_str(probe::between(
        include_str!("../../../user/crates/posix-client/src/newlib_errno.rs"),
        "pub const EPERM:",
        "/// Translate either",
    ));
    program.push_str("}\nmod storage_status {\n");
    // Select the production target branch while keeping the host std linked;
    // only the cfg selector changes, not the conversion or setup functions.
    for line in include_str!("../../secure-ui/src/storage_status.rs").lines() {
        if !line.starts_with("//!") {
            program.push_str(&line.replace("target_os = \"mochios\"", "setup_target_newlib"));
            program.push('\n');
        }
    }
    program.push_str("}\n");
    let setup = include_str!("../../secure-ui/src/setup.rs");
    program.push_str(probe::between(
        setup,
        "#[derive(Clone, Copy, Debug, PartialEq, Eq)]\nenum SetupError",
        "fn create_first_account(",
    ));
    program.push_str(probe::between(
        setup,
        "fn storage_error(",
        "fn remove_home(",
    ));
    program.push_str(r#"
fn main() {
    for (errno, expected) in [(91,-36),(88,-38),(90,-39),(92,-40),(139,-75),(134,-95),
        (i32::MIN,-5),(i32::MAX,-5),(-13,-5),(0,-5)] {
        assert_eq!(storage_error(io::Error::from_raw_os_error(errno)), SetupError::Storage(expected));
    }
    assert_eq!(storage_error(io::ErrorKind::PermissionDenied.into()), SetupError::Storage(-13));
}
"#);
    probe::run_with_cfg(&program, "setup_target_newlib");
}

#[test]
fn setup_newlib_errors_enter_wire_namespace_instead_of_merely_changing_sign() {
    for (errno, status) in [
        (2, -2),
        (13, -13),
        (22, -22),
        (91, -36),
        (88, -38),
        (90, -39),
        (92, -40),
        (139, -75),
        (134, -95),
        (35, -42),
        (36, -43),
        (38, -5),
    ] {
        assert_eq!(storage_status::newlib_status(errno), status);
    }
}

#[test]
fn invalid_or_native_values_cannot_panic_or_escape_as_storage_errno() {
    for errno in [0, -1, -13, -91, i32::MIN, i32::MAX, 2_000_001] {
        assert_eq!(storage_status::newlib_status(errno), -5);
    }
    use mochi_user_platform::syscall::NativeError;
    for error in [
        NativeError::AccessDenied,
        NativeError::ResourceUnavailable,
        NativeError::LimitExceeded,
    ] {
        let raw = error.into_raw() as i32;
        assert_eq!(storage_status::newlib_status(raw), -5);
        assert_eq!(storage_status::newlib_status(-raw), -5);
    }
}

#[test]
fn typed_storage_failures_keep_their_meaning_without_raw_errno() {
    for (kind, status) in [
        (io::ErrorKind::NotFound, -2),
        (io::ErrorKind::PermissionDenied, -13),
        (io::ErrorKind::AlreadyExists, -17),
        (io::ErrorKind::ReadOnlyFilesystem, -30),
        (io::ErrorKind::StorageFull, -28),
        (io::ErrorKind::OutOfMemory, -12),
        (io::ErrorKind::Unsupported, -95),
        (io::ErrorKind::Other, -5),
    ] {
        assert_eq!(storage_status::io_status(&io::Error::from(kind)), status);
    }
    let setup = include_str!("../../secure-ui/src/setup.rs");
    assert!(setup.contains("SetupError::Storage(crate::storage_status::io_status(&error))"));
    assert!(!setup.contains("-errno.abs()"));
    assert!(include_str!("../../secure-ui/src/lib.rs").contains("mod storage_status;"));
}
