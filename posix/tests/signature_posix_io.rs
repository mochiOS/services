#[path = "../../signature/src/endpoint_handoff.rs"]
mod endpoint_handoff;
#[path = "../../signature/src/posix_io.rs"]
#[allow(dead_code)]
mod posix_io;

use mochi_user_platform as platform;

fn attachment() -> platform::ipc::IpcObjectHandles {
    let mut handles = platform::ipc::IpcObjectHandles::default();
    handles.count = 1;
    handles.handles[0].handle = 57;
    handles.handles[0].rights = platform::handle::HANDLE_RIGHT_SEND;
    handles
}

#[test]
fn authenticated_handoff_requires_exactly_one_send_only_handle() {
    let valid = attachment();
    assert_eq!(endpoint_handoff::validate(&valid, true), Ok(57));
    assert_eq!(
        endpoint_handoff::validate(&valid, false),
        Err(platform::syscall::EACCES)
    );
    for mutate in [
        |h: &mut platform::ipc::IpcObjectHandles| h.count = 0,
        |h: &mut platform::ipc::IpcObjectHandles| h.count = 2,
        |h: &mut platform::ipc::IpcObjectHandles| h.count = u32::MAX,
        |h: &mut platform::ipc::IpcObjectHandles| h.delivery_flags = 1,
        |h: &mut platform::ipc::IpcObjectHandles| h.handles[0].handle = 0,
        |h: &mut platform::ipc::IpcObjectHandles| h.handles[0].reserved = 1,
        |h: &mut platform::ipc::IpcObjectHandles| h.handles[0].rights = 0,
        |h: &mut platform::ipc::IpcObjectHandles| {
            h.handles[0].rights |= platform::handle::HANDLE_RIGHT_TRANSFER
        },
    ] {
        let mut handles = valid;
        mutate(&mut handles);
        assert_eq!(
            endpoint_handoff::validate(&handles, true),
            Err(platform::syscall::EINVAL)
        );
    }
}

#[test]
fn before_endpoint_installation_reads_fail_without_legacy_fallback() {
    let error = posix_io::read_file("/system/nonexistent", 1024).unwrap_err();
    assert_eq!(error.raw(), platform::syscall::EAGAIN as i64);
    use mochios_certificate_database::storage::{STATE_PATH, StorageBackend, StorageError};
    assert_eq!(
        posix_io::DatabaseBackend.read(STATE_PATH),
        Err(StorageError::Backend)
    );
    assert_eq!(
        posix_io::DatabaseBackend.read("/unrelated"),
        Err(StorageError::Backend)
    );
    assert_eq!(
        posix_io::DatabaseBackend.write_sync(STATE_PATH, b"x"),
        Err(StorageError::Backend)
    );
}

#[test]
fn signature_reads_and_bootstrap_use_handle_path_without_old_file_syscalls() {
    let source = include_str!("../../signature/src/main.rs");
    assert!(!source.contains("platform::file::"));
    assert!(!source.contains("platform::package::index_mpkg("));
    assert!(!source.contains("platform::package::read_mpkg_range("));
    assert!(source.contains("platform::ipc::wait_object_handles"));
    assert!(source.contains("platform::capability::check_thread(sender, \"capabilities.manage\")"));
    assert!(source.contains("let mut database = None"));
    assert!(source.contains("database = load_active_database()"));
    let manager = include_str!("../../service-manager/src/spawn_support.rs");
    assert!(manager.contains("SIGNATURE_SERVICE_NAME"));
    assert!(manager.contains("mochios_signature_protocol::INSTALL_POSIX_ENDPOINT_OPCODE"));
    let parser = include_str!("../../../user/crates/platform/src/package.rs");
    assert!(!parser.contains("LegacyFileReader"));
    assert!(!parser.contains("super::file::"));
}
