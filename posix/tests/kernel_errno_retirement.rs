//! Guard the kernel implementation, not the separate userspace compatibility
//! clients or the still-to-be-migrated ABI compatibility constants.
#[test]
fn migrated_file_size_status_is_not_part_of_the_kernel_abi() {
    let abi = include_str!("../../../core/crates/abi/src/lib.rs");
    assert!(!abi.contains("pub const EFBIG:"));
    let protocol = include_str!("../../../user/crates/posix-protocol/src/lib.rs");
    assert!(protocol.contains("pub const STATUS_EFBIG: i32 = -27;"));
}

#[test]
fn retired_errno_are_not_exported_by_native_layers() {
    let abi = include_str!("../../../core/crates/abi/src/lib.rs");
    let syscall = include_str!("../../../user/crates/syscall/src/lib.rs");
    for name in [
        "ENODATA", "EMSGSIZE", "ESRCH", "EMFILE", "ENXIO", "EPIPE", "EFAULT", "EBADF",
    ] {
        assert!(!abi.contains(&format!("pub const {name}:")));
        assert!(
            !syscall
                .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .any(|token| token == name)
        );
    }
}

#[test]
fn session_teardown_missing_owner_is_a_userspace_posix_status() {
    let bootstrap = include_str!("../../service-manager/src/bootstrap.rs");
    assert!(
        bootstrap.contains("TeardownError::MissingOwner => mochios_posix_protocol::STATUS_ESRCH")
    );
    let protocol = include_str!("../../../user/crates/posix-protocol/src/lib.rs");
    assert!(protocol.contains("pub const STATUS_ESRCH: i32 = -3;"));
}

#[test]
fn kernel_implementation_does_not_import_or_select_posix_errno_identifiers() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../core/src");
    let forbidden = [
        "EACCES",
        "EAGAIN",
        "EBADF",
        "EEXIST",
        "EFAULT",
        "EFBIG",
        "EINVAL",
        "EIO",
        "EMFILE",
        "EMSGSIZE",
        "ENODATA",
        "ENOENT",
        "ENOMEM",
        "ENOSPC",
        "ENOSYS",
        "ENOTSUP",
        "ENXIO",
        "EOVERFLOW",
        "EPERM",
        "EPIPE",
        "ERANGE",
        "ESRCH",
    ];
    let mut directories = vec![root];
    let mut files = 0;
    while let Some(directory) = directories.pop() {
        for entry in std::fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let kind = entry.file_type().unwrap();
            if kind.is_dir() {
                directories.push(path);
            } else if kind.is_file() && path.extension().is_some_and(|ext| ext == "rs") {
                files += 1;
                let source = std::fs::read_to_string(&path).unwrap();
                for token in source.split(|c: char| !c.is_ascii_alphanumeric() && c != '_') {
                    assert!(!forbidden.contains(&token), "{}: {token}", path.display());
                }
            }
        }
    }
    assert!(files > 100, "kernel source coverage unexpectedly small");
}

#[test]
fn bootstrap_and_thread_entry_failures_use_native_categories() {
    let bootstrap = include_str!("../../../core/src/syscall/exec.rs");
    let start = bootstrap
        .find("pub(crate) fn launch_bootstrap_image(")
        .unwrap();
    let missing = &bootstrap[start
        ..bootstrap[start..]
            .find("crate::performance::increment(")
            .unwrap()
            + start];
    assert!(missing.contains("Error::NotFound.into_raw()"));
    let threads = include_str!("../../../core/src/task/thread.rs");
    assert_eq!(
        threads
            .matches("exit_current_task(mnu_abi::status::Error::NotReady.into_raw())")
            .count(),
        2
    );
    assert_eq!(
        threads
            .matches("exit_current_task(mnu_abi::status::Error::NotFound.into_raw())")
            .count(),
        2
    );
}
