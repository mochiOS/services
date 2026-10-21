#[path = "../../../core/examples/user/src/file_options.rs"]
mod file_options;

use mochios_posix_protocol as posix;

#[test]
fn sample_open_flags_are_normalized_in_userspace() {
    for (flags, expected) in [
        (0, posix::OPEN_READ),
        (1, posix::OPEN_WRITE),
        (2, posix::OPEN_READ | posix::OPEN_WRITE),
        (
            2 | 0o100 | 0o1000,
            posix::OPEN_READ | posix::OPEN_WRITE | posix::OPEN_CREATE | posix::OPEN_TRUNCATE,
        ),
        (
            1 | 0o100 | 0o200 | 0o2000,
            posix::OPEN_WRITE | posix::OPEN_CREATE | posix::OPEN_EXCLUSIVE | posix::OPEN_APPEND,
        ),
    ] {
        assert_eq!(file_options::open_options(flags), Ok(expected));
    }
    for flags in [3, 0x8000, u64::MAX] {
        assert_eq!(file_options::open_options(flags), Err(mochi_user_syscall::EINVAL));
    }
}

#[test]
fn native_sample_uses_inherited_posix_open_and_handle_operations() {
    let source = include_str!("../../../core/examples/user/src/lib.rs");
    for operation in ["FileOpen", "FileClose", "FileRead", "FileWrite", "FileSeek"] {
        assert!(!source.contains(&format!("SyscallNumber::{operation}")));
    }
    assert!(source.contains("Client::from_syscall_launch_context()"));
    assert!(source.contains("Ok(file) => file.handle as u64"));
    for operation in ["HandleRead", "HandleWrite", "HandleClose", "HandleSeek"] {
        assert!(source.contains(&format!("SyscallNumber::{operation}")));
    }
    let main = include_str!("../../../core/examples/user/src/main.rs");
    assert!(!main.contains("3, 0x1, fd"));
    assert!(!main.contains("1, 0x1, fd"));
    assert!(main.contains("mnu_abi::MEMORY_MAP_SHARED"));
}
