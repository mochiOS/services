use mochios_posix_client::fd::{access_allows_read, access_allows_write};

#[test]
fn descriptor_access_mode_is_separate_from_mutable_status_flags() {
    for status in [0, 0x8, 0x800, 0x40000, 0x40808] {
        for (mode, read, write) in [
            (0, true, false),
            (1, false, true),
            (2, true, true),
            (3, false, false),
        ] {
            assert_eq!(access_allows_read(status | mode), read);
            assert_eq!(access_allows_write(status | mode), write);
        }
    }
}

#[test]
fn runtime_checks_access_before_zero_length_or_native_io() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    for (name, next, check) in [
        (
            "fn syscall_read(",
            "fn refill_dir_stream(",
            "access_allows_read",
        ),
        (
            "fn syscall_write(",
            "fn syscall_read(",
            "access_allows_write",
        ),
    ] {
        let body = source
            .split(name)
            .nth(1)
            .unwrap()
            .split(next)
            .next()
            .unwrap();
        assert!(body.find(check).unwrap() < body.find("if length == 0").unwrap());
        assert!(body.contains("return Err(EBADF)"));
        assert!(body.contains("SyscallNumber::Handle"));
    }
}
