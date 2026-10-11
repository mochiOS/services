use mochios_posix_client::newlib_errno::{self as errno, from_status};

fn sdk_errno(name: &str) -> i32 {
    let header = include_str!("../../../libraries/newlib/newlib/libc/include/sys/errno.h");
    header
        .lines()
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            if fields.next() != Some("#define") || fields.next() != Some(name) {
                return None;
            }
            fields.next()?.parse().ok()
        })
        .unwrap_or_else(|| panic!("missing newlib errno {name}"))
}

#[test]
fn all_runtime_error_constants_match_the_sdk() {
    let source = include_str!("../../../user/crates/posix-client/src/newlib_errno.rs");
    for line in source
        .lines()
        .filter_map(|line| line.strip_prefix("pub const "))
        .filter(|line| line.starts_with('E'))
    {
        let (name, value) = line.split_once(": i32 = ").unwrap();
        let value: i32 = value.trim_end_matches(';').parse().unwrap();
        assert_eq!(value, sdk_errno(name), "C error constant {name}");
    }
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    assert!(runtime.contains("use mochios_posix_client::newlib_errno::{"));
    assert!(runtime.contains("mochios_posix_client::newlib_errno::from_status(raw)"));
    assert!(!runtime.contains("const ENOSYS:"));
    // The private Rust std bridge still promises native status values.
    let start = runtime
        .find("pub extern \"C\" fn __mochios_wait_on_address_u32(")
        .unwrap();
    let end = start
        + runtime[start..]
            .find("pub extern \"C\" fn __mochios_wake_address_u32(")
            .unwrap();
    let bridge = &runtime[start..end];
    assert!(bridge.contains("match native_monotonic_nanoseconds()"));
    assert!(bridge.contains("Err(error) => return error.raw() as u64"));
    assert!(!bridge.contains("match monotonic_nanoseconds()"));
}

#[test]
fn native_and_wire_failures_translate_by_meaning_not_numeric_identity() {
    for (native, name) in [
        (1, "EPERM"),
        (2, "ENOENT"),
        (4, "EINTR"),
        (11, "EAGAIN"),
        (22, "EINVAL"),
        (34, "ERANGE"),
        (35, "EDEADLK"),
        (36, "ENAMETOOLONG"),
        (37, "ENOLCK"),
        (38, "ENOSYS"),
        (39, "ENOTEMPTY"),
        (40, "ELOOP"),
        (42, "ENOMSG"),
        (43, "EIDRM"),
        (60, "ENOSTR"),
        (61, "ENODATA"),
        (62, "ETIME"),
        (63, "ENOSR"),
        (67, "ENOLINK"),
        (71, "EPROTO"),
        (72, "EMULTIHOP"),
        (74, "EBADMSG"),
        (75, "EOVERFLOW"),
        (84, "EILSEQ"),
        (88, "ENOTSOCK"),
        (89, "EDESTADDRREQ"),
        (90, "EMSGSIZE"),
        (91, "EPROTOTYPE"),
        (92, "ENOPROTOOPT"),
        (93, "EPROTONOSUPPORT"),
        (95, "ENOTSUP"),
        (96, "EPFNOSUPPORT"),
        (97, "EAFNOSUPPORT"),
        (98, "EADDRINUSE"),
        (99, "EADDRNOTAVAIL"),
        (100, "ENETDOWN"),
        (101, "ENETUNREACH"),
        (102, "ENETRESET"),
        (103, "ECONNABORTED"),
        (104, "ECONNRESET"),
        (105, "ENOBUFS"),
        (106, "EISCONN"),
        (107, "ENOTCONN"),
        (110, "ETIMEDOUT"),
        (111, "ECONNREFUSED"),
        (112, "EHOSTDOWN"),
        (113, "EHOSTUNREACH"),
        (114, "EALREADY"),
        (115, "EINPROGRESS"),
        (116, "ESTALE"),
        (122, "EDQUOT"),
        (125, "ECANCELED"),
        (130, "EOWNERDEAD"),
        (131, "ENOTRECOVERABLE"),
    ] {
        assert_eq!(
            from_status(native),
            sdk_errno(name),
            "positive status {name}"
        );
        assert_eq!(
            from_status(-native),
            sdk_errno(name),
            "negative status {name}"
        );
    }
    for invalid in [0, 15, 9999, i64::MIN, i64::MAX, 1_i64 << 32 | 22] {
        assert_eq!(from_status(invalid), errno::EIO, "invalid status {invalid}");
    }
    // A C errno must not be translated a second time: wire 88 means ENOTSOCK.
    assert_ne!(from_status(i64::from(errno::ENOSYS)), errno::ENOSYS);
}
