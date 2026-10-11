#[path = "../../../user/crates/newlib-runtime/src/credentials.rs"]
mod production;

use mochios_posix_client::newlib_errno::{EACCES, EAGAIN, EIO, EOVERFLOW, ESRCH};

#[test]
fn successful_identity_queries_preserve_errno_and_use_the_newlib_width() {
    for id in [0, 24, 505, 65535] {
        assert_eq!(
            production::finish(Ok(id), EOVERFLOW, |_| panic!("success changed errno")),
            id as u16
        );
    }
    assert_eq!(core::mem::size_of::<production::Id>(), 2);
}

#[test]
fn query_failures_and_overflow_do_not_fabricate_root() {
    for (result, expected) in [
        (Err(EACCES), EACCES),
        (Err(EAGAIN), EAGAIN),
        (Err(EIO), EIO),
        (Err(ESRCH), ESRCH),
        (Ok(65536), EOVERFLOW),
        (Ok(u32::MAX), EOVERFLOW),
    ] {
        let mut errno = 123;
        let id = production::finish(result, EOVERFLOW, |error| errno = error);
        assert_eq!(id, u16::MAX);
        assert_ne!(id, 0);
        assert_eq!(errno, expected);
    }
}

#[test]
fn all_four_public_queries_use_checked_posix_state_and_not_kernel_credentials() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    for (function, field) in [
        ("getuid", "real_uid"),
        ("geteuid", "effective_uid"),
        ("getgid", "real_gid"),
        ("getegid", "effective_gid"),
    ] {
        let start = source
            .find(&format!(
                "pub extern \"C\" fn {function}() -> credentials::Id {{"
            ))
            .unwrap();
        let end = start + source[start..].find("\n}").unwrap();
        let body = &source[start..end];
        assert!(body.contains(&format!("credential_id(|session| session.{field})")));
        assert!(!body.contains("unwrap_or(0)"));
    }
    let header = include_str!("../../../libraries/newlib/newlib/libc/include/sys/_types.h");
    assert!(header.contains("typedef unsigned short __uid_t;"));
    assert!(header.contains("typedef unsigned short __gid_t;"));
}
