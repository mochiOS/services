#[path = "../../../user/crates/newlib-runtime/src/credentials.rs"]
mod production;

#[path = "support/native_error_probe.rs"]
#[allow(dead_code)]
mod probe;

#[test]
fn setters_match_newlib_id_abi_and_forward_values_and_errors() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let mut program = String::from(
        r#"#![allow(dead_code, non_camel_case_types)]
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
type c_int = i32;
const EINVAL: i32 = 22;
static ERRNO: AtomicI32 = AtomicI32::new(0);
static VALUE: AtomicU32 = AtomicU32::new(0);
static METHOD: AtomicU32 = AtomicU32::new(0);
static ERROR: AtomicI32 = AtomicI32::new(0);
fn set_errno(error: i32) { ERRNO.store(error, Ordering::SeqCst); }
fn map_posix_client_error(error: i32) -> i32 { error }
fn result_with_errno(result: Result<i32, i32>, failure: i32) -> i32 {
    match result { Ok(value) => value, Err(error) => { set_errno(error); failure } }
}
struct Client;
fn posix_client() -> Result<Client, i32> { Ok(Client) }
impl Client {
    fn record(&self, method: u32, value: u32) -> Result<(), i32> {
        METHOD.store(method, Ordering::SeqCst);
        VALUE.store(value, Ordering::SeqCst);
        match ERROR.load(Ordering::SeqCst) { 0 => Ok(()), error => Err(error) }
    }
    fn set_uid(&self, value: u32) -> Result<(), i32> { self.record(0, value) }
    fn set_gid(&self, value: u32) -> Result<(), i32> { self.record(1, value) }
    fn set_effective_uid(&self, value: u32) -> Result<(), i32> { self.record(2, value) }
    fn set_effective_gid(&self, value: u32) -> Result<(), i32> { self.record(3, value) }
}
mod credentials {
"#,
    );
    program.push_str(include_str!(
        "../../../user/crates/newlib-runtime/src/credentials.rs"
    ));
    program.push_str("}\n");
    for function in ["setuid", "setgid", "seteuid", "setegid"] {
        let marker = format!("pub extern \"C\" fn {function}(");
        let start = source.find(&marker).unwrap();
        let end = start + source[start..].find("\n}").unwrap() + 2;
        program.push_str(&source[start..end]);
        program.push('\n');
    }
    program.push_str(
        r#"
fn main() {
    let setters: [extern "C" fn(credentials::Id) -> c_int; 4] =
        [setuid, setgid, seteuid, setegid];
    for (method, setter) in setters.into_iter().enumerate() {
        for value in [0, 501, 32768, 65534, 65535] {
            ERRNO.store(123, Ordering::SeqCst);
            ERROR.store(0, Ordering::SeqCst);
            assert_eq!(setter(value), 0);
            assert_eq!(VALUE.load(Ordering::SeqCst), u32::from(value));
            assert_eq!(METHOD.load(Ordering::SeqCst), method as u32);
            assert_eq!(ERRNO.load(Ordering::SeqCst), 123);
            for error in [1, 5, 13, 22] {
                ERROR.store(error, Ordering::SeqCst);
                assert_eq!(setter(value), -1);
                assert_eq!(ERRNO.load(Ordering::SeqCst), error);
            }
        }
    }
}
"#,
    );
    probe::run(&program);
}

#[test]
fn credential_update_sentinel_is_widened_not_truncated() {
    assert_eq!(production::update_id(u16::MAX), u32::MAX);
    for id in [0, 24, 505, 65534] {
        assert_eq!(production::update_id(id), u32::from(id));
    }
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    for function in ["setreuid", "setregid"] {
        let start = source
            .find(&format!(
                "pub extern \"C\" fn {function}(real: credentials::Id"
            ))
            .unwrap();
        let end = start + source[start..].find("\n}").unwrap();
        let body = &source[start..end];
        assert!(body.contains("credentials::update_id(real)"));
        assert!(body.contains("credentials::update_id(effective)"));
        assert!(!body.contains("native_call"));
    }
}

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
