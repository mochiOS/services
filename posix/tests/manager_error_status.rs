//! Execute service-manager's actual conversion functions at the POSIX boundary.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn native_launch_failures_keep_their_meaning_and_never_become_success() {
    let mut program = probe::program();
    probe::constants(
        &mut program,
        include_str!("../../../user/crates/posix-protocol/src/lib.rs"),
        &["STATUS_EIO", "STATUS_EAGAIN"],
    );
    program = program.replacen(
        "mod mochios_posix_protocol {",
        &format!(
            "mod mochios_posix_protocol {{pub mod status {{\n{}\n}}",
            include_str!("../../../user/crates/posix-protocol/src/status.rs")
                .replace("mnu_abi::", "crate::mnu_abi::")
        ),
        1,
    );
    program.push_str(
        "mod mochi_user_platform {pub mod syscall {pub use crate::mochi_user_syscall::*;}}\n",
    );
    program
        .push_str("mod portal_status {use crate::{mochi_user_platform,mochios_posix_protocol};\n");
    program.push_str(include_str!("../../service-manager/src/portal_status.rs"));
    program.push_str("}\n");
    program.push_str(probe::between(
        include_str!("../../service-manager/src/spawn_support.rs"),
        "pub(crate) fn errno(",
        "pub(crate) fn call_with_wait(",
    ));
    program.push_str("mod session_control {\n");
    program.push_str(include_str!(
        "../../../user/crates/platform/src/session_control.rs"
    ));
    program.push_str("}\n");
    program.push_str(r#"
fn check(raw:i64,expected:i32) {
    let error=SysError::from_raw(raw);
    let code=errno(error);
    assert_eq!(code,expected.unsigned_abs() as u64);
    assert_ne!(code,0,"an IPC failure cannot become a successful prompt result");
    for input in [raw as u64,raw.unsigned_abs(),code] {
        assert_eq!(portal_status::failure_status(input),expected);
        let converted=sys_error(input);
        assert_eq!(converted.raw(),expected as i64);
        assert_eq!(converted.errno(),(-4095..=-1).contains(&expected)
            .then_some(expected.unsigned_abs() as u64));
    }
    let response=session_control::Response {
        action:session_control::Action::Lock,session_id:7,
        status:portal_status::failure_status(code),
    };
    let decoded=session_control::decode_response(&session_control::encode_response(response)).unwrap();
    assert_eq!(decoded,response);assert!(decoded.status<0);
}
fn main() {
    use mnu_abi::status::Error;
    for (native,expected) in [
        (Error::LimitExceeded,-75),(Error::InvalidAddress,-14),
        (Error::ResourceUnavailable,-12),(Error::BackingFailure,-5),
        (Error::InvalidArgument,-22),(Error::AccessDenied,-13),
        (Error::NotReady,-11),(Error::AlreadyExists,-17),
        (Error::NotFound,-2),(Error::PeerClosed,-32),(Error::Unsupported,-95),
    ] {
        check(native.into_raw() as i64,expected);
        check((native.into_raw() as i64).unsigned_abs() as i64,expected);
    }
    for status in [-13,13,-22,22,-0x10001,-0x10002,-4095] {
        check(status,-(status.unsigned_abs() as i32));
    }
    for raw in [0,i64::MIN,i64::MAX,
        ((Error::LimitExceeded.into_raw() & !0xffff)|0xffff) as i64] {
        check(raw,-5);
    }
}
"#);
    probe::run(&program);
}
