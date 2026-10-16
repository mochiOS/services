#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn retired_provider_observation_retries_without_treating_failure_as_zero_references() {
    let mut program = probe::program();
    probe::constants(
        &mut program,
        include_str!("../../../user/crates/posix-protocol/src/lib.rs"),
        &["STATUS_EIO", "STATUS_EAGAIN"],
    );
    program.push_str("mod wire_status {\n");
    program.push_str(
        &include_str!("../../../user/crates/posix-protocol/src/status.rs")
            .replace("mnu_abi::", "crate::mnu_abi::"),
    );
    program.push_str("}\n");
    let source = include_str!("../src/socket_gc_native.rs");
    program.push_str(
        &source[source.find("fn reference_count_status(").unwrap()..]
            .replace("mochios_posix_protocol::status::", "wire_status::"),
    );
    program.push_str(
        r#"
fn main() {
    use mnu_abi::status::Error;
    for (native, expected) in [
        (Error::InvalidArgument, -11),
        (Error::NotReady, -11),
        (Error::AccessDenied, -13),
        (Error::ResourceUnavailable, -12),
        (Error::BackingFailure, -5),
        (Error::LimitExceeded, -75),
        (Error::InvalidAddress, -14),
        (Error::AlreadyExists, -17),
    ] {
        assert_eq!(reference_count_status(native.into_raw() as i64), expected);
    }
    let unknown = Error::LimitExceeded.into_raw() | 0xffff;
    for raw in [unknown as i64, 0, i64::MIN, i64::MAX] {
        assert_eq!(reference_count_status(raw), -5);
    }
    for raw in [-9, -11, -13] {
        assert_eq!(reference_count_status(raw), raw as i32);
    }
}
"#,
    );
    probe::run(&program);
}
