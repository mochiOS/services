#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn package_reply_preserves_native_failures_in_both_wire_formats() {
    let mut program = probe::program();
    program.push_str("mod package_protocol {\n");
    program.push_str(
        include_str!("../../../user/crates/package-protocol/src/lib.rs")
            .strip_prefix("#![no_std]\n")
            .unwrap(),
    );
    program.push_str("}\n");
    // Exercise the production status normalizer, not a second mapping table.
    program.push_str("mod wire_status {pub mod status {\n");
    program.push_str(
        &include_str!("../../../user/crates/posix-protocol/src/status.rs")
            .replace("mnu_abi::", "crate::mnu_abi::"),
    );
    program.push_str("}}\n");
    // status.rs uses crate::STATUS_EIO and mnu_abi in the production crate.
    probe::constants(
        &mut program,
        include_str!("../../../user/crates/posix-protocol/src/lib.rs"),
        &["STATUS_EIO", "STATUS_EAGAIN"],
    );
    program.push_str(
        "mod platform {pub mod ipc {
         pub static REPLY:std::sync::Mutex<Vec<u8>>=std::sync::Mutex::new(Vec::new());
         pub fn reply(sender:u64, bytes:&[u8])->Result<(),()> {
             assert_eq!(sender, 123); *REPLY.lock().unwrap()=bytes.to_vec(); Ok(())
         }
         }}\n",
    );
    let source = include_str!("../../package/src/main.rs");
    program.push_str(
        &probe::between(source, "fn reply_errno(", "fn collect_package_manifests(")
            .replace("mochios_posix_protocol::status::", "wire_status::status::"),
    );
    program.push_str(
        r#"fn main() {
        use mnu_abi::status::Error;
        assert_eq!(reply_errno(Err(SysError::from_raw(0))), 5);
        for legacy in [true, false] {
            for (raw, expected) in [
                (0, 0), (-13, 13), (13, 13),
                (Error::LimitExceeded.into_raw() as i64, 75),
                (Error::InvalidAddress.into_raw() as i64, 14),
                (Error::ResourceUnavailable.into_raw() as i64, 12),
                (Error::Unsupported.into_raw() as i64, 95),
                (Error::BackingFailure.into_raw() as i64, 5),
                (Error::InvalidArgument.into_raw() as i64, 22),
                (Error::AccessDenied.into_raw() as i64, 13),
                (Error::NotReady.into_raw() as i64, 11),
                (((Error::LimitExceeded.into_raw() & !0xffff) | 0xffff) as i64, 5),
                (i64::MIN, 5), (i64::MAX, 5),
            ] {
                let result = if raw == 0 { Ok(()) } else { Err(SysError::from_raw(raw)) };
                reply_status(123, 42, legacy, result);
                let bytes = platform::ipc::REPLY.lock().unwrap();
                if legacy {
                    assert_eq!(u64::from_le_bytes(bytes.as_slice().try_into().unwrap()), expected,
                        "legacy raw={raw}");
                } else {
                    assert_eq!(package_protocol::decode_status(&bytes, 42).unwrap(),
                        -(expected as i32), "raw={raw}");
                }
            }
        }
        }"#,
    );
    probe::run(&program);
}
