#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn signature_error_reply_carries_a_posix_failure_not_a_native_tag() {
    let source = include_str!("../../signature/src/main.rs");
    let mut program = probe::program();
    program.push_str("mod mochios_signature_protocol {\n");
    program.push_str(
        include_str!("../../../user/crates/signature-protocol/src/lib.rs")
            .strip_prefix("#![no_std]")
            .unwrap(),
    );
    program.push_str("}\nuse mochios_signature_protocol::ErrorResponse;\n");
    program.push_str("mod wire_status {\n");
    program.push_str(
        &include_str!("../../../user/crates/posix-protocol/src/status.rs")
            .replace("mnu_abi::", "crate::mnu_abi::"),
    );
    program.push_str("}\n");
    probe::constants(
        &mut program,
        include_str!("../../../user/crates/posix-protocol/src/lib.rs"),
        &["STATUS_EIO", "STATUS_EAGAIN"],
    );
    program.push_str(
        "fn diagnostic(_: &str) {}\nmod platform {pub mod ipc {
         pub static REPLY: std::sync::Mutex<Vec<u8>>=std::sync::Mutex::new(Vec::new());
         pub fn reply(sender:u64, bytes:&[u8])->Result<(),()> {
             assert_eq!(sender,123); *REPLY.lock().unwrap()=bytes.to_vec(); Ok(())
         }}}\n",
    );
    program.push_str(
        &probe::between(source, "fn reply_error(", "fn reply_verified(")
            .replace("mochios_posix_protocol::status::", "wire_status::"),
    );
    program.push_str(
        r#"
    fn main() {
        use mnu_abi::status::Error;
        assert_eq!(endpoint_reply_status(Ok(())),0);
        for (raw,expected) in [
            (-13,-13),(13,-13),
            (Error::LimitExceeded.into_raw() as i64,-75),
            (Error::InvalidAddress.into_raw() as i64,-14),
            (Error::ResourceUnavailable.into_raw() as i64,-12),
            (Error::BackingFailure.into_raw() as i64,-5),
            (Error::InvalidArgument.into_raw() as i64,-22),
            (Error::AccessDenied.into_raw() as i64,-13),
            (Error::NotReady.into_raw() as i64,-11),
            (((Error::LimitExceeded.into_raw() & !0xffff)|0xffff) as i64,-5),
            (0,-5),(i64::MIN,-5),(i64::MAX,-5),(1_i64 <<32,-5),
        ] {
            assert_eq!(endpoint_reply_status(Err(raw as u64)) as i64,i64::from(expected));
            reply_error(123,42,raw as u64);
            let bytes=platform::ipc::REPLY.lock().unwrap();
            let reply=ErrorResponse::decode(&bytes).unwrap();
            assert_eq!(reply.request_id,42);
            assert_eq!(reply.status,expected,"raw={raw}");
        }
    }
    "#,
    );
    probe::run(&program);
}
