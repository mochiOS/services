#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn capability_replies_translate_errors_and_preserve_success_payloads() {
    let source = include_str!("../../capability/src/server.rs");
    let mut program = probe::program();
    program.push_str("mod capability_protocol {\n");
    program.push_str(
        &include_str!("../../../user/crates/capability-protocol/src/lib.rs")
            .strip_prefix("#![cfg_attr(not(feature = \"std\"), no_std)]\n")
            .unwrap()
            .replace("#[cfg(feature = \"alloc\")]\n", ""),
    );
    program.push_str("}\nmod wire_status {\n");
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
        "mod platform {
         pub(crate) use crate::capability_protocol as capability;
         pub mod ipc {
             pub static REPLY:std::sync::Mutex<Vec<u8>>=std::sync::Mutex::new(Vec::new());
             pub fn reply(sender:u64, bytes:&[u8])->Result<(),()> {
                 assert_eq!(sender,123); *REPLY.lock().unwrap()=bytes.to_vec(); Ok(())
             }
         }}\n",
    );
    program.push_str(
        &probe::between(source, "const REPLY_OK:", "fn close_received_handles(")
            .replace("mochios_posix_protocol::status::", "wire_status::"),
    );
    program.push_str(probe::between(
        source,
        "fn reply_capabilities(",
        "fn parse_persistent_query(",
    ));
    program.push_str(probe::between(
        include_str!("../../capability/src/resolver.rs"),
        "pub(crate) fn encode_nul_list(",
        "fn encode_authorization_args(",
    ));
    program.push_str(r#"
    fn take_reply()->Vec<u8>{std::mem::take(&mut *platform::ipc::REPLY.lock().unwrap())}
    fn main(){
        use mnu_abi::status::Error;
        for (raw,expected) in [
            (-13,13),(13,13),
            (Error::LimitExceeded.into_raw() as i64,75),
            (Error::InvalidAddress.into_raw() as i64,14),
            (Error::ResourceUnavailable.into_raw() as i64,12),
            (Error::BackingFailure.into_raw() as i64,5),
            (Error::InvalidArgument.into_raw() as i64,22),
            (Error::AccessDenied.into_raw() as i64,13),
            (Error::NotReady.into_raw() as i64,11),
            (((Error::LimitExceeded.into_raw() & !0xffff)|0xffff) as i64,5),
            (i64::MIN,5),(i64::MAX,5),
        ]{
            let error=SysError::from_raw(raw);
            capability_reply(123,raw as u64);
            assert_eq!(u64::from_le_bytes(take_reply().try_into().unwrap()),expected);
            reply_spawn(123,Err(error));
            let bytes=take_reply();
            assert_eq!(bytes.len(),16);
            assert_eq!(u64::from_le_bytes(bytes[..8].try_into().unwrap()),expected,"spawn raw={raw}");
            assert_eq!(&bytes[8..],&[0;8]);
            reply_capabilities(123,Err(error));
            let bytes=take_reply();
            let reply=capability_protocol::decode_resolve_capabilities_reply(&bytes).unwrap();
            assert_eq!(reply.status,expected,"capabilities raw={raw}");
            assert!(reply.capabilities.is_empty());
            reply_execution_security(123,Err(error));
            let bytes=take_reply();
            let reply=capability_protocol::decode_resolve_execution_security_reply(&bytes).unwrap();
            assert_eq!(reply.status,expected,"execution security raw={raw}");
            assert!(reply.identity.is_empty()); assert!(reply.capabilities.is_empty());
        }
        assert_eq!(error_status(SysError::from_raw(0)),5);
        capability_reply(123,0);
        assert_eq!(u64::from_le_bytes(take_reply().try_into().unwrap()),0);
        reply_spawn(123,Ok(u64::MAX));
        let bytes=take_reply();
        assert_eq!(u64::from_le_bytes(bytes[..8].try_into().unwrap()),0);
        assert_eq!(u64::from_le_bytes(bytes[8..].try_into().unwrap()),u64::MAX);
        reply_capabilities(123,Ok(vec!["system.time.read".into()]));
        let bytes=take_reply();
        let reply=capability_protocol::decode_resolve_capabilities_reply(&bytes).unwrap();
        assert_eq!(reply.status,0); assert_eq!(reply.capabilities,b"system.time.read\0");
        reply_execution_security(123,Ok((vec!["identity".into()],vec!["system.time.read".into()])));
        let bytes=take_reply();
        let reply=capability_protocol::decode_resolve_execution_security_reply(&bytes).unwrap();
        assert_eq!(reply.status,0); assert_eq!(reply.identity,b"identity\0");
        assert_eq!(reply.capabilities,b"system.time.read\0");
    }
    "#);
    probe::run(&program);
}
