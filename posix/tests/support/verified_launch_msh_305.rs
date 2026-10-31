//! Test-only measurement/legacy-consent probe in the actual msh instance.
use mochi_user_platform as p;
const ROLE_QUERY: u32 = u32::from_le_bytes(*b"MR05");

pub fn run(requester_endpoint: u64) {
    let endpoint = p::process::find_by_name("capability.service").unwrap();
    let context = p::process::thread_security_context(0).unwrap();
    assert_eq!(
        &context.package_id[..context.package_id_len as usize],
        b"org.mochios.msh"
    );
    let mut reply = [0; 8];
    let message = p::ipc::call(endpoint, &ROLE_QUERY.to_le_bytes(), &mut reply).unwrap();
    assert_eq!(message as u32, 8);
    assert_eq!(
        u64::from_le_bytes(reply),
        0,
        "actual measured msh must authenticate"
    );
    let info = p::process::image_info(None).unwrap();
    let request = p::capability::CapabilityRequest::new_prompt(
        context.process_id,
        "/system/bin/msh",
        info.digest,
        "fs.write.user",
        None,
        Some("legacy positive must not grant"),
        true,
        p::capability::CapabilityClass::UserGrantable,
    )
    .unwrap();
    let mut decision = p::capability::CapabilityDecisionRequest::new(
        p::capability::CapabilityDecision::AllowAllUserGrantable,
        request,
    );
    // The legacy format misused this field as the requester endpoint.
    decision.reserved = requester_endpoint;
    let payload = decision.encode_vec().unwrap();
    let message = p::ipc::call(endpoint, &payload, &mut reply).unwrap();
    assert_eq!(message as u32, 8);
    assert_eq!(u64::from_le_bytes(reply), 95);
    let text = b"verified-msh-305: PASS measured builtin identity, explicit stdio and retired scalar approval\n";
    let _ = p::syscall::call2(
        p::syscall::SyscallNumber::DebugWrite,
        text.as_ptr() as u64,
        text.len() as u64,
    );
}
