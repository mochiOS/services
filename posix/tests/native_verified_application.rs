//! Run from the actual msh. The capability test image enables MR05 role
//! inspection; normal images deliberately provide no diagnostic opcode.
#[cfg(not(target_os = "mochios"))]
fn main() {
    eprintln!("verified-application: requires mochiOS");
}

#[cfg(target_os = "mochios")]
fn main() {
    use mochi_user_platform as p;
    let context = p::process::thread_security_context(0).unwrap();
    assert_eq!(
        &context.package_id[..context.package_id_len as usize],
        b"org.mochios.msh"
    );
    assert_eq!(
        &context.developer_id[..context.developer_id_len as usize],
        b"org.mochios.system"
    );
    assert_eq!(context.provenance, 1);
    let image = p::process::image_info(None).unwrap();
    assert!(image.image_revision >= 1);
    let service = p::process::find_by_name("capability.service").unwrap();
    let mut reply = [0; 8];
    let message = p::ipc::call(
        service,
        &u32::from_le_bytes(*b"MR05").to_le_bytes(),
        &mut reply,
    )
    .unwrap();
    assert_eq!(message as u32, 8);
    assert_eq!(
        u64::from_le_bytes(reply),
        13,
        "inheriting msh identity cannot authenticate different code"
    );
    let message = p::ipc::call(
        service,
        &p::capability::CAPABILITY_DECISION_OPCODE.to_le_bytes(),
        &mut reply,
    )
    .unwrap();
    assert_eq!(message as u32, 8);
    assert_eq!(u64::from_le_bytes(reply), 95);
    println!(
        "verified-application-305: PASS msh identity, replaced-code role refusal and retired scalar approval"
    );
}
