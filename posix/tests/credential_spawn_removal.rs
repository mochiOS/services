#[test]
fn credential_spawn_has_no_kernel_abi_dispatch_or_implementation() {
    let abi = include_str!("../../../core/crates/abi/src/lib.rs");
    let dispatch = include_str!("../../../core/src/syscall/mod.rs");
    let exec = include_str!("../../../core/src/syscall/exec.rs");
    for source in [abi, dispatch, exec] {
        assert!(!source.contains(concat!("ExecManifest", "WithCredentials")));
        assert!(!source.contains(concat!("ExecManifest", "Credentials")));
        assert!(!source.contains("exec_manifest_with_credentials_syscall"));
        assert!(!source.contains("requested_credentials"));
    }
    let enumeration = abi
        .split("pub enum SyscallNumber {")
        .nth(1)
        .unwrap()
        .split('}')
        .next()
        .unwrap();
    assert!(!enumeration.lines().any(|line| {
        line.split('=')
            .nth(1)
            .is_some_and(|value| value.trim().trim_end_matches(',') == "608")
    }));
    assert!(dispatch.contains("_ => mnu_abi::status::Error::Unsupported.into_raw()"));
    // Native creation remains explicit, not a retired pathname ABI shim.
    assert!(dispatch.contains("exec::process_create_syscall(arg0, arg1, arg2)"));
}

#[test]
fn credentials_are_registered_in_userspace_before_native_session_resume() {
    let platform = include_str!("../../../user/crates/platform/src/lib.rs");
    assert!(!platform.contains("spawn_manifest_with_credentials"));
    let launcher = include_str!("../../service-manager/src/service_launcher.rs");
    let native = launcher
        .split("fn spawn_native_session(")
        .nth(1)
        .unwrap()
        .split("fn append_posix_handle(")
        .next()
        .unwrap();
    let compact: String = native
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    assert!(compact.contains("client.register_spawned_child"));
    assert!(native.contains("identity.uid"));
    assert!(native.contains("identity.gid"));
    assert!(native.contains("NativeProcess::create_with_rollback"));
    let owner = include_str!("../../../user/crates/posix-client/src/process_creation.rs");
    assert!(
        owner.find("setup(handle)?").unwrap() < owner.find("resume(handle)?").unwrap()
    );
}
