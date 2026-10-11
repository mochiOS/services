use mnu_abi::ThreadSecurityContext;

#[test]
fn obsolete_kernel_uid_gid_mutation_policy_is_absent() {
    let process = include_str!("../../../core/src/task/process.rs");
    for removed in [
        "fn set_uid(",
        "fn set_gid(",
        "fn real_uid(",
        "fn real_gid(",
        "real_uid:",
        "real_gid:",
        "ProcessCredentials::user(",
    ] {
        assert!(!process.contains(removed), "kernel retains {removed}");
    }
}

#[test]
fn kernel_process_and_launch_no_longer_hold_or_inherit_posix_credentials() {
    for source in [
        include_str!("../../../core/src/task/process.rs"),
        include_str!("../../../core/src/syscall/process.rs"),
        include_str!("../../../core/src/syscall/exec.rs"),
    ] {
        for removed in [
            "ProcessCredentials",
            "set_credentials_for_exec",
            "parent_credentials",
            "credentials()",
            "effective_uid",
            "effective_gid",
        ] {
            assert!(!source.contains(removed), "kernel retains {removed}");
        }
    }
}

#[test]
fn legacy_exec_path_keeps_native_authority_checks_without_posix_mode_policy() {
    let fs = include_str!("../../../core/src/syscall/fs.rs");
    let path = include_str!("../../../core/src/capability/path.rs");
    for removed in [
        "ensure_unix_",
        "unix_mode_allows",
        "effective_ids_for_process",
        "PathOwner::User",
    ] {
        assert!(!fs.contains(removed), "kernel retains {removed}");
    }
    assert!(!path.contains("User(u64)"));
    assert!(fs.contains("with_process(pid, |_| ()).is_none()"));
    assert!(fs.contains("ensure_fs_capability_access_for_process(path, PATH_EXEC, pid.as_u64())"));
    assert!(fs.contains("if !path_owner_allows(entry.owner, pid_raw)"));
    assert!(fs.contains("enforce_fs_capabilities_for_process("));
    assert!(fs.contains(
        "PathOwner::Service(owner_pid) | PathOwner::Application(owner_pid) => owner_pid == pid_raw"
    ));
}

#[test]
fn native_security_context_layout_contains_only_execution_and_package_identity() {
    // No compatibility padding is kept for the removed POSIX UID/GID fields.
    assert_eq!(core::mem::size_of::<ThreadSecurityContext>(), 320);
    assert_eq!(core::mem::align_of::<ThreadSecurityContext>(), 8);
    assert_eq!(core::mem::offset_of!(ThreadSecurityContext, process_id), 0);
    assert_eq!(core::mem::offset_of!(ThreadSecurityContext, thread_id), 8);
    assert_eq!(core::mem::offset_of!(ThreadSecurityContext, provenance), 16);
    assert_eq!(
        core::mem::offset_of!(ThreadSecurityContext, subject_key_id),
        24
    );
    assert_eq!(
        core::mem::offset_of!(ThreadSecurityContext, package_id_len),
        56
    );
    assert_eq!(
        core::mem::offset_of!(ThreadSecurityContext, developer_id_len),
        58
    );
    assert_eq!(core::mem::offset_of!(ThreadSecurityContext, package_id), 64);
    assert_eq!(
        core::mem::offset_of!(ThreadSecurityContext, developer_id),
        192
    );
}

#[test]
fn native_probe_checks_actual_layout_package_identity_and_inspection_gate() {
    let probe = include_str!("native_endpoint_identity.c");
    assert!(probe.contains("sizeof(struct security_identity) == 320"));
    assert!(probe.contains("security.identity.provenance == 1"));
    assert!(probe.contains("security.identity.package_length"));
    assert!(probe.contains("security.guard == UINT64_C(0x5a5a5a5a5a5a5a5a)"));
    assert!(probe.contains("native3(617, endpoint"));
    let early = include_str!("native_security_context.c");
    assert!(early.contains("sizeof(struct security_identity) == 320"));
    assert!(early.contains("offsetof(struct security_identity, provenance) == 16"));
    assert!(early.contains("native3(617, endpoint"));
    assert!(early.contains("org.mochios.capability"));
}

#[test]
fn kernel_security_query_does_not_read_posix_credentials() {
    let kernel = include_str!("../../../core/src/syscall/process.rs");
    let query = kernel
        .split("pub fn get_thread_security_context(")
        .nth(1)
        .unwrap()
        .split("/// ユーザー空間の上限アドレス")
        .next()
        .unwrap();
    assert!(!query.contains("credentials"));
    assert!(!query.contains("effective_uid"));
    assert!(!query.contains("effective_gid"));
    // Removing POSIX fields must not remove native authentication or its gate.
    assert!(query.contains("caller_has_any_capability"));
    assert!(query.contains("Capability::CapabilitiesManage"));
    assert!(query.contains("Capability::ProcessInspect"));
    assert!(query.contains("process.application_identity()"));
    assert!(query.contains("identity.subject_key_id()"));
}
