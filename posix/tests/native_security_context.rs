use mnu_abi::ThreadSecurityContext;

#[test]
fn cwd_is_not_kernel_process_or_launch_state() {
    for source in [
        include_str!("../../../core/src/task/process.rs"),
        include_str!("../../../core/src/syscall/exec.rs"),
        include_str!("../../../core/src/syscall/capability.rs"),
    ] {
        for removed in [
            "cwd:",
            "cwd_len",
            "fn cwd(",
            "set_cwd(",
            ".cwd()",
            "parent_cwd",
        ] {
            assert!(!source.contains(removed), "kernel retains {removed}");
        }
    }
}

#[test]
fn native_scoped_grants_require_absolute_paths_without_losing_authentication() {
    let kernel = include_str!("../../../core/src/syscall/capability.rs");
    assert!(kernel.contains("if !selected_path.starts_with('/')"));
    assert!(kernel.contains("if can_manage_capabilities"));
    assert!(kernel.contains("proc.exe_path() == claimed_exe_path"));
    assert!(
        kernel.contains("path::grant_scoped_path(dest_process.as_u64(), selected_path, rights)")
    );
    let service = include_str!("../../capability/src/dynamic_grant.rs");
    let grant = service
        .split("pub(crate) fn transfer_scoped_path_grant(")
        .nth(1)
        .unwrap()
        .split("pub(crate) fn read_request_str(")
        .next()
        .unwrap();
    assert!(grant.contains("!path.starts_with('/')"));
    assert!(!grant.contains("cwd"));
}

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
fn native_image_authority_does_not_reintroduce_legacy_path_or_posix_mode_policy() {
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
    assert!(!fs.contains("ensure_fs_capability_access_for_process"));
    assert!(!fs.contains("path_owner_allows"));
    let exec = include_str!("../../../core/src/syscall/exec.rs");
    assert!(exec.contains("process.take_exec_authorization(request.identity, thread)"));
    assert!(exec.contains("crate::syscall::handle::read_all(image_handle,"));
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
