#[test]
fn pathname_manifest_launch_has_no_abi_dispatch_handler_or_argument_parser() {
    let abi = include_str!("../../../core/crates/abi/src/lib.rs");
    let dispatch = include_str!("../../../core/src/syscall/mod.rs");
    let exec = include_str!("../../../core/src/syscall/exec.rs");
    let exec_abi = include_str!("../../../core/crates/abi/src/exec.rs");
    let platform = include_str!("../../../user/crates/platform/src/lib.rs");
    let example = include_str!("../../../core/examples/user/src/lib.rs");
    for source in [abi, dispatch, exec, platform, example] {
        for obsolete in [
            "ExecManifest",
            "exec_manifest_syscall",
            "spawn_manifest",
            "SYS_EXEC_MANIFEST",
        ] {
            assert!(
                !source.contains(obsolete),
                "retired launch dependency: {obsolete}"
            );
        }
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
            .is_some_and(|value| value.trim().trim_end_matches(',') == "606")
    }));
    for parser in [
        "parse_inherited_handle_spec",
        "parse_inherited_value_spec",
        "ENVIRONMENT_PREFIX",
        "INHERITED_HANDLE_PREFIX",
        "INHERITED_VALUE_PREFIX",
    ] {
        assert!(
            !exec.contains(parser),
            "kernel argv policy parser: {parser}"
        );
        assert!(
            !exec_abi.contains(parser),
            "kernel ABI exposes launcher policy: {parser}"
        );
    }
    assert!(dispatch.contains("_ => mnu_abi::status::Error::Unsupported.into_raw()"));
    assert!(dispatch.contains("exec::process_create_syscall(arg0, arg1, arg2)"));
    assert!(dispatch.contains("exec::process_image_replace_syscall(arg0, arg1, arg2, arg3, arg4)"));
}
