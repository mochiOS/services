//! Retiring dead kernel pathname policy must not turn scoped requests into
//! broad capabilities or successful authorizations without an actual Handle.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn kernel_has_no_filesystem_path_grant_interpreter_registry_or_process_cleanup() {
    assert!(
        !std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../core/src/capability/path.rs")
            .exists()
    );
    for source in [
        include_str!("../../../core/src/capability/mod.rs"),
        include_str!("../../../core/src/syscall/capability.rs"),
        include_str!("../../../core/src/task/process.rs"),
        include_str!("../../../core/src/init/mod.rs"),
    ] {
        for removed in [
            "SCOPED_PATH_GRANTS",
            "grant_scoped_path",
            "scoped_path_allows",
            "revoke_scoped_paths",
            "parse_scoped_path_grant",
            "fs.scope.",
            "path::init_from_kernel_config",
        ] {
            assert!(!source.contains(removed), "kernel retains {removed}");
        }
    }
}

#[test]
fn path_only_file_requests_are_explicitly_unsupported_not_broadened_or_falsely_granted() {
    let source = include_str!("../../capability/src/dynamic_grant.rs");
    let mut program = probe::program();
    program.push_str(probe::between(
        source,
        "pub(crate) fn validate_grant_resource(",
        "pub(crate) fn read_request_str(",
    ));
    program.push_str(
        r#"
fn main(){
 for capability in ["fs.read.user","fs.write.user"] {
  for path in ["/home/user/file","/","relative","/dir/../file"] {
   let error=validate_grant_resource(capability,Some(path)).unwrap_err();
   assert_eq!(NativeError::from_raw(error.raw()as u64),Some(NativeError::Unsupported));
  }
  assert!(validate_grant_resource(capability,None).is_ok());
 }
 // Non-file process grants retain their existing behavior.
 assert!(validate_grant_resource("network.connect",Some("host")).is_ok());
 assert!(validate_grant_resource("network.connect",None).is_ok());
}
"#,
    );
    probe::run(&program);
}

#[test]
fn retired_dynamic_decisions_cannot_bypass_persistent_resource_validation() {
    let dynamic = include_str!("../../capability/src/dynamic_grant.rs");
    assert!(!dynamic.contains("fn authorize_dynamic_capability("));
    let persistent = include_str!("../../capability/src/persistent_grant.rs")
        .split("pub(crate) fn authorize_persistent_capability(")
        .nth(1)
        .unwrap();
    assert!(
        persistent
            .find("validate_grant_resource(capability, resource)?")
            .unwrap()
            < persistent.find("transfer_user_grant(").unwrap()
    );
    for source in [dynamic, persistent] {
        assert!(!source.contains("transfer_scoped_path_grant"));
        assert!(!source.contains("fs.scope."));
    }
}
