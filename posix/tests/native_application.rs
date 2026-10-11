extern crate alloc;
#[allow(dead_code)]
#[path = "../../capability/src/native_app.rs"]
mod production;

mod persistent_grant {
    use mochi_user_platform as platform;
    use mochios_posix_client::{Client, ClientError, EndpointTransport};
    pub fn with_client<T>(
        _: impl FnOnce(
            &Client<EndpointTransport>,
        ) -> Result<T, ClientError<platform::syscall::SysError>>,
    ) -> Result<T, platform::syscall::SysError> {
        panic!("metadata tests must not issue native IPC")
    }
}

#[test]
fn application_metadata_inherits_only_the_locally_owned_attached_endpoint() {
    let bytes = production::metadata(
        "/app",
        &["argument".into(), "__MNU_EXEC_ENV=HOME=/home/test".into()],
        73,
        [9; 16],
    )
    .unwrap();
    let request = mnu_abi::process_create::decode(&bytes).unwrap();
    assert_eq!(request.identity, "/app");
    assert_eq!(
        request.handles().collect::<Vec<_>>(),
        [mnu_abi::process_create::HandleGrant {
            key: mochios_posix_protocol::CONTROL_HANDLE_KEY,
            source: 73,
            rights: mnu_abi::HANDLE_RIGHT_SEND
                | mnu_abi::HANDLE_RIGHT_DUPLICATE
                | mnu_abi::HANDLE_RIGHT_TRANSFER,
        }]
    );
    assert!(request.values().next().is_none());
    let mnu_abi::process_create::InitialState::Image(startup) = request.startup else {
        panic!("expected image")
    };
    assert!(
        !startup
            .stack()
            .windows(11)
            .any(|part| part == b"__MNU_EXEC_")
    );
}

#[test]
fn remote_arguments_cannot_select_local_handles_or_security_identity() {
    for argument in [
        "__MNU_EXEC_INHERIT_HANDLE=1:73:1",
        "__MNU_EXEC_ID_PACKAGE=root",
        "__MNU_EXEC_INHERIT_VALUE=1:0",
        "__MNU_EXEC_ENV=invalid",
        "__MNU_EXEC_ENV==value",
        "bad\0argument",
    ] {
        assert!(production::metadata("/app", &[argument.into()], 73, [9; 16]).is_err());
    }
    assert!(production::metadata("/app", &[], 0, [9; 16]).is_err());
}

#[test]
fn full_executable_identity_is_not_limited_by_the_display_label() {
    let path = "/system/applications/SystemMonitor.app/entry.elf";
    let bytes = production::metadata(path, &[], 73, [9; 16]).unwrap();
    let request = mnu_abi::process_create::decode(&bytes).unwrap();
    assert_eq!(request.identity, path);
    assert_eq!(request.label, "SystemMonitor.app");
    let path = format!("/applications/{}.app/entry.elf", "あ".repeat(20));
    let bytes = production::metadata(&path, &[], 73, [9; 16]).unwrap();
    let request = mnu_abi::process_create::decode(&bytes).unwrap();
    assert_eq!(request.identity, path);
    assert!(request.label.len() <= mnu_abi::process_create::MAX_LABEL_BYTES);
}

#[test]
fn application_launch_uses_native_creation_and_registers_before_resume() {
    let source = include_str!("../../capability/src/native_app.rs");
    assert!(
        source.find("register_launched_child(").unwrap() < source.find("resume_handle(").unwrap()
    );
    assert!(source.contains("create_stopped(image.0, &metadata)"));
    assert!(source.contains("terminate_handle(process.0, 127)"));
    assert!(source.contains("process_id != expected_requester"));
    let spawn = include_str!("../../capability/src/app_spawn.rs");
    assert!(!spawn.contains("spawn_manifest_for_requester"));
    assert!(!spawn.contains("encode_identity_args"));
    for source in [
        include_str!("../../workspace/src/main.rs"),
        include_str!("../../../applications/binder/src/platform/mochios.rs"),
    ] {
        let compact: String = source
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        assert!(compact.contains("call_object_handles(destination,&request,&mutreply,&muthandles"));
    }
}

#[test]
fn retired_requester_launch_has_no_kernel_abi_dispatch_or_wrapper() {
    let name = concat!("ExecManifest", "ForRequester");
    for source in [
        include_str!("../../../core/crates/abi/src/lib.rs"),
        include_str!("../../../core/src/syscall/mod.rs"),
        include_str!("../../../core/src/syscall/exec.rs"),
        include_str!("../../../user/crates/platform/src/lib.rs"),
    ] {
        assert!(!source.contains(name));
        assert!(!source.contains(concat!("ExecManifest", "Requester")));
        assert!(!source.contains(concat!("exec_manifest_", "for_requester")));
        assert!(!source.contains(concat!("spawn_manifest_", "for_requester")));
    }
}
