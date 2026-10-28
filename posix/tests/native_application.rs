extern crate alloc;
#[allow(dead_code)]
#[path = "../../capability/src/app_image.rs"]
mod app_image;
#[allow(dead_code)]
#[path = "../../capability/src/image_catalog.rs"]
mod image_catalog;
#[allow(dead_code)]
#[path = "../../capability/src/native_app.rs"]
mod production;

// These tests exercise startup encoding only. The actual application launch
// boundary, including package policy, is covered by the native IPC probe.
mod resolver {
    pub(crate) struct ApplicationIdentity;
    pub(crate) struct VerifiedManifest {
        pub manifest: mochi_user_platform::package::PackageManifest,
        pub identity: ApplicationIdentity,
    }
    pub(crate) fn authorize_spawn_image(
        _: u64,
        _: &str,
        _: &ApplicationIdentity,
        _: &[String],
        _: mochi_user_platform::service::ExecutionClass,
        _: &[u8],
    ) -> Result<(), mochi_user_platform::syscall::SysError> {
        panic!("metadata tests must not authorize native images")
    }
}

mod persistent_grant {
    use mochi_user_platform as platform;
    use mochios_posix_client::{Client, ClientError, EndpointTransport};
    pub fn read_file(_: &str) -> Result<Vec<u8>, platform::syscall::SysError> {
        panic!("metadata tests must not read native files")
    }
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
            target: 0,
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
fn application_metadata_accepts_local_prepared_data_and_keeps_remote_items_unprivileged() {
    use mochios_posix_client::process_image::{
        AT_LIFECYCLE_IMAGE, AT_TLS_IMAGE, Executable, Identity, Process,
    };
    let process = Process {
        image: Some(Executable {
            entry: 0x20000180,
            program_headers: 0x20000040,
            program_header_size: 56,
            program_header_count: 5,
            interpreter_base: 0,
            load_bias: 0x20000000,
        }),
        identity: Identity {
            real_uid: 501,
            effective_uid: 0,
            real_gid: 20,
            effective_gid: 20,
        },
        lifecycle: b"life\0",
        tls: b"tls\0",
    };
    let bytes = production::metadata_for_process(
        "/app",
        &[
            "__MNU_EXEC_ENV=LD_PRELOAD=/unsafe".into(),
            "__MNU_EXEC_ENV=KEEP=1".into(),
        ],
        73,
        [9; 16],
        process,
    )
    .unwrap();
    let request = mnu_abi::process_create::decode(&bytes).unwrap();
    assert_eq!(request.identity, "/app");
    let handles: Vec<_> = request.handles().collect();
    assert_eq!(handles.len(), 1);
    assert_eq!(
        (handles[0].source, handles[0].key),
        (73, mochios_posix_protocol::CONTROL_HANDLE_KEY)
    );
    let mnu_abi::process_create::InitialState::Image(startup) = request.startup else {
        panic!("image")
    };
    let stack = startup.stack();
    let word = |index: usize| {
        u64::from_le_bytes(stack[index * 8..index * 8 + 8].try_into().unwrap()) as usize
    };
    assert_eq!(word(0), 1);
    let environment = &stack[word(3)..];
    assert!(environment.starts_with(b"KEEP=1\0"));
    assert_eq!(word(4), 0);
    let auxiliary: Vec<_> = stack[5 * 8..]
        .chunks_exact(16)
        .take_while(|pair| u64::from_le_bytes(pair[..8].try_into().unwrap()) != 0)
        .map(|pair| {
            (
                u64::from_le_bytes(pair[..8].try_into().unwrap()),
                u64::from_le_bytes(pair[8..].try_into().unwrap()),
            )
        })
        .collect();
    for (key, value) in [
        (3, 0x20000040),
        (9, 0x20000180),
        (11, 501),
        (12, 0),
        (23, 1),
    ] {
        assert!(auxiliary.contains(&(key, value)));
    }
    for (key, payload) in [
        (AT_LIFECYCLE_IMAGE, b"life\0".as_slice()),
        (AT_TLS_IMAGE, b"tls\0"),
    ] {
        let offset = auxiliary.iter().find(|pair| pair.0 == key).unwrap().1 as usize;
        assert_eq!(offset % 8, 0);
        assert_eq!(&stack[offset..offset + payload.len()], payload);
    }
    assert!(
        production::metadata_for_process(
            "/app",
            &["__MNU_EXEC_INHERIT_HANDLE=1:99:1".into()],
            73,
            [9; 16],
            process
        )
        .is_err()
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
        source.find("register_launched_child_in_scope(").unwrap()
            < source.find("resume_handle(").unwrap()
    );
    assert!(source.contains("create_stopped(image, &metadata)"));
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
