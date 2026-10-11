use mnu_abi::{process_create as wire, process_image};
use wire::{Error, HandleGrant, Value};

fn startup() -> Vec<u8> {
    let mut bytes = vec![0; 128];
    let length = process_image::encode(0, &[0; 32], &[], &mut bytes).unwrap();
    bytes.truncate(length);
    bytes
}

fn metadata(handles: &[HandleGrant], values: &[Value]) -> Vec<u8> {
    let mut bytes = vec![0; wire::MAX_REQUEST_BYTES];
    let length = wire::encode(
        "opaque identity",
        "display label",
        &startup(),
        handles,
        values,
        &mut bytes,
    )
    .unwrap();
    bytes.truncate(length);
    bytes
}

#[test]
fn creation_metadata_is_relocatable_and_has_no_foreign_pid_or_fd() {
    let handles = [HandleGrant {
        key: u64::MAX,
        source: 17,
        rights: 3,
    }];
    let values = [Value {
        key: u64::MAX,
        value: 91,
    }];
    let bytes = metadata(&handles, &values);
    let request = wire::decode(&bytes).unwrap();
    assert_eq!(request.identity, "opaque identity");
    assert_eq!(request.label, "display label");
    assert_eq!(request.startup.stack(), [0; 32]);
    assert_eq!(request.handles().collect::<Vec<_>>(), handles);
    assert_eq!(request.values().collect::<Vec<_>>(), values);
    // Handle and value keys are independent opaque namespaces.
    assert_eq!(
        request.handles().next().unwrap().key,
        request.values().next().unwrap().key
    );
}

#[test]
fn duplicate_keys_and_invalid_handles_are_rejected() {
    let mut output = vec![0; wire::MAX_REQUEST_BYTES];
    let grant = HandleGrant {
        key: 9,
        source: 12,
        rights: 3,
    };
    assert_eq!(
        wire::encode("x", "label", &startup(), &[grant, grant], &[], &mut output),
        Err(Error::DuplicateKey)
    );
    assert_eq!(
        wire::encode(
            "x",
            "label",
            &startup(),
            &[HandleGrant { source: 0, ..grant }],
            &[],
            &mut output
        ),
        Err(Error::Handle)
    );
    let value = Value { key: 1, value: 0 };
    assert_eq!(
        wire::encode("x", "label", &startup(), &[], &[value, value], &mut output),
        Err(Error::DuplicateKey)
    );
}

#[test]
fn version_reserved_fields_and_lengths_are_strict() {
    let original = metadata(&[], &[]);
    for offset in [0, 4, 6, 28, 31] {
        let mut bytes = original.clone();
        bytes[offset] ^= 1;
        assert!(wire::decode(&bytes).is_err());
    }
    for offset in [8, 12, 16, 20, 24] {
        let mut bytes = original.clone();
        bytes[offset..offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(wire::decode(&bytes).is_err());
    }
    for length in 0..original.len() {
        assert!(wire::decode(&original[..length]).is_err());
    }
    let mut bytes = original;
    bytes.push(0);
    assert!(wire::decode(&bytes).is_err());
}

#[test]
fn identity_and_embedded_startup_are_validated() {
    let mut output = vec![0; wire::MAX_REQUEST_BYTES];
    assert_eq!(
        wire::encode("", "label", &startup(), &[], &[], &mut output),
        Err(Error::Length)
    );
    assert_eq!(
        wire::encode("x\0y", "label", &startup(), &[], &[], &mut output),
        Err(Error::Identity)
    );
    assert_eq!(
        wire::encode("x", "label", &[0; 64], &[], &[], &mut output),
        Err(Error::Startup)
    );
    assert_eq!(
        wire::encode("x", "label", &startup(), &[], &[], &mut [0; 8]),
        Err(Error::BufferTooSmall)
    );
    let mut bytes = metadata(&[], &[]);
    bytes[wire::HEADER_LEN] = 0xff;
    assert!(matches!(wire::decode(&bytes), Err(Error::Identity)));
}

#[test]
fn creation_label_is_bounded_text_and_never_an_authorization_identity() {
    let mut output = vec![0; wire::MAX_REQUEST_BYTES];
    for label in ["", &"x".repeat(wire::MAX_LABEL_BYTES + 1)] {
        assert_eq!(
            wire::encode("authorized", label, &startup(), &[], &[], &mut output),
            Err(Error::Length)
        );
    }
    assert_eq!(
        wire::encode("authorized", "x\0y", &startup(), &[], &[], &mut output),
        Err(Error::Label)
    );
    let label = "あ".repeat(10);
    let length = wire::encode("authorized", &label, &startup(), &[], &[], &mut output).unwrap();
    assert_eq!(wire::decode(&output[..length]).unwrap().label, label);
    output[wire::HEADER_LEN + "authorized".len()] = 0xff;
    assert!(matches!(wire::decode(&output[..length]), Err(Error::Label)));
    let mut bytes = metadata(&[], &[]);
    bytes[4..6].copy_from_slice(&1u16.to_le_bytes());
    assert!(matches!(wire::decode(&bytes), Err(Error::Header)));
    let exec = include_str!("../../../core/src/syscall/exec.rs");
    let native = &exec[exec.find("pub fn process_create_syscall(").unwrap()..];
    assert!(native.contains("take_exec_authorization(request.identity, thread)"));
    assert!(!native.contains("take_exec_authorization(request.label"));
    assert!(native.contains("request.label,\n        request.identity,"));
}

#[test]
fn handle_record_reserved_bits_and_duplicate_wire_keys_are_rejected() {
    let grant = HandleGrant {
        key: 7,
        source: 2,
        rights: 3,
    };
    let offset =
        wire::HEADER_LEN + "opaque identity".len() + "display label".len() + startup().len();
    let mut bytes = metadata(&[grant], &[]);
    bytes[offset + 12] = 1;
    assert!(matches!(wire::decode(&bytes), Err(Error::Handle)));
    let mut bytes = metadata(&[grant, HandleGrant { key: 8, ..grant }], &[]);
    bytes[offset + wire::HANDLE_LEN..offset + wire::HANDLE_LEN + 8]
        .copy_from_slice(&7u64.to_le_bytes());
    assert!(matches!(wire::decode(&bytes), Err(Error::DuplicateKey)));
}

#[test]
fn maximum_opaque_context_round_trips() {
    let handles: Vec<_> = (0..wire::MAX_HANDLES)
        .map(|key| HandleGrant {
            key: key as u64,
            source: 1,
            rights: 0,
        })
        .collect();
    let values: Vec<_> = (0..wire::MAX_VALUES)
        .map(|key| Value {
            key: key as u64,
            value: key as u64,
        })
        .collect();
    let bytes = metadata(&handles, &values);
    assert_eq!(
        wire::decode(&bytes).unwrap().handles().count(),
        handles.len()
    );
    assert_eq!(wire::decode(&bytes).unwrap().values().count(), values.len());
}

#[test]
fn creation_backend_retains_before_publication_and_never_weakens_grants() {
    assert_eq!(mnu_abi::SyscallNumber::ProcessCreate as u64, 676);
    let exec = include_str!("../../../core/src/syscall/exec.rs");
    let start = exec.find("fn exec_with_data(").unwrap();
    let body = &exec[start..exec.find("fn replace_current_process_image(").unwrap()];
    assert!(
        body.find("retain_created_process(&proc)").unwrap()
            < body.find("add_process(proc)").unwrap()
    );
    assert!(body.find("thread.suspend()").unwrap() < body.find("add_thread(thread)").unwrap());
    let native = &exec[exec.find("pub fn process_create_syscall(").unwrap()..];
    for required in [
        "caller_has_process_spawn_capability()",
        "PendingExecKind::Spawn",
        "take_exec_authorization(request.identity, thread)",
        "read_all(image_handle",
        "authorization.executable_digest",
        "export_inherited_handles(Some(owner), &specs)",
        "Some(request.startup)",
    ] {
        assert!(native.contains(required));
    }
    for forbidden in [
        "load_exec_image(",
        "process_alias_for_executable(",
        "ensure_fs_path_executable",
        "FindProcessByName",
    ] {
        assert!(!native.contains(forbidden));
    }
    let export = &exec[exec.find("fn export_inherited_handles(").unwrap()
        ..exec.find("fn install_inherited_handles(").unwrap()];
    assert!(export.contains("HandleRights::TRANSFER"));
    assert!(export.contains("source.rights().contains(spec.rights)"));
}

/// Generates the built-in package record and startup metadata for the isolated native probe.
/// It never modifies an installed package or relaxes production verification.
#[test]
#[ignore = "requires POSIX_NATIVE_FIXTURE_DIR containing the test-only manifest"]
fn generate_native_creation_fixture_record() {
    use mochios_signature_protocol::{InstallProvenance, InstallRecord, VerifiedResponse};
    use sha2::{Digest, Sha256};

    let directory = std::path::PathBuf::from(std::env::var_os("POSIX_NATIVE_FIXTURE_DIR").unwrap());
    let manifest = std::fs::read(directory.join("process-create-probe-manifest.toml")).unwrap();
    let text = std::str::from_utf8(&manifest).unwrap();
    assert!(text.contains("id = \"org.mochios.input\""));
    assert!(text.contains("name = \"Native Process Creation Probe\""));
    let digest: [u8; 32] = Sha256::digest(&manifest).into();
    let caps = [
        "fs.read.all",
        "fs.write.all",
        "ipc.client",
        "process.spawn",
        "process.inspect",
    ];
    let verified = VerifiedResponse {
        request_id: 0,
        provenance: InstallProvenance::BuiltIn,
        certificate_serial: 0,
        subject_key_id: [0; 32],
        manifest_digest: digest,
        package_digest: digest,
        developer_id: "org.mochios.system",
        verified_package_id: "org.mochios.input",
        allowed_capabilities: &caps,
    };
    let record = InstallRecord {
        provenance: InstallProvenance::BuiltIn,
        verification: verified,
    };
    let mut output = vec![0; record.encoded_len()];
    record.encode(&mut output).unwrap();
    let executable = b"/system/services/input.service";
    let mut startup = vec![0; 16384];
    let length = mochios_posix_client::process_image::encode_initial_stack(
        &[b"native-process-create", b"--created-child"],
        &[],
        executable,
        [7; 16],
        &mut startup,
    )
    .unwrap();
    let mut metadata = vec![0; wire::MAX_REQUEST_BYTES];
    let length = wire::encode(
        std::str::from_utf8(executable).unwrap(),
        "native-create-child",
        &startup[..length],
        &[HandleGrant {
            key: u64::from_le_bytes(*b"TESTFILE"),
            source: 1,
            rights: mnu_abi::HANDLE_RIGHT_READ,
        }],
        &[Value {
            key: u64::from_le_bytes(*b"TESTVALU"),
            value: 42,
        }],
        &mut metadata,
    )
    .unwrap();
    std::fs::write(
        directory.join("process-create-probe-metadata.bin"),
        &metadata[..length],
    )
    .unwrap();
    std::fs::write(
        directory.join("process-create-probe-verification.bin"),
        output,
    )
    .unwrap();
}

#[test]
fn native_creation_probe_uses_the_current_mechanism_abi() {
    use mnu_abi::SyscallNumber as Call;
    let source = include_str!("native_process_create.c");
    for (name, call) in [
        ("PROCESS_CREATE", Call::ProcessCreate),
        ("PROCESS_EXIT", Call::ProcessExit),
        ("IPC_CALL_HANDLES", Call::IpcCallObjectHandles),
        ("PROCESS_STATUS", Call::ProcessHandleStatus),
        ("PROCESS_WAIT", Call::ProcessHandleWait),
        ("PROCESS_RESUME", Call::ProcessHandleResume),
        ("LAUNCH_HANDLE_GET", Call::LaunchHandleGet),
        ("LAUNCH_VALUE_GET", Call::LaunchValueGet),
        ("HANDLE_READ_AT", Call::HandleReadAt),
        ("HANDLE_DUPLICATE", Call::HandleDuplicate),
        ("HANDLE_RIGHTS", Call::HandleRightsGet),
    ] {
        assert!(source.contains(&format!("{name} = {}", call as u64)));
    }
}

#[test]
fn native_tree_probe_attaches_objects_and_preserves_an_unrelated_live_owner() {
    use mochios_posix_protocol as protocol;
    let source = include_str!("native_process_create.c");
    for (name, opcode) in [
        ("ROOT_REGISTER", protocol::OP_PROCESS_SPAWNED),
        ("CHILD_ADOPT", protocol::OP_PROCESS_LAUNCHED),
        ("LAUNCH_ABORT", protocol::OP_PROCESS_LAUNCH_ABORT),
        ("TREE_EXIT", protocol::OP_PROCESS_TREE_TERMINATE),
        ("TREE_RECLAIM", protocol::OP_PROCESS_TREE_RECLAIM),
    ] {
        assert!(source.contains(&format!("{name} = {opcode}")));
    }
    assert_eq!(mnu_abi::HANDLE_RIGHT_WAIT, 1 << 4);
    assert_eq!(mnu_abi::HANDLE_RIGHT_SIGNAL, 1 << 5);
    assert!(source.contains(&format!(
        "PROCESS_STATE_RUNNING = {}",
        mnu_abi::PROCESS_STATE_RUNNING
    )));
    assert!(source.contains(&format!(
        "PROCESS_STATE_EXITED = {}",
        mnu_abi::PROCESS_STATE_EXITED
    )));
    let rpc = source
        .split("static int32_t tree_rpc(")
        .nth(1)
        .unwrap()
        .split("static int32_t root_rpc(")
        .next()
        .unwrap();
    assert!(rpc.contains("IPC_CALL_HANDLES"));
    assert!(rpc.contains("get64(response + 8) != sequence"));
    assert!(!rpc.contains("PROCESS_STATUS"));
    assert!(!rpc.contains("process_id"));
    let scenario = source.split("static int tree_lifecycle(").nth(1).unwrap();
    assert!(scenario.contains("TREE_RECLAIM, root) == -EAGAIN"));
    assert!(scenario.contains("TREE_RECLAIM, root) == -ESRCH"));
    assert!(scenario.contains("PROCESS_STATUS, bystander, &status, 0) == 0 && status.state == 1"));
    assert!(scenario.contains("status.exit_code == 1"));
    assert!(scenario.contains("status.exit_code == 127"));
    assert!(scenario.contains("PROCESS_RESUME, root"));
    assert!(scenario.contains("PROCESS_RESUME, descendant"));
    assert!(scenario.contains(
        "PROCESS_STATUS, root, &status, 0) == 0 && status.state == PROCESS_STATE_RUNNING"
    ));
    let manifest = include_str!("native-tree-lifecycle-manifest.toml");
    assert!(manifest.contains("\"process.spawn\""));
    assert!(!manifest.contains("fs.write.all"));
}
