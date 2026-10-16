use mnu_abi::{process_create as wire, process_image};
use wire::{Error, HandleGrant, Value};

fn startup() -> Vec<u8> {
    let mut bytes = vec![0; 128];
    let length = process_image::encode(0, &[0; 32], &[], &mut bytes).unwrap();
    bytes.truncate(length);
    bytes
}

#[test]
fn captured_handle_header_preserves_payload_and_explicit_grants() {
    let grants = [HandleGrant {
        key: 71,
        source: 3,
        target: 9,
        rights: 1,
    }];
    let values = [Value { key: 19, value: 23 }];
    let original = metadata(&grants, &values);
    assert_eq!(wire::decode(&original).unwrap().handle_capture, None);
    let mut bytes = original.clone();
    bytes.resize(original.len() + 8, 0xa5);
    let length = wire::attach_handle_capture(&mut bytes, original.len(), 47).unwrap();
    assert_eq!(length, original.len() + 8);
    let decoded = wire::decode(&bytes[..length]).unwrap();
    assert_eq!(decoded.handle_capture, Some(47));
    assert_eq!(decoded.handles().collect::<Vec<_>>(), grants);
    assert_eq!(decoded.values().collect::<Vec<_>>(), values);
    assert_eq!(decoded.identity, "opaque identity");
    assert_eq!(
        &bytes[wire::CAPTURE_HEADER_LEN..length],
        &original[wire::HEADER_LEN..]
    );
    for offset in [32, 36] {
        let mut invalid = bytes.clone();
        if offset == 32 {
            invalid[32..36].fill(0);
        } else {
            invalid[36] = 1;
        }
        assert!(matches!(wire::decode(&invalid), Err(Error::Header)));
    }
    let before = bytes.clone();
    assert_eq!(
        wire::attach_handle_capture(&mut bytes, length, 48),
        Err(Error::Handle)
    );
    assert_eq!(bytes, before);
}

#[test]
fn capture_header_attachment_failures_do_not_modify_storage() {
    let original = metadata(&[], &[]);
    for capture in [0, 9] {
        let mut bytes = original.clone();
        let before = bytes.clone();
        assert!(wire::attach_handle_capture(&mut bytes, original.len(), capture).is_err());
        assert_eq!(bytes, before);
    }
    let mut bytes = original.clone();
    assert_eq!(
        wire::attach_handle_capture(&mut bytes, usize::MAX, 9),
        Err(Error::Length)
    );
    assert_eq!(bytes, original);
    bytes.resize(original.len() + 8, 0xa5);
    let before = bytes.clone();
    assert_eq!(
        wire::attach_handle_capture(&mut bytes, original.len(), 0),
        Err(Error::Handle)
    );
    assert_eq!(bytes, before);
    bytes[4] = 99;
    let before = bytes.clone();
    assert!(wire::attach_handle_capture(&mut bytes, original.len(), 9).is_err());
    assert_eq!(bytes, before);
}

#[test]
fn captured_table_is_supported_for_native_context_creation() {
    let context = mnu_abi::ThreadCreateContext {
        entry: 0x1000,
        stack_pointer: 0x8000,
        ..Default::default()
    };
    let mut bytes = [0u8; 512];
    let length = wire::encode_context("identity", "label", &context, &[], &[], &mut bytes).unwrap();
    let length = wire::attach_handle_capture(&mut bytes, length, 61).unwrap();
    let decoded = wire::decode(&bytes[..length]).unwrap();
    assert_eq!(decoded.handle_capture, Some(61));
    assert!(matches!(decoded.startup, wire::InitialState::Context(value) if value == context));
    assert!(matches!(wire::decode(&bytes[..39]), Err(Error::Header)));
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
        target: 0,
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
    let wire::InitialState::Image(startup) = request.startup else {
        panic!("expected image")
    };
    assert_eq!(startup.stack(), [0; 32]);
    assert_eq!(request.handles().collect::<Vec<_>>(), handles);
    assert_eq!(request.values().collect::<Vec<_>>(), values);
    // Handle and value keys are independent opaque namespaces.
    assert_eq!(
        request.handles().next().unwrap().key,
        request.values().next().unwrap().key
    );
}

fn explicit_context() -> mnu_abi::ThreadCreateContext {
    mnu_abi::ThreadCreateContext {
        entry: 0x12345000,
        stack_pointer: 0x56789000,
        argument: 0xabcdef0123456789,
        thread_local_base: 0x45678000,
        registers: mnu_abi::ThreadInitialRegisters {
            rax: 1,
            rbx: 2,
            rcx: 3,
            rdx: 4,
            rsi: 5,
            rbp: 6,
            r8: 7,
            r9: 8,
            r10: 9,
            r11: 10,
            r12: 11,
            r13: 12,
            r14: 13,
            r15: 14,
        },
        ..Default::default()
    }
}

#[test]
fn context_creation_roundtrips_all_registers_and_explicit_grants() {
    assert_eq!(
        wire::CONTEXT_LEN,
        core::mem::size_of::<mnu_abi::ThreadCreateContext>()
    );
    let context = explicit_context();
    let handles = [HandleGrant {
        key: 19,
        source: 3,
        target: 0,
        rights: 1,
    }];
    let values = [Value {
        key: 20,
        value: u64::MAX,
    }];
    let mut bytes = vec![0; wire::MAX_REQUEST_BYTES];
    let length =
        wire::encode_context("identity", "label", &context, &handles, &values, &mut bytes).unwrap();
    let request = wire::decode(&bytes[..length]).unwrap();
    assert_eq!(request.startup, wire::InitialState::Context(context));
    assert_eq!(request.handles().collect::<Vec<_>>(), handles);
    assert_eq!(request.values().collect::<Vec<_>>(), values);
    let start = wire::HEADER_LEN + "identity".len() + "label".len();
    assert_eq!(&bytes[start..start + 8], &context.entry.to_le_bytes());
    assert_eq!(
        &bytes[start + 64..start + 72],
        &context.registers.rax.to_le_bytes()
    );
    assert_eq!(
        &bytes[start + 168..start + 176],
        &context.registers.r15.to_le_bytes()
    );
}

#[test]
fn context_has_no_privileged_flags_reserved_words_or_ambiguous_image_form() {
    let context = explicit_context();
    let mut bytes = vec![0; wire::MAX_REQUEST_BYTES];
    for field in 0..6 {
        let mut invalid = context;
        match field {
            0 => invalid.entry = 0,
            1 => invalid.stack_pointer = 15,
            2 => invalid.flags = 0x3000,
            index => invalid.reserved[index - 3] = 1,
        }
        assert_eq!(
            wire::encode_context("x", "y", &invalid, &[], &[], &mut bytes),
            Err(Error::Startup)
        );
    }
    let length = wire::encode_context("x", "y", &context, &[], &[], &mut bytes).unwrap();
    for truncated in 0..length {
        assert!(wire::decode(&bytes[..truncated]).is_err());
    }
    bytes[28..32].copy_from_slice(&0u32.to_le_bytes());
    assert!(wire::decode(&bytes[..length]).is_err());
    bytes[28..32].copy_from_slice(&2u32.to_le_bytes());
    assert!(matches!(wire::decode(&bytes[..length]), Err(Error::Header)));
    let mut image = metadata(&[], &[]);
    image[28..32].copy_from_slice(&1u32.to_le_bytes());
    assert!(matches!(wire::decode(&image), Err(Error::Startup)));
}

#[test]
fn snapshot_creation_requires_authorization_and_control_before_vm_consumption() {
    let exec = include_str!("../../../core/src/syscall/exec.rs");
    let native = &exec[exec.find("pub fn process_create_syscall(").unwrap()..];
    assert!(
        native
            .find("take_exec_authorization(request.identity, thread)")
            .unwrap()
            < native.find("return create_from_address_space(").unwrap()
    );
    let create = &native[native.find("fn create_from_address_space(").unwrap()..];
    assert!(
        create.find("HandleRights::CONTROL").unwrap()
            < create
                .find("consume_address_space_for_create(&image, &authorization, &context)")
                .unwrap()
    );
    assert!(
        create.find("retain_created_process(&process)").unwrap()
            < create.find("add_process(process)").unwrap()
    );
    assert!(create.find("thread.suspend()").unwrap() < create.find("add_thread(thread)").unwrap());
    for forbidden in [
        "clone_object_handles",
        "clone_launch_context",
        "resource_limits()",
        "find_process",
        "parent_id",
    ] {
        assert!(!create.contains(forbidden));
    }
}

#[test]
fn duplicate_keys_and_invalid_handles_are_rejected() {
    let mut output = vec![0; wire::MAX_REQUEST_BYTES];
    let grant = HandleGrant {
        key: 9,
        source: 12,
        target: 0,
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
fn explicit_native_slots_and_duplicate_wire_keys_are_validated() {
    let grant = HandleGrant {
        key: 7,
        source: 2,
        target: 0,
        rights: 3,
    };
    let offset =
        wire::HEADER_LEN + "opaque identity".len() + "display label".len() + startup().len();
    let mut bytes = metadata(&[grant], &[]);
    bytes[offset + 12] = 1;
    assert_eq!(
        wire::decode(&bytes)
            .unwrap()
            .handles()
            .next()
            .unwrap()
            .target,
        1
    );
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
            target: 0,
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
fn explicit_slots_roundtrip_and_duplicate_targets_are_rejected() {
    let mut output = vec![0; wire::MAX_REQUEST_BYTES];
    let grants = [
        HandleGrant {
            key: 7,
            source: 2,
            target: 41,
            rights: 1,
        },
        HandleGrant {
            key: 8,
            source: 2,
            target: 0,
            rights: 0,
        },
        HandleGrant {
            key: 9,
            source: 2,
            target: 1,
            rights: 1,
        },
    ];
    let length = wire::encode("x", "y", &startup(), &grants, &[], &mut output).unwrap();
    assert_eq!(
        wire::decode(&output[..length])
            .unwrap()
            .handles()
            .collect::<Vec<_>>(),
        grants
    );
    let length =
        wire::encode_context("x", "y", &explicit_context(), &grants, &[], &mut output).unwrap();
    assert_eq!(
        wire::decode(&output[..length])
            .unwrap()
            .handles()
            .collect::<Vec<_>>(),
        grants
    );
    let duplicate = [
        grants[0],
        HandleGrant {
            target: 41,
            ..grants[1]
        },
    ];
    assert_eq!(
        wire::encode_context("x", "y", &explicit_context(), &duplicate, &[], &mut output),
        Err(Error::DuplicateTarget)
    );
    let mut tampered = metadata(&grants, &[]);
    let offset =
        wire::HEADER_LEN + "opaque identity".len() + "display label".len() + startup().len();
    tampered[offset + wire::HANDLE_LEN + 12..offset + wire::HANDLE_LEN + 16]
        .copy_from_slice(&41u32.to_le_bytes());
    assert!(matches!(
        wire::decode(&tampered),
        Err(Error::DuplicateTarget)
    ));
}

#[test]
fn explicit_placement_cannot_overwrite_entries_or_capture_a_foreign_table() {
    let table = include_str!("../../../core/src/task/handle_table.rs");
    let insert =
        &table[table.find("pub fn insert_at(").unwrap()..table.find("pub fn retain(").unwrap()];
    assert!(insert.contains("PROCESS_MAX_OBJECT_HANDLES"));
    // Actual occupied-slot rejection and reference preservation are exercised
    // against production storage by handle_storage_native.rs. Here also check
    // that admission precedes reservation/publication in the current layout.
    let vacant = insert.find("let Err(index)").unwrap();
    let reserve = insert.find("try_reserve(1)").unwrap();
    let publish = insert.find("self.entries.insert(index, (handle, entry))").unwrap();
    assert!(vacant < reserve && reserve < publish);
    let exec = include_str!("../../../core/src/syscall/exec.rs");
    let install = &exec[exec.find("fn install_inherited_handles(").unwrap()
        ..exec.find("fn install_inherited_values(").unwrap()];
    assert!(
        install.find("grant.target != 0").unwrap() < install.find("grant.target == 0").unwrap()
    );
    assert!(install.contains("insert_at(handle, grant.entry.clone())"));
    assert!(!install.contains("source_process"));
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
        "ImageLaunch::Created(startup)",
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
            target: 0,
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
