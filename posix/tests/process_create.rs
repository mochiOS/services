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
    let length = wire::encode("opaque identity", &startup(), handles, values, &mut bytes).unwrap();
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
        wire::encode("x", &startup(), &[grant, grant], &[], &mut output),
        Err(Error::DuplicateKey)
    );
    assert_eq!(
        wire::encode(
            "x",
            &startup(),
            &[HandleGrant { source: 0, ..grant }],
            &[],
            &mut output
        ),
        Err(Error::Handle)
    );
    let value = Value { key: 1, value: 0 };
    assert_eq!(
        wire::encode("x", &startup(), &[], &[value, value], &mut output),
        Err(Error::DuplicateKey)
    );
}

#[test]
fn version_reserved_fields_and_lengths_are_strict() {
    let original = metadata(&[], &[]);
    for offset in [0, 4, 6, 24, 31] {
        let mut bytes = original.clone();
        bytes[offset] ^= 1;
        assert!(wire::decode(&bytes).is_err());
    }
    for offset in [8, 12, 16, 20] {
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
        wire::encode("", &startup(), &[], &[], &mut output),
        Err(Error::Length)
    );
    assert_eq!(
        wire::encode("x\0y", &startup(), &[], &[], &mut output),
        Err(Error::Identity)
    );
    assert_eq!(
        wire::encode("x", &[0; 64], &[], &[], &mut output),
        Err(Error::Startup)
    );
    assert_eq!(
        wire::encode("x", &startup(), &[], &[], &mut [0; 8]),
        Err(Error::BufferTooSmall)
    );
    let mut bytes = metadata(&[], &[]);
    bytes[wire::HEADER_LEN] = 0xff;
    assert!(matches!(wire::decode(&bytes), Err(Error::Identity)));
}

#[test]
fn handle_record_reserved_bits_and_duplicate_wire_keys_are_rejected() {
    let grant = HandleGrant {
        key: 7,
        source: 2,
        rights: 3,
    };
    let offset = wire::HEADER_LEN + "opaque identity".len() + startup().len();
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

/// Generates only the built-in package record for the isolated native probe.
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
    let caps = ["fs.read.all", "fs.write.all", "ipc.client", "process.spawn"];
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
    std::fs::write(
        directory.join("process-create-probe-verification.bin"),
        output,
    )
    .unwrap();
}
