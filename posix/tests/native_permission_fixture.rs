#[test]
#[ignore = "requires POSIX_NATIVE_FIXTURE_DIR; isolated KVM fixture only"]
fn generate_permission_prompt_fixture() {
    use mnu_abi::process_create::{self, HandleGrant};
    use mochios_signature_protocol::{InstallProvenance, InstallRecord, VerifiedResponse};
    use sha2::{Digest, Sha256};
    let directory = std::path::PathBuf::from(std::env::var_os("POSIX_NATIVE_FIXTURE_DIR").unwrap());
    let manifest = br#"[package]
provenance = "built-in"
id = "org.mochios.input"
name = "Native Permission Prompt Probe"
version = "1"
vendor = "mochiOS"
[[binary]]
path = "/system/services/input.service"
kind = "service"
requires = ["fs.read.all", "ipc.client", "ipc.server", "process.spawn"]
"#;
    let digest: [u8; 32] = Sha256::digest(manifest).into();
    let caps = ["fs.read.all", "ipc.client", "ipc.server", "process.spawn"];
    let record = InstallRecord {
        provenance: InstallProvenance::BuiltIn,
        verification: VerifiedResponse {
            request_id: 0,
            provenance: InstallProvenance::BuiltIn,
            certificate_serial: 0,
            subject_key_id: [0; 32],
            manifest_digest: digest,
            package_digest: digest,
            developer_id: "org.mochios.system",
            verified_package_id: "org.mochios.input",
            allowed_capabilities: &caps,
        },
    };
    let mut verification = vec![0; record.encoded_len()];
    record.encode(&mut verification).unwrap();
    let executable = b"/system/services/secure-ui.service";
    let mut startup = vec![0; process_create::MAX_REQUEST_BYTES];
    let length = mochios_posix_client::process_image::encode_initial_stack(
        &[
            b"secure-ui.service",
            b"--permission-prompt-server",
            b"--permission-prompt-token=123",
            b"--service-ready=00000000000000000000:123",
        ],
        &[],
        executable,
        [7; 16],
        &mut startup,
    )
    .unwrap();
    let mut metadata = vec![0; process_create::MAX_REQUEST_BYTES];
    let length = process_create::encode(
        std::str::from_utf8(executable).unwrap(),
        "secure-ui.service",
        &startup[..length],
        &[HandleGrant {
            key: u64::from_le_bytes(*b"POSXCTRL"),
            source: 1,
            rights: mnu_abi::HANDLE_RIGHT_SEND
                | mnu_abi::HANDLE_RIGHT_TRANSFER
                | mnu_abi::HANDLE_RIGHT_DUPLICATE,
        }],
        &[],
        &mut metadata,
    )
    .unwrap();
    std::fs::write(directory.join("permission-probe-manifest.toml"), manifest).unwrap();
    std::fs::write(
        directory.join("permission-probe-verification.bin"),
        verification,
    )
    .unwrap();
    std::fs::write(
        directory.join("permission-probe-metadata.bin"),
        &metadata[..length],
    )
    .unwrap();
    let executable = b"/system/services/input.service";
    let length = mochios_posix_client::process_image::encode_initial_stack(
        &[b"fresh-spawn-probe", b"--credential-child"],
        &[],
        executable,
        [7; 16],
        &mut startup,
    )
    .unwrap();
    let length = process_create::encode(
        std::str::from_utf8(executable).unwrap(),
        "fresh-spawn-probe",
        &startup[..length],
        &[HandleGrant {
            key: u64::from_le_bytes(*b"POSXCTRL"),
            source: 1,
            rights: mnu_abi::HANDLE_RIGHT_SEND
                | mnu_abi::HANDLE_RIGHT_TRANSFER
                | mnu_abi::HANDLE_RIGHT_DUPLICATE,
        }],
        &[],
        &mut metadata,
    )
    .unwrap();
    std::fs::write(
        directory.join("spawn-probe-metadata.bin"),
        &metadata[..length],
    )
    .unwrap();
}

#[test]
fn permission_probe_matches_native_abi_and_never_edits_real_ui_policy() {
    use mnu_abi::SyscallNumber as Call;
    let source = include_str!("native_permission_prompt.c");
    for (name, call) in [
        ("PROCESS_CREATE", Call::ProcessCreate),
        ("IPC_RECV_HANDLES", Call::IpcRecvObjectHandles),
        ("IPC_CALL_HANDLES", Call::IpcCallObjectHandles),
    ] {
        assert!(source.contains(&format!("{name} = {}", call as u64)));
    }
    assert!(source.contains("scenario == 0 ? 124 : 123"));
    let compact: String = source.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(compact.contains("handles.entries[0].rights=1;"));
    assert!(compact.contains(&format!(
        "registration[6]={};",
        mochios_posix_protocol::OP_PROCESS_SPAWNED
    )));
}
