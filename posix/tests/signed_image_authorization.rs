//! Actual broker admission and shared signature verifier, with native RAM and
//! authorization mechanisms replaced by observable, fault-injectable adapters.
extern crate alloc;
extern crate mochi_user_platform as platform_real;
extern crate self as mochi_user_platform;
use mochi_user_syscall::{EACCES, NativeError, SysError};
use mochios_capability_protocol::{ProtocolError, signed_image as wire};
use mochios_elf_signature::{sign_adhoc, sign_ed25519};
pub use platform_real::{logln, package};
use sha2::{Digest, Sha256};
use std::cell::RefCell;

#[path = "support/signed_elf.rs"]
mod fixture;
#[allow(dead_code)]
#[path = "../../capability/src/resolver.rs"]
mod resolver;
#[path = "../../capability/src/signed_image.rs"]
mod signed_image;
#[path = "../../capability/src/standalone_image.rs"]
mod standalone_image;
#[allow(dead_code)]
#[path = "../../capability/src/image_catalog.rs"]
mod image_catalog;
#[path = "../../capability/src/installed_image.rs"]
mod installed_image;
#[path = "../../capability/src/object_image.rs"]
mod object_image;

pub mod syscall {
    pub use mochi_user_syscall::*;
}
mod policy {
    #[derive(Default)]
    pub struct AppPromptPolicy {
        pub interactive: std::collections::BTreeSet<String>,
    }
    pub fn needs_app_prompt(policy: &AppPromptPolicy, name: &str) -> bool {
        policy.interactive.contains(name)
    }
    pub fn is_known_capability(name: &str) -> bool {
        mnu_abi::capability::metadata(name).is_some()
    }
}
mod package_index {
    use super::*;
    #[derive(Clone)]
    pub struct PackageRecord {
        pub manifest: package::PackageManifest,
        pub manifest_path: String,
    }
    #[derive(Default)]
    pub struct PackageIndex {
        pub duplicate: bool,
        pub by_binary: std::collections::BTreeMap<String, PackageRecord>,
    }
}
mod state {
    pub struct CapabilityServiceState {
        pub package_index: super::package_index::PackageIndex,
        pub app_prompt_policy: super::policy::AppPromptPolicy,
    }
}
fn empty_state() -> state::CapabilityServiceState {
    state::CapabilityServiceState {
        package_index: Default::default(),
        app_prompt_policy: Default::default(),
    }
}
mod persistent_grant {
    pub fn read_file(path: &str) -> Result<Vec<u8>, super::SysError> {
        super::STATE.with_borrow_mut(|s| {
            s.file_reads.push(path.into());
            s.files
                .get(path)
                .cloned()
                .ok_or_else(|| super::SysError::from_raw(mochi_user_syscall::ENOENT as i64))
        })
    }
}

#[derive(Default)]
struct State {
    allowed: bool,
    bytes: Vec<u8>,
    extent: u64,
    length_error: Option<SysError>,
    read_error: Option<SysError>,
    issue_error: Option<SysError>,
    part_limit: usize,
    bad_count: bool,
    grow: bool,
    length_calls: usize,
    reads: usize,
    issued: Vec<(u64, String, Vec<u8>)>,
    issued_caps: Vec<Vec<u8>>,
    files: std::collections::BTreeMap<String, Vec<u8>>,
    file_reads: Vec<String>,
}
thread_local! { static STATE: RefCell<State> = RefCell::new(State::default()); }

pub mod capability {
    pub use mochios_capability_protocol::{
        decode_authorize_captured_image_request, decode_authorize_exec_object_request, signed_image,
    };
    pub fn check_thread(sender: u64, name: &str) -> Result<u64, crate::SysError> {
        assert_eq!((sender, name), (77, "process.spawn"));
        Ok(crate::STATE.with_borrow(|s| u64::from(s.allowed)))
    }
}
pub mod ipc {
    pub use mnu_abi::{IpcObjectHandle, IpcObjectHandles};
}
pub mod memory_object {
    pub const READONLY_BUFFER_RIGHTS: u64 = mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_MAP;
}
pub mod memory {
    pub fn object_length(handle: u64) -> Result<u64, crate::SysError> {
        assert_eq!(handle, 19);
        crate::STATE.with_borrow_mut(|s| {
            s.length_calls += 1;
            if let Some(error) = s.length_error {
                return Err(error);
            }
            Ok(s.extent)
        })
    }
}
pub mod handle {
    pub const HANDLE_RIGHT_READ: u64 = mnu_abi::HANDLE_RIGHT_READ;
    pub fn read_at(handle: u32, out: &mut [u8], offset: u64) -> Result<usize, crate::SysError> {
        assert_eq!(handle, 19);
        assert!(out.len() <= 256 * 1024);
        crate::STATE.with_borrow_mut(|s| {
            s.reads += 1;
            if let Some(error) = s.read_error {
                return Err(error);
            }
            if s.bad_count {
                return Ok(out.len() + 1);
            }
            if s.grow && offset == s.extent {
                out[0] = 1;
                return Ok(1);
            }
            let tail = s.bytes.get(offset as usize..).unwrap_or(&[]);
            let n = tail.len().min(out.len()).min(s.part_limit);
            out[..n].copy_from_slice(&tail[..n]);
            Ok(n)
        })
    }
}
pub mod service {
    pub use crate::platform_real::service::ExecutionClass;
    pub fn authorize_exec_for_requester(
        sender: u64,
        key: &str,
        fields: &[u8],
        caps: &[u8],
    ) -> Result<u64, crate::SysError> {
        crate::STATE.with_borrow_mut(|s| {
            if let Some(error) = s.issue_error {
                return Err(error);
            }
            s.issued.push((sender, key.into(), fields.to_vec()));
            s.issued_caps.push(caps.to_vec());
            Ok(0)
        })
    }
}

fn setup(bytes: Vec<u8>) -> (Vec<u8>, ipc::IpcObjectHandles) {
    let length = bytes.len() as u64;
    STATE.with_borrow_mut(|s| {
        *s = State {
            allowed: true,
            bytes,
            extent: length,
            part_limit: usize::MAX,
            ..State::default()
        }
    });
    let request = encode(length, None);
    let mut attached = ipc::IpcObjectHandles::default();
    attached.count = 1;
    attached.handles[0] = ipc::IpcObjectHandle {
        handle: 19,
        reserved: 0,
        rights: memory_object::READONLY_BUFFER_RIGHTS,
    };
    (request, attached)
}
fn encode(length: u64, key: Option<&[u8; 32]>) -> Vec<u8> {
    let mut bytes = vec![0; 512];
    let n = wire::encode(
        &wire::Request {
            source_length: length,
            public_key: key,
            identity: "opaque:signed",
        },
        &mut bytes,
    )
    .unwrap();
    bytes.truncate(n);
    bytes
}
fn no_issue() {
    STATE.with_borrow(|s| assert!(s.issued.is_empty()));
}

fn install_code(
    state: &mut state::CapabilityServiceState,
    package_id: &str,
    path: &str,
    code: &[u8],
    kind: &str,
    requires: &[&str],
) {
    use mochios_signature_protocol::{InstallProvenance, InstallRecord, VerifiedResponse};
    let text = format!(
        "[package]\nid='{package_id}'\nname='fixture'\nversion='1'\nprovenance='built-in'\n[[binary]]\npath='{path}'\nkind='{kind}'\nfile='code'\nrequires={requires:?}\n[[file]]\nid='code'\npath='{path}'\ndigest='sha256:{:x}'\nsize={}\nmode='0755'\n",
        Sha256::digest(code),
        code.len()
    );
    let manifest = package::parse_manifest(&text).unwrap();
    let digest = Sha256::digest(text.as_bytes()).into();
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
            verified_package_id: package_id,
            allowed_capabilities: requires,
        },
    };
    let mut bytes = vec![0; record.encoded_len()];
    record.encode(&mut bytes).unwrap();
    let manifest_path = format!("/system/packages/{package_id}/manifest.toml");
    STATE.with_borrow_mut(|s| {
        s.files.insert(
            format!("/system/packages/{package_id}/verification.bin"),
            bytes,
        );
        s.files.insert(manifest_path.clone(), text.into_bytes());
    });
    state.package_index.by_binary.insert(
        path.into(),
        package_index::PackageRecord {
            manifest,
            manifest_path,
        },
    );
}

#[test]
fn both_transports_authenticate_installed_code_and_drop_the_shell_identity() {
    for legacy in [false, true] {
        let code = fixture::unsigned();
        let digest = Sha256::digest(&code).into();
        let (request, mut attached) = setup(code.clone());
        let mut state = empty_state();
        install_code(
            &mut state,
            "org.mochios.fixture",
            "/system/bin/fixture",
            &code,
            "application",
            &["fs.read.all", "process.spawn"],
        );
        // A mutable index copy cannot supply either requirements or identity.
        state
            .package_index
            .by_binary
            .get_mut("/system/bin/fixture")
            .unwrap()
            .manifest
            .binaries[0]
            .requires = vec!["capabilities.manage".into()];
        if legacy {
            let mut request = vec![0; 300];
            let n = mochios_capability_protocol::encode_authorize_exec_object_request(
                "opaque:signed",
                &digest,
                &mut request,
            )
            .unwrap();
            attached.handles[0].rights = handle::HANDLE_RIGHT_READ;
            object_image::authorize(&state, 77, &request[..n], &attached).unwrap();
        } else {
            signed_image::authorize(&state, 77, &request, &attached).unwrap();
        }
        STATE.with_borrow(|s| {
            assert_eq!(s.issued.len(), 1);
            let fields = std::str::from_utf8(&s.issued[0].2).unwrap();
            assert!(fields.contains("org.mochios.fixture"));
            assert!(fields.contains("org.mochios.system"));
            assert!(!fields.contains("local.elf."));
            assert!(!fields.contains("image-replace-inherit"));
            assert_eq!(s.issued_caps, [b"fs.read.all\0process.spawn\0".to_vec()]);
            assert_eq!(
                s.file_reads,
                [
                    "/system/packages/org.mochios.fixture/verification.bin",
                    "/system/packages/org.mochios.fixture/manifest.toml"
                ]
            );
        });
    }
}

#[test]
fn legacy_transport_cannot_publish_an_arbitrary_digest_or_inherited_identity() {
    let code = sign_adhoc(&fixture::unsigned()).unwrap();
    let digest = Sha256::digest(&code).into();
    let (_, mut attached) = setup(code);
    attached.handles[0].rights = handle::HANDLE_RIGHT_READ;
    let mut request = vec![0; 300];
    let n = mochios_capability_protocol::encode_authorize_exec_object_request(
        "opaque:legacy",
        &digest,
        &mut request,
    )
    .unwrap();
    object_image::authorize(&empty_state(), 77, &request[..n], &attached).unwrap();
    STATE.with_borrow(|s| {
        let fields = std::str::from_utf8(&s.issued[0].2).unwrap();
        assert!(fields.contains("local.elf."));
        assert!(!fields.contains("image-replace-inherit"));
        assert!(s.issued_caps[0].is_empty());
    });
    let unsigned = fixture::unsigned();
    let digest = Sha256::digest(&unsigned).into();
    let (_, mut attached) = setup(unsigned);
    attached.handles[0].rights = handle::HANDLE_RIGHT_READ;
    let n = mochios_capability_protocol::encode_authorize_exec_object_request(
        "opaque:legacy",
        &digest,
        &mut request,
    )
    .unwrap();
    assert!(object_image::authorize(&empty_state(), 77, &request[..n], &attached).is_err());
    no_issue();
}

#[test]
fn legacy_transport_rejects_providers_before_any_owner_read() {
    let (_, mut attached) = setup(fixture::unsigned());
    attached.handles[0].rights = handle::HANDLE_RIGHT_READ;
    STATE.with_borrow_mut(|s| {
        s.length_error = Some(SysError::from(NativeError::Unsupported.into_raw()))
    });
    let mut request = vec![0; 300];
    let n = mochios_capability_protocol::encode_authorize_exec_object_request(
        "opaque:legacy",
        &[0; 32],
        &mut request,
    )
    .unwrap();
    assert!(object_image::authorize(&empty_state(), 77, &request[..n], &attached).is_err());
    STATE.with_borrow(|s| {
        assert_eq!(s.reads, 0);
        assert!(s.issued.is_empty());
    });
}

#[test]
fn installed_authentication_errors_and_ambiguity_do_not_downgrade_to_standalone() {
    for scenario in 0..5 {
        let code = sign_adhoc(&fixture::unsigned()).unwrap();
        let (request, attached) = setup(code.clone());
        let mut state = empty_state();
        install_code(
            &mut state,
            "org.mochios.fixture",
            "/system/bin/fixture",
            &code,
            "application",
            &[],
        );
        match scenario {
            0 => STATE.with_borrow_mut(|s| {
                s.files
                    .get_mut("/system/packages/org.mochios.fixture/manifest.toml")
                    .unwrap()
                    .extend_from_slice(b"# changed\n")
            }),
            1 => {
                state.package_index.duplicate = true;
            }
            2 => install_code(
                &mut state,
                "org.mochios.other",
                "/system/bin/other",
                &code,
                "application",
                &[],
            ),
            3 => install_code(
                &mut state,
                "org.mochios.fixture",
                "/system/bin/fixture",
                &code,
                "service",
                &[],
            ),
            4 => STATE.with_borrow_mut(|s| {
                s.files
                    .remove("/system/packages/org.mochios.fixture/verification.bin");
            }),
            _ => unreachable!(),
        }
        assert!(
            signed_image::authorize(&state, 77, &request, &attached).is_err(),
            "scenario {scenario}"
        );
        no_issue();
    }
}

#[test]
fn installed_code_needing_interactive_permission_does_not_publish_a_permit() {
    let code = fixture::unsigned();
    let (request, attached) = setup(code.clone());
    let mut state = empty_state();
    install_code(
        &mut state,
        "org.mochios.fixture",
        "/system/bin/fixture",
        &code,
        "application",
        &["window.overlay"],
    );
    state
        .app_prompt_policy
        .interactive
        .insert("window.overlay".into());
    assert_eq!(
        signed_image::authorize(&state, 77, &request, &attached),
        Err(SysError::from(NativeError::Unsupported.into_raw()))
    );
    no_issue();
}

#[test]
fn an_explicit_verification_key_cannot_fall_back_to_installed_authority() {
    let code = sign_adhoc(&fixture::unsigned()).unwrap();
    let (_, attached) = setup(code.clone());
    let mut state = empty_state();
    install_code(
        &mut state,
        "org.mochios.fixture",
        "/system/bin/fixture",
        &code,
        "application",
        &[],
    );
    let key = ed25519_dalek::SigningKey::from_bytes(&[8; 32])
        .verifying_key()
        .to_bytes();
    assert!(
        signed_image::authorize(
            &state,
            77,
            &encode(code.len() as u64, Some(&key)),
            &attached
        )
        .is_err()
    );
    STATE.with_borrow(|s| {
        assert!(s.file_reads.is_empty());
        assert!(s.issued.is_empty());
    });
}

#[test]
fn wire_is_bounded_versioned_and_accepts_no_ambient_authority() {
    for public_key in [None, Some(&[7; 32])] {
        let bytes = encode(17, public_key);
        assert_eq!(
            wire::decode(&bytes).unwrap(),
            wire::Request {
                source_length: 17,
                public_key,
                identity: "opaque:signed"
            }
        );
        for n in 0..wire::PREFIX_LEN + usize::from(public_key.is_some()) * 32 {
            assert!(wire::decode(&bytes[..n]).is_err());
        }
        for (offset, value, error) in [
            (0, 0, ProtocolError::UnknownOpcode),
            (4, 1, ProtocolError::UnsupportedVersion),
            (4, 2, ProtocolError::UnsupportedVersion),
            (4, 4, ProtocolError::UnsupportedVersion),
            (16, 2, ProtocolError::InvalidField),
            (20, 1, ProtocolError::InvalidField),
        ] {
            let mut bad = bytes.clone();
            bad[offset] = value;
            assert_eq!(wire::decode(&bad), Err(error));
        }
        let mut zero = bytes.clone();
        zero[8..16].fill(0);
        assert_eq!(wire::decode(&zero), Err(ProtocolError::InvalidField));
        let mut nul = bytes.clone();
        nul.push(0);
        assert_eq!(wire::decode(&nul), Err(ProtocolError::InvalidField));
        let mut utf8 = bytes.clone();
        *utf8.last_mut().unwrap() = 0xff;
        assert_eq!(wire::decode(&utf8), Err(ProtocolError::InvalidUtf8));
        let mut long = bytes.clone();
        long.resize(400, b'a');
        assert_eq!(wire::decode(&long), Err(ProtocolError::InvalidField));
        let req = wire::decode(&bytes).unwrap();
        assert!(wire::encode(&req, &mut vec![0; bytes.len() - 1]).is_err());
    }
}

#[test]
fn signed_ram_gets_a_separate_development_identity_and_no_inherited_grants() {
    let signed = sign_adhoc(&fixture::unsigned()).unwrap();
    let raw: [u8; 32] = Sha256::digest(&signed).into();
    let (request, attached) = setup(signed);
    STATE.with_borrow_mut(|s| s.part_limit = 17);
    signed_image::authorize(&empty_state(), 77, &request, &attached).unwrap();
    STATE.with_borrow(|s| {
        assert!(s.reads > 2);
        assert_eq!(s.length_calls, 2);
        assert_eq!(s.issued.len(), 1);
        assert!(s.issued_caps[0].is_empty());
        let (sender, identity, fields) = &s.issued[0];
        assert_eq!((*sender, identity.as_str()), (77, "opaque:signed"));
        let hex = raw.iter().map(|v| format!("{v:02x}")).collect::<String>();
        use mnu_abi::exec::*;
        let fields: Vec<_> = fields.split(|b| *b == 0).filter(|s| !s.is_empty()).map(|s| std::str::from_utf8(s).unwrap()).collect();
        assert_eq!(fields.len(), 7);
        for expected in [
            format!("{APPLICATION_PACKAGE_ID_PREFIX}local.elf.{hex}"),
            format!("{APPLICATION_DEVELOPER_ID_PREFIX}org.mochios.local"),
            format!("{APPLICATION_SUBJECT_KEY_ID_PREFIX}{}", "0".repeat(64)),
            format!("{APPLICATION_PROVENANCE_PREFIX}development"),
            format!("{EXEC_AUTHORIZATION_KIND_PREFIX}{EXEC_AUTHORIZATION_KIND_IMAGE_REPLACE}"),
            format!("{EXEC_AUTHORIZATION_CLASS_PREFIX}unprivileged"),
            format!("{EXECUTABLE_DIGEST_PREFIX}{hex}"),
        ] { assert!(fields.contains(&expected.as_str()), "missing field: {expected}"); }
    });
}

#[test]
fn embedded_identity_claims_cannot_impersonate_an_installed_package() {
    let declaration = "[package]\nid='org.mochios.msh'\nname='msh'\nversion='1'\nvendor='org.mochios.system'\nprovenance='built-in'\n[[binary]]\npath='/system/bin/msh'\nrequires=[]\n";
    let embedded =
        mochios_elf_signature::embed_manifest(&fixture::unsigned(), declaration).unwrap();
    let signed = sign_adhoc(&embedded).unwrap();
    let digest = Sha256::digest(&signed)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let (request, attached) = setup(signed.clone());
    signed_image::authorize(&empty_state(), 77, &request, &attached).unwrap();
    STATE.with_borrow(|s| {
        assert_eq!(s.issued.len(), 1);
        let fields = std::str::from_utf8(&s.issued[0].2).unwrap();
        assert!(fields.contains(&digest));
        assert!(fields.contains("local.elf."));
        assert!(!fields.contains("org.mochios.msh"));
        assert!(!fields.contains("org.mochios.system"));
        assert!(!fields.contains("built-in"));
    });
    // The declaration is selected from the same verified source, never a sidecar.
    let mut changed = signed;
    let position = changed
        .windows(declaration.len())
        .position(|b| b == declaration.as_bytes())
        .unwrap();
    changed[position] ^= 1;
    let (request, attached) = setup(changed);
    assert_eq!(
        signed_image::authorize(&empty_state(), 77, &request, &attached)
            .unwrap_err()
            .raw(),
        EACCES as i64
    );
    no_issue();
}

fn declared(binary: &str) -> Vec<u8> {
    let text = format!("[package]\nid='org.example.main'\nname='main'\nversion='1'\n{binary}");
    sign_adhoc(&mochios_elf_signature::embed_manifest(&fixture::unsigned(), &text).unwrap())
        .unwrap()
}

#[test]
fn every_canonical_capability_is_classified_and_never_granted_by_inheritance() {
    use mnu_abi::capability::{CAPABILITIES, CapabilityClassification};
    for metadata in CAPABILITIES {
        let signed = declared(&format!(
            "[[binary]]\npath='main'\nrequires=['{}']\n",
            metadata.name
        ));
        let (request, attached) = setup(signed.clone());
        let result = signed_image::authorize(&empty_state(), 77, &request, &attached);
        if metadata.classification == CapabilityClassification::UserGrantable {
            let evidence =
                mochios_elf_signature::verify_image(&signed, None, &Default::default()).unwrap();
            let selection = standalone_image::select(&evidence).unwrap();
            assert_eq!(selection.requested, [metadata.name]);
            assert_eq!(
                result,
                Err(SysError::from(NativeError::Unsupported.into_raw()))
            );
        } else {
            assert_eq!(
                result,
                Err(SysError::from_raw(EACCES as i64)),
                "{}",
                metadata.name
            );
        }
        no_issue();
    }
    let (request, attached) = setup(declared(
        "[[binary]]\npath='main'\nrequires=['unknown.capability']\n",
    ));
    assert_eq!(
        signed_image::authorize(&empty_state(), 77, &request, &attached),
        Err(SysError::from_raw(mochi_user_syscall::EINVAL as i64))
    );
    no_issue();
}

#[test]
fn ambiguous_invalid_and_non_application_declarations_cannot_select_an_empty_grant_set() {
    for binary in [
        "",
        "[[binary]]\npath='one'\nrequires=[]\n[[binary]]\npath='two'\nrequires=['net.connect']\n",
        "[[binary]]\npath='main'\nrequires='net.connect'\n",
        "[[binary]]\npath='main'\nrequires=[]\nkind='service'\n",
        "[[binary]]\npath='main'\nrequires=[]\nkind='driver'\n",
        "[[binary]]\npath='main'\nrequires=[]\ncapability_profile='system'\n",
        "[[binary]]\npath='main'\nrequires=['net.connect','net.connect']\n",
    ] {
        let (request, attached) = setup(declared(binary));
        assert!(
            signed_image::authorize(&empty_state(), 77, &request, &attached).is_err(),
            "{binary}"
        );
        no_issue();
    }
}

#[test]
fn verified_key_and_full_source_digest_determine_identity_without_developer_trust() {
    let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let unsigned = fixture::unsigned();
    let mut previous = String::new();
    for extra in [b"one".as_slice(), b"two".as_slice()] {
        let mut source = unsigned.clone();
        source.extend_from_slice(extra);
        let signed = sign_ed25519(&source, &key).unwrap();
        let public = key.verifying_key().to_bytes();
        let resolver = mochios_elf_signature::SuppliedPublicKey::new(&public).unwrap();
        let image =
            mochios_elf_signature::verify_image(&signed, Some(&resolver), &Default::default())
                .unwrap();
        let selection = standalone_image::select(&image).unwrap();
        assert_eq!(
            selection.identity.subject_key_id,
            image.signature().key_id.unwrap()
        );
        assert_eq!(
            selection.identity.provenance,
            mochios_signature_protocol::InstallProvenance::Development
        );
        assert_eq!(selection.identity.developer_id, "org.mochios.local");
        assert_ne!(selection.identity.package_id, previous);
        previous = selection.identity.package_id;
    }
}

#[test]
fn unsigned_tampered_and_key_mismatched_images_never_receive_a_permit() {
    let unsigned = fixture::unsigned();
    let signed = sign_adhoc(&unsigned).unwrap();
    let mut tampered = signed.clone();
    tampered[0xf0] ^= 1;
    for bytes in [unsigned, tampered] {
        let (request, attached) = setup(bytes);
        assert_eq!(
            signed_image::authorize(&empty_state(), 77, &request, &attached),
            Err(SysError::from_raw(EACCES as i64))
        );
        no_issue();
    }
    let (request, attached) = setup(signed);
    let with_key = encode(
        wire::decode(&request).unwrap().source_length,
        Some(&[7; 32]),
    );
    assert!(signed_image::authorize(&empty_state(), 77, &with_key, &attached).is_err());
    no_issue();
    let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let signed = sign_ed25519(&fixture::unsigned(), &key).unwrap();
    let length = signed.len() as u64;
    let (_, attached) = setup(signed);
    assert!(signed_image::authorize(&empty_state(), 77, &encode(length, None), &attached).is_err());
    no_issue();
    let wrong = ed25519_dalek::SigningKey::from_bytes(&[8; 32])
        .verifying_key()
        .to_bytes();
    assert!(
        signed_image::authorize(&empty_state(), 77, &encode(length, Some(&wrong)), &attached)
            .is_err()
    );
    no_issue();
    let public = key.verifying_key().to_bytes();
    signed_image::authorize(
        &empty_state(),
        77,
        &encode(length, Some(&public)),
        &attached,
    )
    .unwrap();
    STATE.with_borrow(|s| assert_eq!(s.issued.len(), 1));
}

#[test]
fn malformed_delivery_and_missing_authority_fail_before_any_ram_access() {
    for case in 0..11 {
        let (mut request, mut attached) = setup(sign_adhoc(&fixture::unsigned()).unwrap());
        match case {
            0 => attached.count = 0,
            1 => attached.count = 2,
            2 => attached.delivery_flags = mnu_abi::IPC_DELIVERY_NATIVE_OBJECT,
            3 => attached.handles[0].handle = 0,
            4 => attached.handles[0].reserved = 1,
            5 => attached.handles[0].rights = mnu_abi::HANDLE_RIGHT_READ,
            6 => attached.handles[0].rights |= mnu_abi::HANDLE_RIGHT_WRITE,
            7 => STATE.with_borrow_mut(|s| s.allowed = false),
            8 => request[4] = 99,
            9 => request[8..16].copy_from_slice(&u64::MAX.to_le_bytes()),
            _ => request[8..16].fill(0),
        }
        assert!(signed_image::authorize(&empty_state(), 77, &request, &attached).is_err());
        STATE.with_borrow(|s| {
            assert_eq!(s.length_calls, 0);
            assert_eq!(s.reads, 0);
        });
        no_issue();
    }
}

#[test]
fn providers_and_inconsistent_extents_are_rejected_without_provider_io() {
    for case in 0..2 {
        let (request, attached) = setup(sign_adhoc(&fixture::unsigned()).unwrap());
        STATE.with_borrow_mut(|s| match case {
            0 => s.length_error = Some(SysError::from(NativeError::InvalidArgument.into_raw())),
            _ => s.extent += 1,
        });
        assert!(signed_image::authorize(&empty_state(), 77, &request, &attached).is_err());
        STATE.with_borrow(|s| assert_eq!(s.reads, 0));
        no_issue();
    }
    // These are the production native type checks, not Provider metadata.
    let query = include_str!("../../../core/src/syscall/handle.rs")
        .split("pub fn memory_object_length(")
        .nth(1)
        .unwrap()
        .split("pub fn memory_object_resize(")
        .next()
        .unwrap();
    assert!(query.contains("object_with_rights_native(raw, HandleRights::empty())"));
    assert!(query.contains("KernelObject::VmObject(object)"));
    assert!(query.contains(".memory_length()"));
    let ram = include_str!("../../../core/src/mem/vm_object.rs")
        .split("pub fn memory_length(")
        .nth(1)
        .unwrap()
        .split("pub(crate) fn resize_memory(")
        .next()
        .unwrap();
    assert!(ram.contains("VmObjectSource::Memory(memory) => Some(memory.length())"));
    assert!(ram.contains("_ => None"));
}

#[test]
fn snapshot_failures_and_native_authorization_errors_are_not_retried() {
    for case in 0..5 {
        let (request, attached) = setup(sign_adhoc(&fixture::unsigned()).unwrap());
        STATE.with_borrow_mut(|s| match case {
            0 => {
                s.bytes.truncate(17);
            }
            1 => s.bad_count = true,
            2 => s.grow = true,
            3 => s.read_error = Some(SysError::from(NativeError::BackingFailure.into_raw())),
            _ => s.issue_error = Some(SysError::from(NativeError::AccessDenied.into_raw())),
        });
        let error = signed_image::authorize(&empty_state(), 77, &request, &attached).unwrap_err();
        if case == 3 {
            assert_eq!(
                error,
                SysError::from(NativeError::BackingFailure.into_raw())
            );
        }
        if case == 4 {
            assert_eq!(error, SysError::from(NativeError::AccessDenied.into_raw()));
        }
        no_issue();
    }
}

#[test]
fn service_dispatch_releases_received_references_before_replying() {
    let source = include_str!("../../capability/src/server.rs");
    let branch = source
        .split("if opcode == platform::capability::signed_image::AUTHORIZE_OPCODE {")
        .nth(1)
        .unwrap()
        .split("continue;")
        .next()
        .unwrap();
    assert!(
        branch.find("crate::signed_image::authorize").unwrap()
            < branch.find("close_received_handles(&attached)").unwrap()
    );
    assert!(
        branch.find("close_received_handles(&attached)").unwrap()
            < branch.find("capability_reply").unwrap()
    );
}
