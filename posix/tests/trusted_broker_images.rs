//! Execute production broker authentication with controlled native observations.
extern crate alloc;
extern crate mochi_user_platform as platform_real;
extern crate self as mochi_user_platform;
use mochios_signature_protocol::{InstallProvenance, InstallRecord, VerifiedResponse};
pub use platform_real::{logln, package, service};
use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    collections::{BTreeMap, VecDeque},
};
pub mod syscall {
    pub use mochi_user_syscall::*;
}
#[path = "../../../user/crates/platform/src/execution_peer.rs"]
pub mod execution_peer;
pub mod capability {
    pub use mochios_capability_protocol::*;
}
use syscall::{ExecutionIdentity, NativeError, ProcessImageInfo, SysError, ThreadSecurityContext};
#[allow(dead_code)]
#[path = "../../capability/src/consent.rs"]
mod consent;
#[path = "../../capability/src/consent_peer.rs"]
mod consent_peer;
#[allow(dead_code)]
#[path = "../../capability/src/image_catalog.rs"]
mod image_catalog;
#[allow(dead_code)]
#[path = "../../capability/src/resolver.rs"]
mod resolver;
#[allow(dead_code)]
#[path = "../../capability/src/trusted_images.rs"]
mod trusted_images;
mod policy {
    pub fn is_known_capability(_: &str) -> bool {
        true
    }
}
mod package_index {
    use super::*;
    #[derive(Clone)]
    pub struct PackageRecord {
        pub manifest_path: String,
        pub manifest: package::PackageManifest,
    }
    #[derive(Default)]
    pub struct PackageIndex {
        pub duplicate: bool,
        pub by_package: BTreeMap<String, PackageRecord>,
        pub by_binary: BTreeMap<String, PackageRecord>,
    }
}
#[derive(Default)]
struct State {
    files: BTreeMap<String, Vec<u8>>,
    reads: Vec<String>,
    events: Vec<&'static str>,
    closed: Vec<u32>,
    context: ThreadSecurityContext,
    identity: ExecutionIdentity,
    last_identity: Option<ExecutionIdentity>,
    infos: BTreeMap<u32, ProcessImageInfo>,
    queued: VecDeque<ProcessImageInfo>,
    objects: BTreeMap<u32, u64>,
    failure: Option<usize>,
    next_handle: u32,
}
thread_local! {static STATE:RefCell<State>=RefCell::new(State::default());}
fn error() -> SysError {
    SysError::from_raw(NativeError::BackingFailure.into_raw() as i64)
}
fn native_event(label: &'static str) -> Result<(), SysError> {
    STATE.with_borrow_mut(|s| {
        let index = s.events.len();
        s.events.push(label);
        if s.failure == Some(index) {
            Err(error())
        } else {
            Ok(())
        }
    })
}
pub mod ipc {
    use super::*;
    pub fn endpoint_execution_identity(endpoint: u64) -> Result<ExecutionIdentity, SysError> {
        assert_eq!(endpoint, 700);
        native_event("endpoint")?;
        Ok(STATE.with_borrow(|s| {
            if s.events.len() > 1 {
                s.last_identity.unwrap_or(s.identity)
            } else {
                s.identity
            }
        }))
    }
}
pub mod process {
    use super::*;
    pub fn open_handle_for_endpoint(endpoint: u64, rights: u64) -> Result<u32, SysError> {
        assert_eq!((endpoint, rights), (700, handle::HANDLE_RIGHT_WAIT));
        native_event("open")?;
        Ok(31)
    }
    pub fn thread_security_context(endpoint: u64) -> Result<ThreadSecurityContext, SysError> {
        assert_eq!(endpoint, 700);
        native_event("context")?;
        Ok(STATE.with_borrow(|s| s.context))
    }
    pub fn image_info(handle: Option<u32>) -> Result<ProcessImageInfo, SysError> {
        let handle = handle.expect("no caller fallback");
        native_event("image")?;
        STATE.with_borrow_mut(|s| {
            s.queued
                .pop_front()
                .or_else(|| s.infos.get(&handle).copied())
                .ok_or_else(error)
        })
    }
}
pub mod handle {
    use super::*;
    pub use platform_real::handle::*;
    pub fn close(h: u32) -> Result<(), SysError> {
        STATE.with_borrow_mut(|s| s.closed.push(h));
        Ok(())
    }
    pub fn duplicate(h: u32, rights: u64) -> Result<u32, SysError> {
        assert_eq!(rights, HANDLE_RIGHT_WAIT);
        native_event("duplicate")?;
        STATE.with_borrow_mut(|s| {
            let info = s.infos[&h];
            let object = s.objects[&h];
            let next = s.next_handle;
            s.next_handle += 1;
            s.infos.insert(next, info);
            s.objects.insert(next, object);
            Ok(next)
        })
    }
    pub fn same_object(a: u32, b: u32) -> Result<bool, SysError> {
        native_event("same-object")?;
        Ok(STATE.with_borrow(|s| s.objects[&a] == s.objects[&b]))
    }
}
const PROFILES: &[(trusted_images::Role, &str, &str, &str)] = &[
    (
        trusted_images::Role::TextPrompt,
        "org.mochios.msh",
        "application",
        "/system/bin/msh",
    ),
    (
        trusted_images::Role::Workspace,
        "org.mochios.workspace",
        "service",
        "/system/services/workspace.service",
    ),
    (
        trusted_images::Role::GraphicalPrompt,
        "org.mochios.secure-ui",
        "service",
        "/system/services/secure-ui.service",
    ),
    (
        trusted_images::Role::Input,
        "org.mochios.input",
        "service",
        "/system/services/input.service",
    ),
    (
        trusted_images::Role::Compositor,
        "org.mochios.compositor",
        "service",
        "/system/services/compositor.service",
    ),
];
fn elf(kind: u16, tag: u8) -> Vec<u8> {
    let mut b = vec![0; 4096];
    b[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
    b[16..18].copy_from_slice(&kind.to_le_bytes());
    b[18..20].copy_from_slice(&62u16.to_le_bytes());
    b[20..24].copy_from_slice(&1u32.to_le_bytes());
    b[24..32].copy_from_slice(&(if kind == 2 { 0x400100u64 } else { 0x100 }).to_le_bytes());
    b[32..40].copy_from_slice(&64u64.to_le_bytes());
    b[52..54].copy_from_slice(&64u16.to_le_bytes());
    b[54..56].copy_from_slice(&56u16.to_le_bytes());
    b[56..58].copy_from_slice(&1u16.to_le_bytes());
    b[64..68].copy_from_slice(&1u32.to_le_bytes());
    b[68..72].copy_from_slice(&5u32.to_le_bytes());
    b[80..88].copy_from_slice(&(if kind == 2 { 0x400000u64 } else { 0 }).to_le_bytes());
    b[96..104].copy_from_slice(&4096u64.to_le_bytes());
    b[104..112].copy_from_slice(&4096u64.to_le_bytes());
    b[112..120].copy_from_slice(&4096u64.to_le_bytes());
    b[4095] = tag;
    b
}
fn install(files: &mut BTreeMap<String, Vec<u8>>, package: &str, text: &str) {
    let manifest = package::parse_manifest(text).unwrap();
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
            verified_package_id: &manifest.package_id,
            allowed_capabilities: &[],
        },
    };
    let mut bytes = vec![0; record.encoded_len()];
    record.encode(&mut bytes).unwrap();
    files.insert(
        format!("/system/packages/{package}/verification.bin"),
        bytes,
    );
    files.insert(
        format!("/system/packages/{package}/manifest.toml"),
        text.as_bytes().to_vec(),
    );
}
fn fixture(dynamic: bool) -> package_index::PackageIndex {
    let mut s = State {
        next_handle: 1000,
        ..State::default()
    };
    let mut index = package_index::PackageIndex::default();
    for (i, &(_, package, kind, path)) in PROFILES.iter().enumerate() {
        let name = package.rsplit('.').next().unwrap();
        let text = format!(
            "[package]\nprovenance=\"built-in\"\nid=\"{package}\"\nname=\"{name}\"\nversion=\"1\"\n\n[[binary]]\npath=\"{path}\"\nkind=\"{kind}\"\nrequires=[]\n"
        );
        install(&mut s.files, name, &text);
        s.files.insert(
            path.into(),
            elf(if dynamic && i == 0 { 3 } else { 2 }, i as u8),
        );
        let record = package_index::PackageRecord {
            manifest_path: format!("/system/packages/{name}/manifest.toml"),
            manifest: package::parse_manifest(&text).unwrap(),
        };
        index.by_binary.insert(path.into(), record.clone());
        index.by_package.insert(package.into(), record);
    }
    s.identity = ExecutionIdentity {
        process_id: 42,
        thread_id: 43,
    };
    s.context = ThreadSecurityContext {
        process_id: 42,
        thread_id: 43,
        provenance: InstallProvenance::BuiltIn as u8,
        ..Default::default()
    };
    let developer = b"org.mochios.system";
    s.context.developer_id[..developer.len()].copy_from_slice(developer);
    s.context.developer_id_len = developer.len() as u16;
    let package = PROFILES[0].1.as_bytes();
    s.context.package_id[..package.len()].copy_from_slice(package);
    s.context.package_id_len = package.len() as u16;
    let info = ProcessImageInfo {
        process_id: 42,
        image_revision: 0,
        digest_kind: syscall::PROCESS_IMAGE_DIGEST_SHA256,
        digest: Sha256::digest(&s.files[PROFILES[0].3]).into(),
        reserved: 0,
    };
    s.infos.insert(31, info);
    s.infos.insert(77, info);
    s.objects.insert(31, 11);
    s.objects.insert(77, 11);
    STATE.set(s);
    index
}
fn read(path: &str) -> Result<Vec<u8>, SysError> {
    STATE.with_borrow_mut(|s| {
        s.reads.push(path.into());
        s.files.get(path).cloned().ok_or_else(error)
    })
}
fn bootstrap(index: &package_index::PackageIndex) -> trusted_images::TrustedImages {
    trusted_images::TrustedImages::bootstrap(index, read).unwrap()
}
fn capture() -> consent_peer::Peer {
    consent_peer::capture(700).unwrap()
}
fn manifest_digest() -> [u8; 32] {
    STATE.with_borrow(|s| Sha256::digest(&s.files["/system/packages/msh/manifest.toml"]).into())
}
fn identity() -> resolver::ApplicationIdentity {
    resolver::ApplicationIdentity {
        package_id: PROFILES[0].1.into(),
        developer_id: "org.mochios.system".into(),
        subject_key_id: [0; 32],
        provenance: InstallProvenance::BuiltIn,
    }
}

#[test]
fn all_roles_require_their_boot_code_and_the_authenticated_builtin_identity() {
    let index = fixture(false);
    let trusted = bootstrap(&index);
    for (role, package, _, path) in PROFILES {
        STATE.with_borrow_mut(|s| {
            s.context.package_id.fill(0);
            s.context.package_id[..package.len()].copy_from_slice(package.as_bytes());
            s.context.package_id_len = package.len() as u16;
            let digest = Sha256::digest(&s.files[*path]).into();
            s.infos.get_mut(&31).unwrap().digest = digest;
        });
        let peer = capture();
        assert_eq!(trusted.role(&peer).unwrap(), Some(*role));
    }
    let reads = STATE.with_borrow(|s| s.reads.len());
    let mut peer = capture();
    peer.context.developer_id[0] ^= 1;
    assert_eq!(trusted.role(&peer).unwrap(), None);
    peer.context.developer_id[0] ^= 1;
    peer.context.subject_key_id[0] = 1;
    assert_eq!(trusted.role(&peer).unwrap(), None);
    peer.context.subject_key_id = [0; 32];
    peer.context.provenance = InstallProvenance::Development as u8;
    assert_eq!(trusted.role(&peer).unwrap(), None);
    assert_eq!(
        STATE.with_borrow(|s| s.reads.len()),
        reads,
        "role lookup performs no filesystem I/O"
    );
}
#[test]
fn inherited_package_identity_does_not_authenticate_different_code() {
    let index = fixture(false);
    let trusted = bootstrap(&index);
    STATE.with_borrow_mut(|s| {
        let info = s.infos.get_mut(&31).unwrap();
        info.digest[0] ^= 1;
        info.image_revision = 1;
    });
    let peer = capture();
    assert_eq!(peer.context.package_id_len, PROFILES[0].1.len() as u16);
    assert_eq!(trusted.role(&peer).unwrap(), None);
}
#[test]
fn replacing_a_runtime_file_cannot_redefine_the_boot_trust_root() {
    let index = fixture(false);
    let trusted = bootstrap(&index);
    let reads = STATE.with_borrow(|s| s.reads.len());
    STATE.with_borrow_mut(|s| {
        s.files.get_mut(PROFILES[0].3).unwrap()[4095] ^= 1;
    });
    assert_eq!(
        trusted.role(&capture()).unwrap(),
        Some(trusted_images::Role::TextPrompt)
    );
    STATE.with_borrow_mut(|s| {
        s.infos.get_mut(&31).unwrap().digest = Sha256::digest(&s.files[PROFILES[0].3]).into()
    });
    assert_eq!(trusted.role(&capture()).unwrap(), None);
    assert_eq!(STATE.with_borrow(|s| s.reads.len()), reads);
}
#[test]
fn endpoint_capture_has_no_pid_fallback_and_closes_every_owned_reference_on_failure() {
    for fail in 0..6 {
        fixture(false);
        STATE.with_borrow_mut(|s| s.failure = Some(fail));
        assert_eq!(consent_peer::capture(700).err(), Some(error()));
        let closed = STATE.with_borrow(|s| s.closed.clone());
        assert_eq!(closed, if fail < 2 { vec![] } else { vec![31] });
    }
    fixture(false);
    assert_eq!(
        consent_peer::capture(0).err().unwrap().native_error(),
        Some(NativeError::AccessDenied)
    );
    assert!(STATE.with_borrow(|s| s.events.is_empty()));
}
#[test]
fn exec_races_retired_endpoints_and_malformed_security_contexts_are_not_cached() {
    for mutation in 0..11 {
        fixture(false);
        STATE.with_borrow_mut(|s| match mutation {
            0 => {
                let mut changed = s.infos[&31];
                changed.image_revision += 1;
                s.queued.extend([s.infos[&31], changed]);
            }
            1 => {
                s.last_identity = Some(ExecutionIdentity {
                    thread_id: 44,
                    ..s.identity
                })
            }
            2 => s.context.process_id += 1,
            3 => s.context.thread_id += 1,
            4 => s.context.reserved0[0] = 1,
            5 => s.context.reserved1 = 1,
            6 => s.context.package_id_len = u16::MAX,
            7 => s.context.developer_id_len = u16::MAX,
            8 => s.infos.get_mut(&31).unwrap().digest_kind = syscall::PROCESS_IMAGE_DIGEST_NONE,
            9 => s.infos.get_mut(&31).unwrap().process_id += 1,
            10 => s.identity.thread_id = 0,
            _ => unreachable!(),
        });
        assert_eq!(
            consent_peer::capture(700).err().unwrap().native_error(),
            Some(NativeError::AccessDenied),
            "mutation {mutation}"
        );
        assert_eq!(STATE.with_borrow(|s| s.closed.clone()), [31]);
    }
}
#[test]
fn bootstrap_uses_the_verified_snapshot_not_stale_index_metadata() {
    let mut index = fixture(false);
    index
        .by_package
        .get_mut(PROFILES[0].1)
        .unwrap()
        .manifest
        .binaries[0]
        .path = "/attacker".into();
    let trusted = bootstrap(&index);
    assert_eq!(
        trusted.role(&capture()).unwrap(),
        Some(trusted_images::Role::TextPrompt)
    );
    assert!(!STATE.with_borrow(|s| s.reads.iter().any(|p| p == "/attacker")));
}
#[test]
fn absent_duplicate_ambiguous_and_changed_manifest_roots_fail_closed() {
    let mut index = fixture(false);
    index.duplicate = true;
    assert!(trusted_images::TrustedImages::bootstrap(&index, read).is_err());
    let mut index = fixture(false);
    index.by_package.remove(PROFILES[0].1);
    assert!(trusted_images::TrustedImages::bootstrap(&index, read).is_err());
    let index = fixture(false);
    STATE.with_borrow_mut(|s| {
        s.files
            .get_mut("/system/packages/msh/manifest.toml")
            .unwrap()
            .push(b' ')
    });
    assert!(trusted_images::TrustedImages::bootstrap(&index, read).is_err());
    let index = fixture(false);
    STATE.with_borrow_mut(|s| {
        let mut text =
            String::from_utf8(s.files["/system/packages/msh/manifest.toml"].clone()).unwrap();
        text.push_str("\n[[binary]]\npath=\"/evil\"\nkind=\"application\"\nrequires=[]\n");
        install(&mut s.files, "msh", &text);
    });
    assert!(trusted_images::TrustedImages::bootstrap(&index, read).is_err());
}
#[test]
fn source_read_failure_and_signed_file_binding_mismatch_have_no_mutable_fallback() {
    let index = fixture(false);
    STATE.with_borrow_mut(|s| {
        s.files.remove(PROFILES[0].3);
    });
    assert_eq!(
        trusted_images::TrustedImages::bootstrap(&index, read)
            .err()
            .unwrap(),
        error()
    );
    let index = fixture(false);
    STATE.with_borrow_mut(|s|{let mut text=String::from_utf8(s.files["/system/packages/msh/manifest.toml"].clone()).unwrap();text=text.replace("requires=[]","requires=[]\nfile=\"root\"");text.push_str(&format!("\n[[file]]\nid=\"root\"\npath=\"{}\"\ndigest=\"sha256:{}\"\nsize=4096\nmode=\"0755\"\n",PROFILES[0].3,"00".repeat(32)));install(&mut s.files,"msh",&text);});
    assert!(trusted_images::TrustedImages::bootstrap(&index, read).is_err());
}
#[test]
fn transformed_code_is_attested_only_to_the_process_created_by_the_trusted_preparer() {
    let index = fixture(true);
    let trusted = bootstrap(&index);
    let source = STATE.with_borrow(|s| s.files[PROFILES[0].3].clone());
    let output = elf(2, 0x91);
    let digest = Sha256::digest(&output).into();
    STATE.with_borrow_mut(|s| {
        for h in [31, 77] {
            s.infos.get_mut(&h).unwrap().digest = digest;
        }
    });
    assert_eq!(trusted.role(&capture()).unwrap(), None);
    trusted
        .record_created(&identity(), manifest_digest(), &source, &output, 77)
        .unwrap();
    assert_eq!(
        trusted.role(&capture()).unwrap(),
        Some(trusted_images::Role::TextPrompt)
    );
    STATE.with_borrow_mut(|s| {
        s.objects.insert(31, 99);
    });
    assert_eq!(
        trusted.role(&capture()).unwrap(),
        None,
        "same PID/revision/hash on another object is not the admitted process"
    );
    STATE.with_borrow_mut(|s| {
        s.objects.insert(31, 11);
        s.infos.get_mut(&31).unwrap().image_revision = 1;
    });
    assert_eq!(
        trusted.role(&capture()).unwrap(),
        None,
        "replacement needs fresh prepared admission"
    );
    drop(trusted);
    assert!(STATE.with_borrow(|s| s.closed.contains(&1000)));
}
#[test]
fn asserted_output_hash_or_wrong_source_cannot_register_a_derived_image() {
    let index = fixture(true);
    let trusted = bootstrap(&index);
    let source = STATE.with_borrow(|s| s.files[PROFILES[0].3].clone());
    let output = elf(2, 0x91);
    assert_eq!(
        trusted
            .record_created(&identity(), manifest_digest(), &source, &output, 77)
            .unwrap_err()
            .native_error(),
        Some(NativeError::AccessDenied)
    );
    let mut wrong = source.clone();
    wrong[4095] ^= 1;
    assert_eq!(
        trusted
            .record_created(&identity(), manifest_digest(), &wrong, &output, 77)
            .unwrap_err()
            .native_error(),
        Some(NativeError::AccessDenied)
    );
    assert_eq!(trusted.role(&capture()).unwrap(), None);
    assert!(STATE.with_borrow(|s| s.events.iter().all(|e| *e != "duplicate")));
}

#[test]
fn same_code_with_a_different_manifest_cannot_register_a_trusted_transformation() {
    let index = fixture(true);
    let trusted = bootstrap(&index);
    let source = STATE.with_borrow(|s| s.files[PROFILES[0].3].clone());
    let output = elf(2, 0x91);
    STATE
        .with_borrow_mut(|s| s.infos.get_mut(&77).unwrap().digest = Sha256::digest(&output).into());
    let mut changed = manifest_digest();
    changed[0] ^= 1;
    assert_eq!(
        trusted
            .record_created(&identity(), changed, &source, &output, 77)
            .unwrap_err()
            .native_error(),
        Some(NativeError::AccessDenied)
    );
    assert!(STATE.with_borrow(|s| s.events.is_empty()));
}

#[test]
fn derived_reference_budget_is_bounded_and_ended_instances_are_reclaimed() {
    let index = fixture(true);
    let trusted = bootstrap(&index);
    let source = STATE.with_borrow(|s| s.files[PROFILES[0].3].clone());
    let output = elf(2, 0x91);
    let digest = Sha256::digest(&output).into();
    let manifest = manifest_digest();
    for n in 0..128 {
        STATE.with_borrow_mut(|s| {
            let info = s.infos.get_mut(&77).unwrap();
            info.process_id = 100 + n;
            info.digest = digest;
            s.objects.insert(77, 100 + n);
        });
        trusted
            .record_created(&identity(), manifest, &source, &output, 77)
            .unwrap();
    }
    STATE.with_borrow_mut(|s| {
        s.infos.get_mut(&77).unwrap().process_id = 999;
        s.objects.insert(77, 999);
    });
    assert_eq!(
        trusted
            .record_created(&identity(), manifest, &source, &output, 77)
            .unwrap_err()
            .native_error(),
        Some(NativeError::LimitExceeded)
    );
    STATE.with_borrow_mut(|s| s.infos.retain(|h, _| *h < 1000));
    trusted
        .record_created(&identity(), manifest, &source, &output, 77)
        .unwrap();
    assert_eq!(STATE.with_borrow(|s| s.closed.len()), 128);
    drop(trusted);
    assert_eq!(STATE.with_borrow(|s| s.closed.len()), 129);
}
