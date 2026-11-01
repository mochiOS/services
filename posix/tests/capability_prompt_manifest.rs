//! Production policy and manifest authentication with observable file input.
extern crate alloc;
use mochi_user_platform::{package, syscall::SysError};
use mochios_signature_protocol::{InstallProvenance, InstallRecord, VerifiedResponse};
use sha2::{Digest, Sha256};
use std::{cell::RefCell, collections::BTreeMap};

#[allow(dead_code)]
#[path = "../../capability/src/policy.rs"]
mod policy;
#[allow(dead_code)]
#[path = "../../capability/src/resolver.rs"]
mod resolver;
mod package_index {
    use super::*;
    #[derive(Clone)]
    pub struct PackageRecord {
        pub manifest_path: String,
        pub manifest: package::PackageManifest,
    }
    #[derive(Default)]
    pub struct PackageIndex {
        pub by_package: BTreeMap<String, PackageRecord>,
        pub by_binary: BTreeMap<String, PackageRecord>,
        pub duplicate: bool,
    }
}
#[derive(Default)]
struct Files {
    bytes: BTreeMap<String, Vec<u8>>,
    reads: Vec<String>,
    error: Option<SysError>,
}
thread_local! { static FILES: RefCell<Files> = RefCell::new(Files::default()); }
fn read(path: &str) -> Result<Vec<u8>, SysError> {
    FILES.with_borrow_mut(|s| {
        s.reads.push(path.into());
        if let Some(error) = s.error {
            return Err(error);
        }
        s.bytes
            .get(path)
            .cloned()
            .ok_or_else(|| SysError::from_raw(-2))
    })
}
mod bootstrap_file {
    pub fn read_file(path: &str) -> Result<Vec<u8>, super::SysError> {
        super::read(path)
    }
}
mod persistent_grant {
    pub fn read_file(path: &str) -> Result<Vec<u8>, super::SysError> {
        super::read(path)
    }
}
const MANIFEST: &str = "/system/packages/capability/manifest.toml";
const RECORD: &str = "/system/packages/capability/verification.bin";
const HEADER: &str = "[package]\nid='org.mochios.capability'\nname='Capability'\nversion='1'\nprovenance='built-in'\n[[binary]]\npath='/system/services/capability.service'\nkind='service'\nrequires=[]\n";
fn fixture(prompt: &str) -> package_index::PackageIndex {
    // An earlier index snapshot must not supply the current prompt settings.
    let manifest = package::parse_manifest(HEADER).unwrap();
    let text = format!("{HEADER}{prompt}");
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
    let mut encoded = vec![0; record.encoded_len()];
    record.encode(&mut encoded).unwrap();
    FILES.with_borrow_mut(|s| {
        *s = Files::default();
        s.bytes.insert(MANIFEST.into(), text.into_bytes());
        s.bytes.insert(RECORD.into(), encoded);
    });
    let mut index = package_index::PackageIndex::default();
    index.by_package.insert(
        manifest.package_id.clone(),
        package_index::PackageRecord {
            manifest_path: MANIFEST.into(),
            manifest,
        },
    );
    index
}

#[test]
fn standard_multiline_arrays_keep_every_interactive_capability() {
    for load in LOADERS {
        let index = fixture(
            "[prompt]\ninteractive_capabilities=[\n 'window.overlay', # comment\n 'input.pointer',\n \"input.\\u006beyboard\",\n]\n",
        );
        let parsed = load(&index).unwrap();
        for name in ["window.overlay", "input.pointer", "input.keyboard"] {
            assert!(
                policy::needs_app_prompt(&parsed, name),
                "lost prompt policy: {name}"
            );
        }
        assert!(!policy::needs_app_prompt(&parsed, "net.connect"));
        FILES.with_borrow(|files| assert_eq!(files.reads, [RECORD, MANIFEST]));
    }
}

type Loader = fn(&package_index::PackageIndex) -> Result<policy::AppPromptPolicy, SysError>;
const LOADERS: [Loader; 2] = [
    policy::load_app_prompt_policy,
    policy::load_runtime_app_prompt_policy,
];

#[test]
fn absent_or_explicitly_empty_authenticated_configuration_is_empty() {
    for load in LOADERS {
        for prompt in ["", "[prompt]\ninteractive_capabilities=[]\n"] {
            let parsed = load(&fixture(prompt)).unwrap();
            assert!(!policy::needs_app_prompt(&parsed, "window.overlay"));
        }
    }
}

#[test]
fn malformed_or_ambiguous_configuration_is_never_an_empty_policy() {
    for load in LOADERS {
        for prompt in [
            "[prompt]\ninteractive_capabilities='input.keyboard'\n",
            "[prompt]\ninteractive_capabilities=['input.keyboard',17]\n",
            "[prompt]\ninteractive_capabilities=['']\n",
            "[prompt]\ninteractive_capabilities=['input.keyboard','input.keyboard']\n",
            "[prompt]\ninteractive_capabilities=[\"input.\\nkeyboard\"]\n",
            "[prompt]\ninteractive_capabilities=['input.keyboard'\n",
            "[prompt]\ninteractive_capabilities=[]\ninteractive_capabilities=['input.keyboard']\n",
        ] {
            assert_eq!(
                load(&fixture(prompt)).err(),
                Some(SysError::from_raw(mochi_user_syscall::EACCES as i64)),
                "{prompt}"
            );
        }
    }
}

#[test]
fn unknown_or_non_user_grantable_names_are_rejected() {
    for load in LOADERS {
        for capability in [
            "not.a.capability",
            "capabilities.manage",
            "service.register",
        ] {
            let index = fixture(&format!(
                "[prompt]\ninteractive_capabilities=['{capability}']\n"
            ));
            assert_eq!(
                load(&index).err(),
                Some(SysError::from_raw(mochi_user_syscall::EINVAL as i64)),
                "{capability}"
            );
        }
    }
}

#[test]
fn missing_index_or_input_errors_are_propagated_without_a_fallback() {
    for load in LOADERS {
        let mut index = fixture("");
        index.by_package.clear();
        assert_eq!(
            load(&index).err(),
            Some(SysError::from_raw(mochi_user_syscall::ENOENT as i64))
        );
        FILES.with_borrow(|files| assert!(files.reads.is_empty()));
        for path in [RECORD, MANIFEST] {
            let index = fixture("");
            FILES.with_borrow_mut(|files| {
                files.bytes.remove(path);
            });
            assert_eq!(
                load(&index).err(),
                Some(SysError::from_raw(mochi_user_syscall::ENOENT as i64))
            );
            let expected = if path == RECORD {
                vec![RECORD]
            } else {
                vec![RECORD, MANIFEST]
            };
            FILES.with_borrow(|files| assert_eq!(files.reads, expected));
        }
        for error in [mochi_user_syscall::EIO, mochi_user_syscall::EACCES] {
            let index = fixture("");
            let error = SysError::from_raw(error as i64);
            FILES.with_borrow_mut(|files| files.error = Some(error));
            assert_eq!(load(&index).err(), Some(error));
            FILES.with_borrow(|files| assert_eq!(files.reads, [RECORD]));
        }
    }
}

fn replace_authenticated_input(text: &str, provenance: InstallProvenance, package_id: &str) {
    let digest = Sha256::digest(text.as_bytes()).into();
    let record = InstallRecord {
        provenance,
        verification: VerifiedResponse {
            request_id: 0,
            provenance,
            certificate_serial: 0,
            subject_key_id: [0; 32],
            manifest_digest: digest,
            package_digest: digest,
            developer_id: "org.mochios.system",
            verified_package_id: package_id,
            allowed_capabilities: &[],
        },
    };
    let mut encoded = vec![0; record.encoded_len()];
    record.encode(&mut encoded).unwrap();
    FILES.with_borrow_mut(|files| {
        files.bytes.insert(RECORD.into(), encoded);
        files
            .bytes
            .insert(MANIFEST.into(), text.as_bytes().to_vec());
    });
}

#[test]
fn unverified_modified_or_different_package_cannot_set_policy() {
    for load in LOADERS {
        for scenario in 0..5 {
            let index = fixture("[prompt]\ninteractive_capabilities=['window.overlay']\n");
            match scenario {
                0 => FILES.with_borrow_mut(|files| {
                    files.bytes.insert(RECORD.into(), b"invalid".to_vec());
                }),
                1 => FILES.with_borrow_mut(|files| {
                    files
                        .bytes
                        .get_mut(MANIFEST)
                        .unwrap()
                        .extend_from_slice(b"# update\n")
                }),
                2 => replace_authenticated_input(
                    &HEADER.replace("org.mochios.capability", "org.example.capability"),
                    InstallProvenance::BuiltIn,
                    "org.example.capability",
                ),
                3 => replace_authenticated_input(
                    &HEADER.replace("provenance='built-in'", "provenance='development'"),
                    InstallProvenance::Development,
                    "org.mochios.capability",
                ),
                4 => replace_authenticated_input(
                    &format!("prompt = 1\n{HEADER}"),
                    InstallProvenance::BuiltIn,
                    "org.mochios.capability",
                ),
                _ => unreachable!(),
            }
            assert_eq!(
                load(&index).err(),
                Some(SysError::from_raw(mochi_user_syscall::EACCES as i64)),
                "scenario {scenario}"
            );
        }
    }
}

#[test]
fn actual_system_prompt_manifest_is_read_using_the_shared_schema() {
    let index = fixture("");
    replace_authenticated_input(
        include_str!("../../capability/manifest.toml"),
        InstallProvenance::BuiltIn,
        "org.mochios.capability",
    );
    for load in LOADERS {
        let parsed = load(&index).unwrap();
        for name in ["window.overlay", "input.pointer", "input.keyboard"] {
            assert!(policy::needs_app_prompt(&parsed, name));
        }
    }
}
