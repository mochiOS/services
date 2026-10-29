use super::*;
use mochios_posix_client::image_preparation::Source;
#[path = "library_package_dependencies.rs"]
mod external;

const APP: &str = "/applications/Test.app/entry.elf";
const LIB: &str = "/applications/Test.app/lib/library.so";
const ROOT: &[u8] = b"approved executable bytes";
const LIBRARY: &[u8] = b"approved library bytes";

fn manifest() -> String {
    format!(
        r#"
[package]
id = "org.mochios.test"
name = "Test"
version = "1"
kind = "application"
provenance = "built-in"

[application]
entry = "entry.elf"
resources = []

[[binary]]
path = "{APP}"
kind = "application"
file = "root"
requires = []

[[binary]]
path = "{LIB}"
kind = "library"
file = "library"
requires = []

[[file]]
id = "root"
path = "$/entry.elf"
digest = "sha256:{:x}"
size = {}
mode = "0755"

[[file]]
id = "library"
path = "$/lib/library.so"
digest = "sha256:{:x}"
size = {}
mode = "0644"
"#,
        Sha256::digest(ROOT),
        ROOT.len(),
        Sha256::digest(LIBRARY),
        LIBRARY.len(),
    )
}

fn install(text: &str) {
    let manifest = package::parse_manifest(text).expect("valid manifest fixture");
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
    FILES.with_borrow_mut(|files| {
        *files = Files::default();
        files
            .bytes
            .insert(MANIFEST.into(), text.as_bytes().to_vec());
        files.bytes.insert(RECORD.into(), bytes);
    });
}

fn catalog() -> image_catalog::Catalog {
    install(&manifest());
    let snapshot = resolver::verified_manifest(MANIFEST, read_file).unwrap();
    image_catalog::Catalog::new(snapshot, APP).unwrap()
}

fn dependency(path: &[u8]) -> Source<'_> {
    Source::Dependency {
        needed: b"library.so",
        path,
    }
}

#[test]
fn exact_inputs_use_one_authenticated_snapshot_without_reopening_executables() {
    let approved = catalog();
    assert_eq!(approved.identity().package_id, "org.mochios.test");
    assert_eq!(approved.identity().developer_id, "org.mochios.system");
    assert_eq!(approved.validate(Source::Root, ROOT), Ok(()));
    assert_eq!(
        approved.validate(dependency(LIB.as_bytes()), LIBRARY),
        Ok(())
    );
    FILES.with_borrow_mut(|files| {
        assert_eq!(files.reads, [RECORD, MANIFEST]);
        files.error = Some(syscall::SysError::from_raw(syscall::EIO as i64));
    });
    // The policy applies to the owned capture, not a new file read after a
    // rename/update or a mutable package-index snapshot.
    assert_eq!(approved.validate(Source::Root, ROOT), Ok(()));
    assert_eq!(
        approved.validate(dependency(LIB.as_bytes()), LIBRARY),
        Ok(())
    );
    FILES.with_borrow(|files| assert_eq!(files.reads.len(), 2));
}

#[test]
fn modified_truncated_and_appended_bytes_are_rejected_for_every_input() {
    let approved = catalog();
    for (source, expected) in [
        (Source::Root, ROOT),
        (dependency(LIB.as_bytes()), LIBRARY),
        (Source::Interpreter { path: LIB.as_bytes() }, LIBRARY),
    ] {
        let mut modified = expected.to_vec();
        modified[0] ^= 1;
        let mut appended = expected.to_vec();
        appended.push(0);
        for bytes in [
            modified.as_slice(),
            &expected[..expected.len() - 1],
            &appended,
        ] {
            assert_eq!(
                approved.validate(source, bytes).unwrap_err().raw(),
                syscall::EACCES as i64
            );
        }
    }
}

#[test]
fn interpreter_uses_exact_authenticated_library_binding_without_extra_identity() {
    let approved = catalog();
    assert_eq!(
        approved.validate(
            Source::Interpreter {
                path: LIB.as_bytes()
            },
            LIBRARY
        ),
        Ok(())
    );
    for path in [APP.as_bytes(), b"library.so", b"/tmp/library.so"] {
        assert!(
            approved
                .validate(Source::Interpreter { path }, LIBRARY)
                .is_err()
        );
    }
    assert_eq!(approved.identity().package_id, "org.mochios.test");
    assert_eq!(approved.identity().developer_id, "org.mochios.system");
    FILES.with_borrow(|files| assert_eq!(files.reads, [RECORD, MANIFEST]));
}

#[test]
fn library_selection_never_uses_a_basename_or_the_root_record() {
    let approved = catalog();
    for path in [
        b"library.so".as_slice(),
        b"lib/library.so",
        b"/tmp/library.so",
        APP.as_bytes(),
        b"/applications/Test.app/lib/./library.so",
        b"/applications/Test.app/lib//library.so",
    ] {
        assert_eq!(
            approved
                .validate(dependency(path), LIBRARY)
                .unwrap_err()
                .raw(),
            syscall::EACCES as i64
        );
    }
    assert!(approved.validate(dependency(LIB.as_bytes()), ROOT).is_err());
}

#[test]
fn unsigned_manifest_changes_and_invalid_records_are_rejected() {
    catalog();
    FILES.with_borrow_mut(|files| {
        files
            .bytes
            .get_mut(MANIFEST)
            .unwrap()
            .extend_from_slice(b"\n# changed")
    });
    assert_eq!(
        resolver::verified_manifest(MANIFEST, read_file)
            .err()
            .unwrap()
            .raw(),
        syscall::EACCES as i64
    );
    catalog();
    FILES.with_borrow_mut(|files| files.bytes.insert(RECORD.into(), vec![0; 20]));
    assert_eq!(
        resolver::verified_manifest(MANIFEST, read_file)
            .err()
            .unwrap()
            .raw(),
        syscall::EACCES as i64
    );
}

#[test]
fn loader_policy_uses_the_new_verified_manifest_instead_of_an_earlier_copy() {
    let original = manifest();
    install(&original);
    let old = resolver::verified_manifest(MANIFEST, read_file).unwrap();
    install(&original.replace(
        &format!("{:x}", Sha256::digest(ROOT)),
        &format!("{:x}", Sha256::digest(b"replacement")),
    ));
    let new = resolver::verified_manifest(MANIFEST, read_file).unwrap();
    assert!(
        image_catalog::Catalog::new(old, APP)
            .unwrap()
            .validate(Source::Root, ROOT)
            .is_ok()
    );
    assert!(
        image_catalog::Catalog::new(new, APP)
            .unwrap()
            .validate(Source::Root, ROOT)
            .is_err()
    );
}

#[test]
fn every_code_record_requires_a_matching_file_binding_and_strict_digest() {
    let original = manifest();
    for text in [
        original.replace("file = \"root\"", "file = \"absent\""),
        original.replace("file = \"library\"", ""),
        original.replace("$/entry.elf", "$/elsewhere.elf"),
        original.replace("$/lib/library.so", "/other/library.so"),
        original.replace("sha256:", "sha512:"),
        original.replace(&format!("{:x}", Sha256::digest(ROOT)), &"g".repeat(64)),
        original.replace(&format!("{:x}", Sha256::digest(ROOT)), "abc"),
        original.replace("kind = \"application\"", "kind = \"service\""),
    ] {
        install(&text);
        let snapshot = resolver::verified_manifest(MANIFEST, read_file).unwrap();
        assert_eq!(
            image_catalog::Catalog::new(snapshot, APP)
                .err()
                .unwrap()
                .raw(),
            syscall::EACCES as i64
        );
    }
}

#[test]
fn signed_data_and_non_library_binaries_do_not_approve_dependency_code() {
    install(&manifest().replace("kind = \"library\"", "kind = \"data\""));
    let snapshot = resolver::verified_manifest(MANIFEST, read_file).unwrap();
    let approved = image_catalog::Catalog::new(snapshot, APP).unwrap();
    assert!(
        approved
            .validate(dependency(LIB.as_bytes()), LIBRARY)
            .is_err()
    );
}

#[test]
fn bundle_traversal_and_path_aliases_do_not_bind_code_records() {
    for path in [
        "$/../entry.elf",
        "$/./entry.elf",
        "$/lib//entry.elf",
        "$/",
        "relative",
    ] {
        install(&manifest().replace("$/entry.elf", path));
        let snapshot = resolver::verified_manifest(MANIFEST, read_file).unwrap();
        assert!(image_catalog::Catalog::new(snapshot, APP).is_err());
    }
    let approved = catalog();
    for status in [syscall::EAGAIN, syscall::EIO, syscall::EACCES] {
        FILES.with_borrow_mut(|files| {
            files.error = Some(syscall::SysError::from_raw(status as i64))
        });
        assert_eq!(
            resolver::verified_manifest(MANIFEST, read_file)
                .err()
                .unwrap()
                .raw(),
            status as i64
        );
        assert!(approved.validate(Source::Root, ROOT).is_ok());
    }
}

#[test]
fn static_installed_path_policy_cannot_approve_a_dynamic_or_unbound_modern_package() {
    let original = manifest();
    let legacy = original
        .split("[[file]]")
        .next()
        .unwrap()
        .replace("file = \"root\"", "")
        .replace("file = \"library\"", "");
    let mut bytes = vec![0; 120];
    bytes[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
    bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
    bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
    bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&1u16.to_le_bytes());
    for dynamic in [false, true] {
        install(&legacy);
        let snapshot = resolver::verified_manifest(MANIFEST, read_file).unwrap();
        bytes[64..68].copy_from_slice(&(if dynamic { 2u32 } else { 1u32 }).to_le_bytes());
        let policy = image_catalog::Catalog::for_static(snapshot, APP, &bytes);
        if dynamic {
            assert!(policy.is_err());
        } else {
            let policy = policy.unwrap();
            assert!(policy.validate(Source::Root, &bytes).is_ok());
            bytes[100] ^= 1;
            assert!(policy.validate(Source::Root, &bytes).is_err());
            assert!(
                policy
                    .validate(dependency(LIB.as_bytes()), LIBRARY)
                    .is_err()
            );
        }
    }
    install(&original.replace("file = \"root\"", ""));
    let snapshot = resolver::verified_manifest(MANIFEST, read_file).unwrap();
    assert!(image_catalog::Catalog::for_static(snapshot, APP, &bytes).is_err());
}
