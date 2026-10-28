use super::*;

const A: &str = "org.mochios.shared.a";
const B: &str = "org.mochios.shared.b";
const A_PATH: &str = "/libraries/shared-a.so";
const B_PATH: &str = "/libraries/shared-b.so";
const A_BYTES: &[u8] = b"shared implementation A";
const B_BYTES: &[u8] = b"shared implementation B";

fn edge(package: &str) -> String {
    format!(
        r#"
[[library_dependency]]
package = "{package}"
developer = "org.mochios.system"
subject_key_id = "{}"
provenance = "built-in"
abi = "shared-1"
"#,
        "0".repeat(64)
    )
}

fn provider(id: &str, path: &str, bytes: &[u8], dependencies: &str) -> String {
    format!(
        r#"
[package]
id = "{id}"
name = "Shared"
version = "1"
kind = "binary"
provenance = "built-in"
architecture = "x86_64"
abi = "shared-1"
[[binary]]
path = "{path}"
kind = "library"
file = "code"
requires = ["fs.write.all"]
[[file]]
id = "code"
path = "{path}"
digest = "sha256:{:x}"
size = {}
mode = "0644"
{dependencies}
"#,
        Sha256::digest(bytes),
        bytes.len()
    )
}

fn path(id: &str) -> String {
    format!("/system/packages/{id}/manifest.toml")
}

fn put(text: &str) {
    let manifest = package::parse_manifest(text).expect("valid dependency fixture");
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
            allowed_capabilities: &["fs.write.all"],
        },
    };
    let mut encoded = vec![0; record.encoded_len()];
    record.encode(&mut encoded).unwrap();
    let manifest_path = path(&manifest.package_id);
    FILES.with_borrow_mut(|files| {
        files
            .bytes
            .insert(manifest_path.clone(), text.as_bytes().to_vec());
        files.bytes.insert(
            manifest_path.replace("manifest.toml", "verification.bin"),
            encoded,
        );
    });
}

fn root(edges: &str) -> resolver::VerifiedManifest {
    let text = manifest().replace(
        "kind = \"application\"\nprovenance",
        "kind = \"application\"\narchitecture = \"x86_64\"\nprovenance",
    ) + edges;
    install(&text);
    resolver::verified_manifest(MANIFEST, read_file).unwrap()
}

fn load(id: &str) -> Result<resolver::VerifiedManifest, syscall::SysError> {
    resolver::verified_manifest(&path(id), read_file)
}

#[test]
fn trust_declarations_are_strict_and_do_not_break_binary_or_file_sections() {
    let original = manifest();
    let declaration = edge(A);
    let parsed = package::parse_manifest(&(original.clone() + &declaration)).unwrap();
    assert_eq!(parsed.library_dependencies.len(), 1);
    assert_eq!(parsed.library_dependencies[0].package, A);
    assert_eq!(parsed.binaries.len(), 2);
    assert_eq!(parsed.files.len(), 2);
    for changed in [
        declaration.replace("abi = \"shared-1\"", ""),
        declaration.replace("developer = \"org.mochios.system\"", "developer = \"\""),
        declaration.replace(&"0".repeat(64), &"g".repeat(64)),
        declaration.replace(&"0".repeat(64), "00"),
        declaration.replace("\"built-in\"", "\"unknown\""),
        declaration.replace("\"shared-1\"", "shared-1"),
        declaration.clone() + "abi = \"other\"\n",
        declaration.clone() + "version = \"ignored\"\n",
        declaration.clone() + &declaration,
    ] {
        assert!(
            package::parse_manifest(&(original.clone() + &changed)).is_none(),
            "{changed}"
        );
    }
    let text =
        original + &declaration + "\n[[binary]]\npath = \"/bin/another\"\nkind = \"application\"\n";
    let parsed = package::parse_manifest(&text).unwrap();
    assert_eq!(parsed.library_dependencies[0].abi, "shared-1");
    assert_eq!(parsed.binaries.last().unwrap().path, "/bin/another");
}

#[test]
fn explicit_package_trust_approves_only_library_code_without_changing_root_authority() {
    let verified = root(&edge(A));
    assert!(
        verified
            .decide_capabilities(APP)
            .unwrap()
            .requested
            .is_empty()
    );
    let text = provider(A, A_PATH, A_BYTES, "")
        + r#"
[[binary]]
path = "/bin/shared-admin"
kind = "application"
file = "admin"
requires = ["fs.write.all"]
[[file]]
id = "admin"
path = "/bin/shared-admin"
digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
size = 1
mode = "0755"
"#;
    put(&text);
    let approved = image_catalog::Catalog::resolve(verified, APP, load).unwrap();
    assert_eq!(approved.identity().package_id, "org.mochios.test");
    assert!(
        approved
            .validate(dependency(A_PATH.as_bytes()), A_BYTES)
            .is_ok()
    );
    assert!(
        approved
            .validate(dependency(b"/bin/shared-admin"), b"x")
            .is_err()
    );
    assert!(
        approved
            .validate(dependency(b"/tmp/shared-a.so"), A_BYTES)
            .is_err()
    );
    FILES.with_borrow_mut(|files| files.error = Some(syscall::SysError::from_raw(-5)));
    assert!(
        approved
            .validate(dependency(A_PATH.as_bytes()), A_BYTES)
            .is_ok()
    );
    assert!(
        approved
            .validate(dependency(A_PATH.as_bytes()), b"modified")
            .is_err()
    );
}

#[test]
fn two_applications_can_reference_one_provider_without_claiming_its_binary_paths() {
    let first = root(&edge(A));
    let second_text = (manifest() + &edge(A))
        .replace("org.mochios.test", "org.mochios.other")
        .replace("name = \"Test\"", "name = \"Other\"")
        .replace("/applications/Test.app", "/applications/Other.app");
    put(&second_text);
    put(&provider(A, A_PATH, A_BYTES, ""));
    let second = resolver::verified_manifest(&path("org.mochios.other"), read_file).unwrap();
    let one = image_catalog::Catalog::resolve(first, APP, load).unwrap();
    let two =
        image_catalog::Catalog::resolve(second, "/applications/Other.app/entry.elf", load).unwrap();
    assert_ne!(one.identity().package_id, two.identity().package_id);
    for approved in [one, two] {
        assert!(
            approved
                .validate(dependency(A_PATH.as_bytes()), A_BYTES)
                .is_ok()
        );
    }
    let provider = package::parse_manifest(&provider(A, A_PATH, A_BYTES, "")).unwrap();
    assert_eq!(provider.binaries.len(), 1);
}

#[test]
fn compatible_updates_use_fresh_authenticated_digests_and_keep_old_launch_snapshots_immutable() {
    let first = root(&edge(A));
    put(&provider(A, A_PATH, A_BYTES, ""));
    let old = image_catalog::Catalog::resolve(first, APP, load).unwrap();
    let newer = b"updated compatible implementation";
    put(&provider(A, A_PATH, newer, "").replace("version = \"1\"", "version = \"2\""));
    let second = resolver::verified_manifest(MANIFEST, read_file).unwrap();
    let new = image_catalog::Catalog::resolve(second, APP, load).unwrap();
    assert!(old.validate(dependency(A_PATH.as_bytes()), A_BYTES).is_ok());
    assert!(old.validate(dependency(A_PATH.as_bytes()), newer).is_err());
    assert!(new.validate(dependency(A_PATH.as_bytes()), newer).is_ok());
    assert!(
        new.validate(dependency(A_PATH.as_bytes()), A_BYTES)
            .is_err()
    );
}

#[test]
fn publisher_key_provenance_abi_and_architecture_cannot_be_substituted() {
    for declaration in [
        edge(A).replace("org.mochios.system", "org.example.attacker"),
        edge(A).replace(&"0".repeat(64), &"1".repeat(64)),
        edge(A).replace("\"built-in\"", "\"development\""),
        edge(A).replace("shared-1", "shared-2"),
    ] {
        let verified = root(&declaration);
        put(&provider(A, A_PATH, A_BYTES, ""));
        assert_eq!(
            image_catalog::Catalog::resolve(verified, APP, load)
                .err()
                .unwrap()
                .raw(),
            -13
        );
    }
    let verified = root(&edge(A));
    put(&provider(A, A_PATH, A_BYTES, "").replace("x86_64", "aarch64"));
    assert_eq!(
        image_catalog::Catalog::resolve(verified, APP, load)
            .err()
            .unwrap()
            .raw(),
        -13
    );
    let verified = root(&edge(A));
    put(&provider(B, B_PATH, B_BYTES, ""));
    assert!(image_catalog::Catalog::resolve(verified, APP, |_| load(B)).is_err());
}

#[test]
fn transitive_cycles_share_one_snapshot_but_conflicting_repeated_edges_fail() {
    let verified = root(&(edge(A) + &edge(B)));
    put(&provider(A, A_PATH, A_BYTES, &edge(B)));
    put(&provider(B, B_PATH, B_BYTES, &edge(A)));
    let mut calls = Vec::new();
    let approved = image_catalog::Catalog::resolve(verified, APP, |id| {
        calls.push(id.to_owned());
        load(id)
    })
    .unwrap();
    assert_eq!(calls, [A, B]);
    assert!(
        approved
            .validate(dependency(A_PATH.as_bytes()), A_BYTES)
            .is_ok()
    );
    assert!(
        approved
            .validate(dependency(B_PATH.as_bytes()), B_BYTES)
            .is_ok()
    );
    let verified = resolver::verified_manifest(MANIFEST, read_file).unwrap();
    put(&provider(
        B,
        B_PATH,
        B_BYTES,
        &edge(A).replace(&"0".repeat(64), &"1".repeat(64)),
    ));
    assert!(image_catalog::Catalog::resolve(verified, APP, load).is_err());
}

#[test]
fn missing_unreadable_and_modified_provider_records_never_fall_back_to_installed_paths() {
    let verified = root(&edge(A));
    assert_eq!(
        image_catalog::Catalog::resolve(verified, APP, load)
            .err()
            .unwrap()
            .raw(),
        -2
    );
    let verified = resolver::verified_manifest(MANIFEST, read_file).unwrap();
    put(&provider(A, A_PATH, A_BYTES, ""));
    FILES.with_borrow_mut(|files| {
        files
            .bytes
            .get_mut(&path(A))
            .unwrap()
            .extend_from_slice(b"\n# changed")
    });
    assert_eq!(
        image_catalog::Catalog::resolve(verified, APP, load)
            .err()
            .unwrap()
            .raw(),
        -13
    );
    for status in [-5, -11, -13] {
        let verified = root(&edge(A));
        FILES.with_borrow_mut(|files| files.error = Some(syscall::SysError::from_raw(status)));
        assert_eq!(
            image_catalog::Catalog::resolve(verified, APP, load)
                .err()
                .unwrap()
                .raw(),
            status
        );
    }
    let verified = root("");
    put(&provider(A, A_PATH, A_BYTES, ""));
    let approved =
        image_catalog::Catalog::resolve(verified, APP, |_| panic!("no dependency was declared"))
            .unwrap();
    assert!(
        approved
            .validate(dependency(A_PATH.as_bytes()), A_BYTES)
            .is_err()
    );
}

#[test]
fn conflicting_export_ownership_and_missing_file_bindings_are_rejected() {
    let verified = root(&(edge(A) + &edge(B)));
    put(&provider(A, A_PATH, A_BYTES, ""));
    put(&provider(B, A_PATH, A_BYTES, ""));
    assert_eq!(
        image_catalog::Catalog::resolve(verified, APP, load)
            .err()
            .unwrap()
            .raw(),
        -17
    );
    let verified = root(&edge(A));
    put(&provider(A, A_PATH, A_BYTES, "").replace("file = \"code\"", "file = \"missing\""));
    assert_eq!(
        image_catalog::Catalog::resolve(verified, APP, load)
            .err()
            .unwrap()
            .raw(),
        -13
    );
}

#[test]
fn dependency_expansion_has_a_finite_resource_limit_without_recursion() {
    let verified = root(&edge("org.mochios.chain.n0"));
    let mut calls = 0;
    let error = image_catalog::Catalog::resolve(verified, APP, |id| {
        let number: usize = id.rsplit('n').next().unwrap().parse().unwrap();
        let text = format!(
            r#"[package]
id = "{id}"
name = "Meta"
version = "1"
provenance = "built-in"
kind = "binary"
architecture = "x86_64"
abi = "shared-1"
{}"#,
            edge(&format!("org.mochios.chain.n{}", number + 1))
        );
        put(&text);
        calls += 1;
        load(id)
    })
    .err()
    .unwrap();
    assert_eq!(error.raw(), -7);
    assert!(calls > 32 && calls <= 256);
}
