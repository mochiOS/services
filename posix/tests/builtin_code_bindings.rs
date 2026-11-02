//! Actual host msign CLI: staged code, common manifest schema and install record.
use mochios_file_publication::PrivateDirectory;
use mochios_package_manifest::parse_manifest_checked;
use mochios_signature_protocol::InstallRecordView;
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::PathBuf,
    process::{Command, Output},
};

const DECLARATION: &str = "[package]\nid='org.example.tool'\nname='Tool'\nversion='1'\nprovenance='built-in'\n[prompt]\ninteractive_capabilities=[\n'window.overlay', # keep the value\n]\n[custom]\nmarker='keep-this'\n[[binary]]\npath='/bin/main'\nkind='command'\nrequires=[\n\"net.\\u0063onnect\",\n'fs.read.all',\n]\n";
const CODE: &[u8] = b"code bytes including a non-LOAD trailer\0\xff";

struct Fixture {
    tool: PathBuf,
    directory: PrivateDirectory,
}
impl Fixture {
    fn new() -> Self {
        let fixture = Self {
            tool: std::env::var_os("MOCHIOS_TEST_MSIGN")
                .expect("set MOCHIOS_TEST_MSIGN")
                .into(),
            directory: PrivateDirectory::new_in(&std::env::temp_dir(), "built-in-bindings")
                .unwrap(),
        };
        fs::create_dir(fixture.path("rootfs")).unwrap();
        fs::write(fixture.path("input.toml"), DECLARATION).unwrap();
        fixture.code("system/bin/main", CODE, 0o755);
        fs::write(fixture.path("output.toml"), b"previous output").unwrap();
        fixture
    }
    fn path(&self, name: &str) -> PathBuf {
        self.directory.path().join(name)
    }
    fn code(&self, name: &str, bytes: &[u8], mode: u32) {
        let path = self.path("rootfs").join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }
    fn bind(&self, args: &[&str]) -> Output {
        Command::new(&self.tool)
            .args(["package", "bind-built-in"])
            .arg(self.path("input.toml"))
            .arg("--rootfs")
            .arg(self.path("rootfs"))
            .arg("--output")
            .arg(self.path("output.toml"))
            .args(args)
            .output()
            .unwrap()
    }
    fn success(&self, args: &[&str]) -> mochios_package_manifest::PackageManifest {
        let output = self.bind(args);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        parse_manifest_checked(&fs::read_to_string(self.path("output.toml")).unwrap()).unwrap()
    }
    fn failure(&self, args: &[&str], diagnostic: &str) {
        let before = fs::read(self.path("output.toml")).unwrap();
        let output = self.bind(args);
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(diagnostic),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(fs::read(self.path("output.toml")).unwrap(), before);
    }
}

#[test]
#[ignore = "requires MOCHIOS_TEST_MSIGN with the current host msign"]
fn complete_bytes_and_prompt_requirements_survive_binding_and_record_generation() {
    let fixture = Fixture::new();
    let manifest = fixture.success(&["--map-path", "/bin=/system/bin"]);
    assert_eq!(manifest.interactive_capabilities, ["window.overlay"]);
    assert_eq!(
        manifest.binaries[0].requires,
        ["net.connect", "fs.read.all"]
    );
    let file = &manifest.files[0];
    assert_eq!(manifest.binaries[0].file.as_ref(), Some(&file.id));
    assert_eq!(file.path, "/bin/main");
    assert_eq!(file.size, CODE.len() as u64);
    assert_eq!(file.mode, 0o755);
    assert_eq!(file.digest, format!("sha256:{:x}", Sha256::digest(CODE)));
    let bytes = fs::read(fixture.path("output.toml")).unwrap();
    assert!(std::str::from_utf8(&bytes).unwrap().contains("keep-this"));
    let output = Command::new(&fixture.tool)
        .args(["package", "built-in-record"])
        .arg(fixture.path("output.toml"))
        .arg("--output")
        .arg(fixture.path("verification.bin"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let record = fs::read(fixture.path("verification.bin")).unwrap();
    let record = InstallRecordView::decode(&record).unwrap();
    assert_eq!(
        record.verification.manifest_digest,
        <[u8; 32]>::from(Sha256::digest(bytes))
    );
    assert_eq!(record.verification.verified_package_id, manifest.package_id);
    assert_eq!(
        record
            .verification
            .allowed_capabilities()
            .map(Result::unwrap)
            .collect::<Vec<_>>(),
        ["fs.read.all", "net.connect"]
    );
    assert_eq!(
        fs::read(fixture.path("rootfs/system/bin/main")).unwrap(),
        CODE
    );
}

#[test]
#[ignore = "requires MOCHIOS_TEST_MSIGN with the current host msign"]
fn namespace_mapping_is_explicit_and_uses_complete_longest_prefixes() {
    let fixture = Fixture::new();
    fixture.failure(&[], "missing staged code");
    fs::write(
        fixture.path("input.toml"),
        DECLARATION.replace("/bin/main", "/bin/sub/main"),
    )
    .unwrap();
    fixture.code("special/main", b"longest prefix", 0o755);
    fixture.code("system/bin/sub/main", b"wrong prefix", 0o755);
    let manifest = fixture.success(&[
        "--map-path",
        "/bin=/system/bin",
        "--map-path",
        "/bin/sub=/special",
    ]);
    assert_eq!(
        manifest.files[0].digest,
        format!("sha256:{:x}", Sha256::digest(b"longest prefix"))
    );
    fs::write(
        fixture.path("input.toml"),
        DECLARATION.replace("/bin/main", "/binary/main"),
    )
    .unwrap();
    fixture.failure(&["--map-path", "/bin=/system/bin"], "missing staged code");
    for mapping in [
        "/bin",
        "bin=/system/bin",
        "/bin=/system/../bin",
        "/bin=/system//bin",
    ] {
        fixture.failure(&["--map-path", mapping], "map-path");
    }
    fixture.failure(
        &["--map-path", "/bin=/one", "--map-path", "/bin=/two"],
        "duplicate map-path",
    );
}

#[test]
#[ignore = "requires MOCHIOS_TEST_MSIGN with the current host msign"]
fn existing_bindings_are_verified_and_never_replaced_after_code_changes() {
    for change in 0..3 {
        let fixture = Fixture::new();
        fixture.success(&["--map-path", "/bin=/system/bin"]);
        fs::copy(fixture.path("output.toml"), fixture.path("input.toml")).unwrap();
        fixture.success(&["--map-path", "/bin=/system/bin"]);
        match change {
            0 => {
                let mut bytes = CODE.to_vec();
                bytes[0] ^= 1;
                fixture.code("system/bin/main", &bytes, 0o755);
            }
            1 => {
                let mut bytes = CODE.to_vec();
                bytes.push(0);
                fixture.code("system/bin/main", &bytes, 0o755);
            }
            2 => fixture.code("system/bin/main", CODE, 0o700),
            _ => unreachable!(),
        }
        fixture.failure(
            &["--map-path", "/bin=/system/bin"],
            "existing code binding does not match",
        );
    }
}

#[test]
#[ignore = "requires MOCHIOS_TEST_MSIGN with the current host msign"]
fn optional_binaries_require_exact_declared_exclusions() {
    let fixture = Fixture::new();
    fs::write(
        fixture.path("input.toml"),
        format!("{DECLARATION}\n[[binary]]\npath='/bin/optional'\nkind='command'\nrequires=[]\n"),
    )
    .unwrap();
    fixture.failure(&["--map-path", "/bin=/system/bin"], "missing staged code");
    fixture.failure(
        &["--exclude-binary", "/bin/other"],
        "excluded binary is not declared",
    );
    fixture.failure(
        &[
            "--exclude-binary",
            "/bin/optional",
            "--exclude-binary",
            "/bin/optional",
        ],
        "duplicate binary exclusion",
    );
    let manifest = fixture.success(&[
        "--map-path",
        "/bin=/system/bin",
        "--exclude-binary",
        "/bin/optional",
    ]);
    assert_eq!(manifest.binaries.len(), 1);
    assert_eq!(manifest.binaries[0].path, "/bin/main");
    assert_eq!(manifest.files.len(), 1);
}

#[test]
#[ignore = "requires MOCHIOS_TEST_MSIGN with the current host msign"]
fn invalid_or_missing_code_does_not_replace_the_previous_output() {
    let fixture = Fixture::new();
    for path in ["relative", "/bin/../main", "/bin//main", "/bin/main/"] {
        fs::write(
            fixture.path("input.toml"),
            DECLARATION.replace("/bin/main", path),
        )
        .unwrap();
        fixture.failure(
            &["--map-path", "/bin=/system/bin"],
            "canonical and absolute",
        );
    }
    fs::write(fixture.path("input.toml"), DECLARATION).unwrap();
    fixture.code("system/bin/main", b"", 0o755);
    fixture.failure(&["--map-path", "/bin=/system/bin"], "nonempty regular file");
    fixture.code("system/bin/main", CODE, 0o644);
    fixture.failure(&["--map-path", "/bin=/system/bin"], "no execute permission");
    fs::write(
        fixture.path("input.toml"),
        DECLARATION.replace("built-in", "development"),
    )
    .unwrap();
    fixture.failure(&[], "built-in record requires");
}

#[test]
#[ignore = "requires MOCHIOS_TEST_MSIGN with the current host msign"]
fn escaping_symlinks_and_output_aliases_cannot_overwrite_code() {
    let fixture = Fixture::new();
    fs::write(fixture.path("external-code"), CODE).unwrap();
    fs::remove_file(fixture.path("rootfs/system/bin/main")).unwrap();
    symlink(
        fixture.path("external-code"),
        fixture.path("rootfs/system/bin/main"),
    )
    .unwrap();
    fixture.failure(&["--map-path", "/bin=/system/bin"], "escapes rootfs");
    fs::remove_file(fixture.path("rootfs/system/bin/main")).unwrap();
    fixture.code("system/bin/main", CODE, 0o755);
    fs::remove_file(fixture.path("output.toml")).unwrap();
    fs::hard_link(
        fixture.path("rootfs/system/bin/main"),
        fixture.path("output.toml"),
    )
    .unwrap();
    fixture.failure(&["--map-path", "/bin=/system/bin"], "aliases staged code");
    fs::remove_file(fixture.path("output.toml")).unwrap();
    symlink(
        fixture.path("rootfs/system/bin/main"),
        fixture.path("output.toml"),
    )
    .unwrap();
    fixture.failure(&["--map-path", "/bin=/system/bin"], "aliases staged code");
    assert_eq!(
        fs::read(fixture.path("rootfs/system/bin/main")).unwrap(),
        CODE
    );
}

#[test]
#[ignore = "requires MOCHIOS_TEST_MSIGN with the current host msign"]
fn rootfs_manifest_step_binds_only_the_explicit_build_configuration() {
    let script = include_str!("../../../scripts/mmake/stage-rootfs.sh");
    let start = script.find("install_manifest() {").unwrap();
    let end = start + script[start..].find("\n}\n").unwrap() + 3;
    let command = format!(
        "set -eu\numask 077\nstage_new=$2\nconfig=$3\nmsign=$4\n{}\ninstall_manifest \"$1\" coreutils\n",
        &script[start..end]
    );
    for performance in [false, true] {
        for selftests in [false, true] {
            let fixture = Fixture::new();
            let mut manifest = DECLARATION.to_owned();
            for path in ["mperf", "selftest-ext2-write", "selftest-system-layout"] {
                manifest.push_str(&format!(
                    "\n[[binary]]\npath='/bin/{path}'\nkind='application'\nrequires=[]\n"
                ));
                if (path == "mperf" && performance) || (path != "mperf" && selftests) {
                    fixture.code(&format!("system/bin/{path}"), CODE, 0o755);
                }
            }
            fs::write(fixture.path("input.toml"), manifest).unwrap();
            fs::write(
                fixture.path("config"),
                format!(
                    "KERNEL_PERFORMANCE_INSTRUMENTATION={}\nUSER_BUILD_SELFTESTS={}\n",
                    if performance { "y" } else { "n" },
                    if selftests { "y" } else { "n" }
                ),
            )
            .unwrap();
            let run = || {
                Command::new("bash")
                    .args(["-c", &command, "--"])
                    .arg(fixture.path("input.toml"))
                    .arg(fixture.path("rootfs"))
                    .arg(fixture.path("config"))
                    .arg(&fixture.tool)
                    .output()
                    .unwrap()
            };
            let result = run();
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            let path = fixture.path("rootfs/system/packages/coreutils/manifest.toml");
            let manifest = parse_manifest_checked(&fs::read_to_string(&path).unwrap()).unwrap();
            assert_eq!(
                manifest.binaries.len(),
                1 + usize::from(performance) + 2 * usize::from(selftests)
            );
            assert!(manifest.binaries.iter().all(|b| b.file.is_some()));
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o644
            );
            assert_eq!(
                fs::metadata(path.with_file_name("verification.bin"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o644
            );
            // An enabled input cannot silently become an optional omission.
            fs::remove_file(fixture.path("rootfs/system/bin/main")).unwrap();
            let original = fs::read(&path).unwrap();
            assert!(!run().status.success());
            assert_eq!(fs::read(path).unwrap(), original);
        }
    }
}
