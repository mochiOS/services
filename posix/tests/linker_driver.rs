//! Exercise the actual driver, including failed child tools and atomic publication.
use mochios_linker_driver::{Options, run};
use std::os::unix::{
    ffi::{OsStrExt, OsStringExt},
    fs::{PermissionsExt, symlink},
};
use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    root: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "mochios-linker-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let fixture = Self { root };
        for directory in ["SDK with spaces/lib", "SDK with spaces/sysroot/lib"] {
            fs::create_dir_all(fixture.root.join(directory)).unwrap();
        }
        for file in [
            "lib/linker.ld",
            "lib/crt0.o",
            "lib/libmochi_user_newlib_runtime.a",
            "lib/libgcc.a",
            "sysroot/lib/libc.a",
            "sysroot/lib/libm.a",
        ] {
            fs::write(fixture.sdk().join(file), b"SDK input").unwrap();
        }
        let mut elf = [0; 64];
        elf[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        elf[16] = 2;
        elf[18] = 62;
        fs::write(fixture.root.join("seed.elf"), elf).unwrap();
        fixture.backend(0);
        fixture.signer(0, 0);
        fs::write(fixture.output(), b"previous working application").unwrap();
        fixture
    }
    fn sdk(&self) -> PathBuf {
        self.root.join("SDK with spaces")
    }
    fn output(&self) -> PathBuf {
        self.root.join("application with spaces")
    }
    fn script(&self, name: &str, text: &str) {
        let path = self.root.join(name);
        fs::write(&path, format!("#!/bin/sh\nset -eu\n{text}\n")).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    fn backend(&self, status: i32) {
        self.script("ld.lld", &format!(
            "printf '%s\\n' \"$@\" > {}\nif test {status} != 0; then exit {status}; fi\noutput=\nwhile test $# -gt 0; do if test \"$1\" = -o; then shift; output=$1; fi; shift; done\ncp {} \"$output\"",
            quote(&self.root.join("lld-arguments")), quote(&self.root.join("seed.elf"))));
    }
    fn signer(&self, sign_status: i32, verify_status: i32) {
        self.script("msign", &format!(
            "test \"$(cat {})\" = 'previous working application'\nprintf '%s\\n' \"$@\" >> {}\ncase \"$2\" in sign) exit {sign_status};; verify) exit {verify_status};; *) exit 92;; esac",
            quote(&self.output()), quote(&self.root.join("msign-arguments"))));
    }
    fn options(&self, arguments: &[&str]) -> Options {
        let mut words: Vec<OsString> = vec![
            "--mochios-sdk".into(),
            self.sdk().into(),
            "--mochios-lld".into(),
            self.root.join("ld.lld").into(),
            "--mochios-msign".into(),
            self.root.join("msign").into(),
            "-o".into(),
            self.output().into(),
        ];
        words.extend(arguments.iter().map(OsString::from));
        Options::parse(words).unwrap()
    }
    fn lld_arguments(&self) -> Vec<String> {
        fs::read_to_string(self.root.join("lld-arguments"))
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }
    fn assert_unchanged(&self) {
        assert_eq!(
            fs::read(self.output()).unwrap(),
            b"previous working application"
        );
        self.assert_clean();
    }
    fn assert_clean(&self) {
        assert!(fs::read_dir(&self.root).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .as_bytes()
                .starts_with(b".mochios-ld-")
        }));
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn quote(path: &Path) -> String {
    format!("'{}'", path.to_str().unwrap().replace('\'', "'\\''"))
}
fn parse(words: &[&str]) -> Options {
    Options::parse(words.iter().map(OsString::from)).unwrap()
}

#[test]
fn output_aliases_and_non_utf8_paths_are_normalized_without_shell_parsing() {
    let options = parse(&[
        "-ofirst",
        "--output=second",
        "-o",
        "third",
        "-L",
        "lib with spaces",
        "-lfoo",
        "-l",
        "bar",
        "--",
        "-input.o",
    ]);
    assert_eq!(options.output, Path::new("third"));
    assert_eq!(
        options.arguments,
        ["-L", "lib with spaces", "-lfoo", "-l", "bar", "./-input.o"].map(OsString::from)
    );
    let path = OsString::from_vec(b"output-\xff".to_vec());
    assert_eq!(
        Options::parse(["-o".into(), path.clone()])
            .unwrap()
            .output
            .as_os_str(),
        path
    );
    for words in [
        vec!["-o"],
        vec!["-L"],
        vec!["-l"],
        vec!["-T"],
        vec!["--sysroot="],
        vec!["--sign-key", "private"],
        vec!["--public-key", "public"],
        vec!["-pie"],
        vec!["-shared"],
        vec!["-o", "-"],
    ] {
        assert!(Options::parse(words.into_iter().map(OsString::from)).is_err());
    }
    for words in [
        vec!["@options"],
        vec!["-T", "@options"],
        vec!["--", "@options"],
    ] {
        assert!(
            Options::parse(words.into_iter().map(OsString::from))
                .unwrap_err()
                .message
                .contains("response files")
        );
    }
}

#[test]
fn sdk_defaults_are_injected_and_sign_then_verify_precede_publication() {
    let f = Fixture::new();
    run(f.options(&["input.o", "-Lcustom", "-lcustom"])).unwrap();
    let arguments = f.lld_arguments();
    let find = |word: &str| arguments.iter().position(|value| value == word).unwrap();
    assert!(find(f.sdk().join("lib/crt0.o").to_str().unwrap()) < find("input.o"));
    assert!(find("input.o") < find("--start-group"));
    assert!(
        find("--start-group")
            < find(
                f.sdk()
                    .join("lib/libmochi_user_newlib_runtime.a")
                    .to_str()
                    .unwrap()
            )
    );
    for word in ["-static", "-no-pie", "noexecstack", "-Lcustom", "-lcustom"] {
        find(word);
    }
    assert_eq!(arguments.iter().filter(|value| *value == "-o").count(), 1);
    assert!(
        !arguments
            .iter()
            .any(|value| value == f.output().to_str().unwrap())
    );
    let calls = fs::read_to_string(f.root.join("msign-arguments")).unwrap();
    assert!(calls.starts_with("elf\nsign\n"));
    assert!(calls.contains("\n--adhoc\nelf\nverify\n"));
    assert_eq!(
        fs::read(f.output()).unwrap(),
        fs::read(f.root.join("seed.elf")).unwrap()
    );
    f.assert_clean();
}

#[test]
fn link_sign_and_verify_failures_preserve_existing_output_and_child_exit_codes() {
    for (link, sign, verify, expected) in [(47, 0, 0, 47), (0, 48, 0, 48), (0, 0, 49, 49)] {
        let f = Fixture::new();
        f.backend(link);
        f.signer(sign, verify);
        assert_eq!(
            run(f.options(&["input.o"])).unwrap_err().exit_code,
            expected
        );
        f.assert_unchanged();
        if link != 0 {
            assert!(!f.root.join("msign-arguments").exists());
        }
        if sign != 0 {
            assert!(
                !fs::read_to_string(f.root.join("msign-arguments"))
                    .unwrap()
                    .contains("\nverify\n")
            );
        }
    }
}

#[test]
fn missing_tools_and_signal_termination_are_real_failures() {
    let f = Fixture::new();
    fs::remove_file(f.root.join("ld.lld")).unwrap();
    assert!(
        run(f.options(&["input.o"]))
            .unwrap_err()
            .message
            .contains("cannot execute")
    );
    f.assert_unchanged();
    f.script("ld.lld", "kill -TERM $$");
    assert_eq!(run(f.options(&["input.o"])).unwrap_err().exit_code, 143);
    f.assert_unchanged();
    f.backend(0);
    fs::remove_file(f.root.join("msign")).unwrap();
    assert!(
        run(f.options(&["input.o"]))
            .unwrap_err()
            .message
            .contains("cannot execute")
    );
    f.assert_unchanged();
}

#[test]
fn recursive_backend_and_empty_invocation_are_rejected() {
    let f = Fixture::new();
    fs::remove_file(f.root.join("ld.lld")).unwrap();
    symlink(std::env::current_exe().unwrap(), f.root.join("ld.lld")).unwrap();
    assert!(
        run(f.options(&["input.o"]))
            .unwrap_err()
            .message
            .contains("this linker driver")
    );
    assert!(
        run(f.options(&[]))
            .unwrap_err()
            .message
            .contains("no input files")
    );
    f.assert_unchanged();
}

#[test]
fn keyed_signing_uses_only_the_explicit_key_and_public_key() {
    let f = Fixture::new();
    let private = f.root.join("private key");
    let public = f.root.join("public key");
    fs::write(&private, b"private").unwrap();
    fs::write(&public, b"public").unwrap();
    let mut options = f.options(&["input.o"]);
    options.key = Some(private.clone());
    options.public_key = Some(public.clone());
    run(options).unwrap();
    let calls = fs::read_to_string(f.root.join("msign-arguments")).unwrap();
    assert!(calls.contains(&format!("\n--key\n{}\n", private.display())));
    assert!(calls.contains(&format!("\n--public-key\n{}\n", public.display())));
    assert!(!calls.contains("--adhoc"));
    f.assert_clean();
}

#[test]
fn unsigned_and_relocatable_outputs_never_invoke_msign() {
    let f = Fixture::new();
    fs::remove_file(f.root.join("msign")).unwrap();
    run(f.options(&["--no-sign", "input.o"])).unwrap();
    assert!(!f.root.join("msign-arguments").exists());
    let mut seed = fs::read(f.root.join("seed.elf")).unwrap();
    seed[16] = 1;
    fs::write(f.root.join("seed.elf"), seed).unwrap();
    fs::remove_dir_all(f.sdk()).unwrap();
    run(f.options(&["-r", "input.o"])).unwrap();
    assert_eq!(f.lld_arguments()[..2], ["-r", "input.o"]);
    f.assert_clean();
}

#[test]
fn runtime_manifest_selects_builtins_and_missing_or_invalid_inputs_fail_before_lld() {
    let f = Fixture::new();
    fs::write(
        f.sdk().join("manifest.toml"),
        "architecture='x86_64'\ncompiler_runtime='compiler-rt'\n",
    )
    .unwrap();
    fs::remove_file(f.sdk().join("lib/libgcc.a")).unwrap();
    fs::write(
        f.sdk().join("lib/libclang_rt.builtins-x86_64.a"),
        b"builtins",
    )
    .unwrap();
    run(f.options(&["--no-sign", "input.o"])).unwrap();
    assert!(
        f.lld_arguments()
            .iter()
            .any(|arg| arg.ends_with("libclang_rt.builtins-x86_64.a"))
    );
    for manifest in [
        "compiler_runtime=3",
        "compiler_runtime='unknown'",
        "architecture='aarch64'",
        "broken = [",
    ] {
        fs::write(f.sdk().join("manifest.toml"), manifest).unwrap();
        fs::remove_file(f.root.join("lld-arguments")).unwrap();
        assert!(run(f.options(&["input.o"])).is_err());
        assert!(!f.root.join("lld-arguments").exists());
        f.backend(0);
        fs::write(f.root.join("lld-arguments"), "").unwrap();
    }
    fs::remove_file(f.root.join("lld-arguments")).unwrap();
    fs::remove_file(f.sdk().join("lib/crt0.o")).unwrap();
    let error = run(f.options(&["input.o"])).unwrap_err();
    assert!(error.message.contains("lib/crt0.o"));
    assert!(!f.root.join("lld-arguments").exists());
    f.assert_clean();
}

#[test]
fn explicit_script_and_nostdlib_do_not_require_default_runtime_files() {
    let f = Fixture::new();
    fs::remove_dir_all(f.sdk()).unwrap();
    run(f.options(&[
        "-nostdlib",
        "-T",
        "custom script.ld",
        "--no-sign",
        "input.o",
    ]))
    .unwrap();
    let arguments = f.lld_arguments();
    assert!(arguments.iter().any(|word| word == "custom script.ld"));
    assert!(
        !arguments
            .iter()
            .any(|word| word.contains("crt0.o") || word == "--start-group" || word == "-nostdlib")
    );
    f.assert_clean();
}

#[test]
fn malformed_elf_key_alias_and_symlink_output_are_not_published() {
    let f = Fixture::new();
    fs::write(f.root.join("seed.elf"), b"not ELF").unwrap();
    assert!(run(f.options(&["--no-sign", "input.o"])).is_err());
    f.assert_unchanged();
    let key = f.root.join("private");
    let public = f.root.join("public");
    fs::hard_link(f.output(), &key).unwrap();
    fs::write(&public, b"public").unwrap();
    let mut options = f.options(&["input.o"]);
    options.key = Some(key);
    options.public_key = Some(public);
    assert!(run(options).unwrap_err().message.contains("key"));
    f.assert_unchanged();
    fs::rename(f.output(), f.root.join("real-output")).unwrap();
    symlink(f.root.join("real-output"), f.output()).unwrap();
    assert!(
        run(f.options(&["input.o"]))
            .unwrap_err()
            .message
            .contains("symlink")
    );
    assert_eq!(
        fs::read(f.root.join("real-output")).unwrap(),
        b"previous working application"
    );
    f.assert_clean();
}

#[test]
fn dry_run_never_creates_outputs_or_calls_tools() {
    let f = Fixture::new();
    run(f.options(&["--dry-run", "input.o"])).unwrap();
    assert!(!f.root.join("lld-arguments").exists());
    assert!(!f.root.join("msign-arguments").exists());
    f.assert_unchanged();
}

#[test]
#[ignore = "requires MOCHIOS_TEST_LLD and MOCHIOS_TEST_MSIGN; run explicitly"]
fn real_lld_and_msign_link_sign_verify_and_reject_tampering() {
    let f = Fixture::new();
    let lld = PathBuf::from(std::env::var_os("MOCHIOS_TEST_LLD").expect("real ld.lld path"));
    let msign = PathBuf::from(std::env::var_os("MOCHIOS_TEST_MSIGN").expect("real msign path"));
    let source = f.root.join("main.c");
    let object = f.root.join("main.o");
    fs::write(&source, "void _start(void) { for (;;) {} }\n").unwrap();
    assert!(
        Command::new("clang")
            .args([
                "--target=x86_64-unknown-none-elf",
                "-fno-pie",
                "-mno-red-zone",
                "-c"
            ])
            .arg(&source)
            .arg("-o")
            .arg(&object)
            .status()
            .unwrap()
            .success()
    );
    let mut options = f.options(&["-nostdlib", "-T", "/dev/null"]);
    // Use an actual script, not the injected mock SDK contents.
    let script = f.root.join("linker.ld");
    fs::write(&script, "ENTRY(_start)\nSECTIONS { . = 0x400000; .text : { *(.text*) } .rodata : { *(.rodata*) } .data : { *(.data*) } .bss : { *(.bss*) } }\n").unwrap();
    options.arguments = vec![
        "-T".into(),
        script.into(),
        object.into(),
        "-z".into(),
        "execstack".into(),
    ];
    options.lld = Some(lld);
    options.msign = Some(msign.clone());
    run(options).unwrap();
    assert!(
        Command::new(&msign)
            .args(["elf", "verify"])
            .arg(f.output())
            .status()
            .unwrap()
            .success()
    );
    let mut image = fs::read(f.output()).unwrap();
    let entry = u64::from_le_bytes(image[24..32].try_into().unwrap());
    let phoff = u64::from_le_bytes(image[32..40].try_into().unwrap()) as usize;
    let size = u16::from_le_bytes(image[54..56].try_into().unwrap()) as usize;
    let count = u16::from_le_bytes(image[56..58].try_into().unwrap()) as usize;
    let stack = (0..count)
        .find_map(|index| {
            let ph = &image[phoff + index * size..][..size];
            (u32::from_le_bytes(ph[..4].try_into().unwrap()) == 0x6474e551)
                .then(|| u32::from_le_bytes(ph[4..8].try_into().unwrap()))
        })
        .unwrap();
    assert_eq!(
        stack & 1,
        0,
        "the default output must have a non-executable stack"
    );
    let offset = (0..count)
        .find_map(|index| {
            let ph = &image[phoff + index * size..][..size];
            let start = u64::from_le_bytes(ph[16..24].try_into().unwrap());
            let length = u64::from_le_bytes(ph[32..40].try_into().unwrap());
            (u32::from_le_bytes(ph[..4].try_into().unwrap()) == 1
                && entry >= start
                && entry < start + length)
                .then(|| {
                    (u64::from_le_bytes(ph[8..16].try_into().unwrap()) + entry - start) as usize
                })
        })
        .unwrap();
    image[offset] ^= 1;
    fs::write(f.output(), image).unwrap();
    assert!(
        !Command::new(&msign)
            .args(["elf", "verify"])
            .arg(f.output())
            .status()
            .unwrap()
            .success()
    );
    f.assert_clean();
}

#[test]
#[ignore = "requires real driver, LLD, msign, and read-only SDK inputs; run explicitly"]
fn real_driver_cli_links_existing_sdk_inputs_and_propagates_lld_failure() {
    let f = Fixture::new();
    let input = PathBuf::from(std::env::var_os("MOCHIOS_TEST_SDK").expect("SDK input snapshot"));
    let driver =
        PathBuf::from(std::env::var_os("MOCHIOS_TEST_DRIVER").expect("host linker driver"));
    let lld = PathBuf::from(std::env::var_os("MOCHIOS_TEST_LLD").unwrap());
    let msign = PathBuf::from(std::env::var_os("MOCHIOS_TEST_MSIGN").unwrap());
    for file in [
        "lib/crt0.o",
        "lib/linker.ld",
        "lib/libmochi_user_newlib_runtime.a",
        "lib/libgcc.a",
        "sysroot/lib/libc.a",
        "sysroot/lib/libm.a",
    ] {
        fs::remove_file(f.sdk().join(file)).unwrap();
        symlink(input.join(file), f.sdk().join(file)).unwrap();
    }
    symlink(
        input.join("newlib_reent.o"),
        f.sdk().join("lib/newlib_reent.o"),
    )
    .unwrap();
    let source = f.root.join("main.c");
    let object = f.root.join("main.o");
    fs::write(&source, "extern int puts(const char *); int main(void) { puts(\"driver C runtime\"); return 37; }\n").unwrap();
    assert!(
        Command::new("clang")
            .args([
                "--target=x86_64-unknown-none-elf",
                "-fno-pie",
                "-mno-red-zone",
                "-c"
            ])
            .arg(&source)
            .arg("-o")
            .arg(&object)
            .status()
            .unwrap()
            .success()
    );
    let mut command = Command::new(&driver);
    command
        .arg("--mochios-sdk")
        .arg(f.sdk())
        .arg("--mochios-lld")
        .arg(&lld)
        .arg("--mochios-msign")
        .arg(&msign)
        .arg(&object)
        .arg("-o")
        .arg(f.output());
    let result = command.output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        Command::new(&msign)
            .args(["elf", "verify"])
            .arg(f.output())
            .status()
            .unwrap()
            .success()
    );
    let expected = fs::read(f.output()).unwrap();
    fs::write(&object, b"invalid object").unwrap();
    assert!(!command.output().unwrap().status.success());
    assert_eq!(fs::read(f.output()).unwrap(), expected);
    f.assert_clean();
}
