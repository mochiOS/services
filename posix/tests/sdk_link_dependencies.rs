use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

struct TempDirectory(PathBuf);

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn mochi_std_tracks_sdk_inputs_needed_to_relink_the_runtime() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let temporary = TempDirectory(std::env::temp_dir().join(format!(
        "mochios-sdk-link-dependencies-{}-{nonce}",
        std::process::id()
    )));
    fs::create_dir(&temporary.0).unwrap();
    let build_script = temporary.0.join("std-build");
    let source =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../libraries/rust/library/std/build.rs");
    let compiled = Command::new("rustc")
        .args(["--edition=2021", "-o"])
        .arg(&build_script)
        .arg(source)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );

    let sdk = temporary.0.join("SDK with spaces");
    let flags = format!("-C\u{1f}link-arg=--sysroot={}/sysroot", sdk.display());
    let run = |target_os: &str| {
        let output = Command::new(&build_script)
            .env("CARGO_CFG_TARGET_ARCH", "x86_64")
            .env("CARGO_CFG_TARGET_OS", target_os)
            .env("CARGO_CFG_TARGET_VENDOR", "unknown")
            .env("CARGO_CFG_TARGET_ENV", "")
            .env("CARGO_ENCODED_RUSTFLAGS", &flags)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    };
    let native = run("mochios");
    for input in [
        "lib/crt0.o",
        "lib/linker.ld",
        "lib/libmochi_user_newlib_runtime.a",
        "lib/libgcc.a",
        "sysroot/lib/libc.a",
        "sysroot/lib/libm.a",
    ] {
        let dependency = format!("cargo:rerun-if-changed={}", sdk.join(input).display());
        assert!(
            native.lines().any(|line| line == dependency),
            "missing {dependency}"
        );
    }
    // Host test builds must not pick up target SDK linker dependencies.
    assert!(!run("linux").contains(&sdk.to_string_lossy().to_string()));
}
