use std::process::Command;

#[test]
fn desktop_stdio_profile_is_explicit_and_invalidates_the_configure_cache() {
    let build = include_str!("../../../user/scripts/build-newlib.sh");
    let configure = include_str!("../../../libraries/newlib/newlib/configure.ac");
    for feature in ["long-long", "c99-formats", "pos-args", "long-double"] {
        assert!(build.contains(&format!("--enable-newlib-io-{feature}=yes")));
        assert!(configure.contains(&format!("newlib-io-{feature}")));
    }
    assert!(build.contains("\"${configure_options[@]}\""));
    assert!(build.contains(".mochios-configure-options"));
    assert!(build.contains("rm -f \"$BUILD_DIR/x86_64-elf/newlib/config.cache\""));
}

#[test]
fn native_stdio_probe_has_valid_portable_conversion_expectations() {
    let directory = std::env::temp_dir().join(format!(
        "mochios-stdio-formats-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(directory.clone());
    let binary = directory.join("probe");
    let source =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/native_stdio_formats.c");
    let compiled = Command::new("cc")
        .args(["-Wall", "-Wextra", "-Werror", "-fno-builtin"])
        .arg(source)
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let result = Command::new(binary).output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    // This checks the probe against a host libc, not the target SDK. The same
    // C source must also run on mochiOS to verify newlib's configured behavior.
    assert!(String::from_utf8_lossy(&result.stderr).contains("stdio-formats: pass"));
}
