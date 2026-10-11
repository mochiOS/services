use std::{
    fs,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

struct Temporary(std::path::PathBuf);
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn publishing_identical_complete_runtime_preserves_sdk_mtime() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let temporary = Temporary(std::env::temp_dir().join(format!(
        "mochios-runtime-archive-{}-{nonce}",
        std::process::id()
    )));
    let root = &temporary.0;
    let target = root.join("target");
    let archive_dir = target.join("x86_64-unknown-mochios/release");
    for path in [
        root.join("hello"),
        root.join("sdk/lib"),
        root.join("runtime"),
        root.join("sysroot/include"),
        archive_dir.clone(),
    ] {
        fs::create_dir_all(path).unwrap();
    }
    fs::write(
        root.join("runtime/newlib_reent.c"),
        "int reent_fixture(void) { return 1; }\n",
    )
    .unwrap();
    fs::write(
        root.join("runtime/newlib_ioctl.c"),
        "int ioctl_fixture(void) { return 4; }\n",
    )
    .unwrap();
    fs::write(
        root.join("base.c"),
        "int base_fixture(void) { return 2; }\n",
    )
    .unwrap();
    let compile = Command::new("gcc")
        .arg("-c")
        .arg(root.join("base.c"))
        .arg("-o")
        .arg(root.join("base.o"))
        .output()
        .unwrap();
    assert!(
        compile.status.success(),
        "{}",
        String::from_utf8_lossy(&compile.stderr)
    );
    assert!(
        Command::new("ar")
            .arg("rcs")
            .arg(archive_dir.join("libmochi_user_newlib_runtime.a"))
            .arg(root.join("base.o"))
            .status()
            .unwrap()
            .success()
    );
    let script = include_str!("../../../user/scripts/build-newlib.sh");
    let body = script
        .split("# Compose the complete archive")
        .nth(1)
        .unwrap()
        .split("install -C -m 0644 \"$USER_ROOT/runtime/linker.ld\"")
        .next()
        .unwrap();
    // Execute the actual publication steps with host ELF tools; no SDK build.
    let commands = body
        .lines()
        .skip(2)
        .collect::<Vec<_>>()
        .join("\n")
        .replace("x86_64-elf-", "");
    let publish = || {
        let result = Command::new("bash")
            .args(["-eu", "-c", &commands])
            .env("OUT_ROOT", root)
            .env("USER_ROOT", root)
            .env("TARGET_DIR", &target)
            .env("SYSROOT", root.join("sysroot"))
            .env("SDK", root.join("sdk"))
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    };
    publish();
    let archive = root.join("sdk/lib/libmochi_user_newlib_runtime.a");
    let bytes = fs::read(&archive).unwrap();
    let modified = fs::metadata(&archive).unwrap().modified().unwrap();
    publish();
    assert_eq!(fs::read(&archive).unwrap(), bytes);
    assert_eq!(
        fs::metadata(&archive).unwrap().modified().unwrap(),
        modified
    );
    fs::write(
        root.join("runtime/newlib_reent.c"),
        "int reent_fixture(void) { return 3; }\n",
    )
    .unwrap();
    publish();
    assert_ne!(fs::read(&archive).unwrap(), bytes);
}
