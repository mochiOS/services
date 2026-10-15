use std::process::Command;

#[test]
fn production_newlib_mkdtemp_uses_atomic_mkdir_without_cross_configure_probe() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let sdk = root.join("out/newlib-port/sdk/sysroot/include");
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory =
        std::env::temp_dir().join(format!("mochios-mkdtemp-{}-{nonce}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    for native in [false, true] {
        let executable = directory.join(if native { "mochios" } else { "other" });
        let mut compiler = Command::new("cc");
        compiler
            .args(["-std=gnu11", "-O2", "-g0", "-Wl,--strip-all", "-I"])
            .arg(&sdk);
        if native {
            compiler.arg("-D__mochios__");
        }
        let compiled = compiler
            .arg(root.join("libraries/newlib/newlib/libc/stdio/mktemp.c"))
            .arg(root.join("services/posix/tests/support/newlib_mkdtemp.c"))
            .arg("-o")
            .arg(&executable)
            .output()
            .unwrap();
        assert!(
            compiled.status.success(),
            "{}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        let run = Command::new(&executable).output().unwrap();
        assert!(
            run.status.success(),
            "mochios={native} failed at C line {:?}: {}",
            run.status.code(),
            String::from_utf8_lossy(&run.stderr)
        );
    }
    std::fs::remove_dir_all(directory).unwrap();
}
