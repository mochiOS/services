use std::{fs, process::Command};

#[test]
fn actual_newlib_allocator_maps_large_blocks_and_keeps_small_sbrk_allocations() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let temp = std::env::temp_dir().join(format!("mochios-malloc-{}-{nonce}", std::process::id()));
    fs::create_dir(&temp).unwrap();
    for mochios in [true, false] {
        let mut compile = Command::new("cc");
        compile.args([
            "-O2",
            "-no-pie",
            "-Wl,-z,noexecstack",
            "-D_LIBC",
            "-DGETREENT_PROVIDED",
        ]);
        if mochios {
            compile.arg("-D__mochios__");
        }
        compile
            .arg("-I")
            .arg(root.join("out/newlib-port/sdk/sysroot/include"));
        compile.arg("-I").arg(root.join("user/libc-port/include"));
        compile.arg(root.join("services/posix/tests/host_malloc_mapping.c"));
        for name in ["mallocr", "freer", "reallocr", "callocr", "malignr"] {
            compile.arg(root.join(format!("libraries/newlib/newlib/libc/stdlib/{name}.c")));
        }
        let binary = temp.join("malloc");
        let output = compile.arg("-o").arg(&binary).output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let result = Command::new(&binary).status().unwrap();
        assert!(result.success(), "allocator check failed: {result}");
    }
    fs::remove_dir_all(temp).unwrap();
}
