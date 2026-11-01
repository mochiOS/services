//! Real mochiOS clang defaults, shared linker driver, signing and ./main.
//! Tools live in one diagnostic SDK; no compiler/SDK paths are passed to clang.
#[cfg(not(target_os = "mochios"))]
fn main() {
    eprintln!("native-clang-driver: requires mochiOS");
}

#[cfg(target_os = "mochios")]
fn main() {
    use mochios_file_publication::PrivateDirectory;
    use std::{fs, path::Path, process::Command};

    const BIN: &str = "/system/tests/posix/clang315/sdk/bin";
    const SOURCE: &str = r#"
#include <stdio.h>
#include <stdint.h>
#if !defined(__mochios__) || !defined(__unix__) || defined(__linux__)
#error wrong target environment
#endif
_Static_assert(sizeof(void *) == 8 && sizeof(long) == 8, "LP64 required");
int main(void) { puts("clang-driver315"); return 37; }
"#;

    unsafe { libc::alarm(900) };
    let directory = PrivateDirectory::new_in(Path::new("/tmp"), "clang-driver315").unwrap();
    let command = |tool: &str| {
        let mut command = Command::new(format!("{BIN}/{tool}"));
        command.current_dir(directory.path());
        for variable in [
            "MOCHIOS_SDK",
            "MOCHIOS_LLD",
            "MOCHIOS_MSIGN",
            "LIBRARY_PATH",
            "CCC_OVERRIDE_OPTIONS",
        ] {
            command.env_remove(variable);
        }
        command
    };
    let target = command("clang").arg("-dumpmachine").output().unwrap();
    assert!(target.status.success());
    assert_eq!(target.stdout, b"x86_64-unknown-mochios\n");
    println!("native-clang-driver-315: PASS default mochiOS target");

    fs::write(directory.path().join("main.c"), SOURCE).unwrap();
    let output = command("clang")
        .args(["main.c", "-o", "main"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "clang: {:?}\n{}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let verified = command("msign")
        .args(["elf", "verify", "main"])
        .output()
        .unwrap();
    assert!(
        verified.status.success(),
        "{}",
        String::from_utf8_lossy(&verified.stderr)
    );
    assert!(String::from_utf8_lossy(&verified.stdout).contains("valid AdHoc ELF signature"));
    println!("native-clang-driver-315: PASS clang main.c -o main with automatic signing");
    let executed = Command::new("./main")
        .current_dir(directory.path())
        .output()
        .unwrap();
    assert_eq!(executed.status.code(), Some(37));
    assert_eq!(executed.stdout, b"clang-driver315\n");
    println!("native-clang-driver-315: PASS ./main stdout and exit37");

    let previous = fs::read(directory.path().join("main")).unwrap();
    for source in [
        "int main(void) { this is invalid C; }\n",
        "extern int absent_symbol(void); int main(void) { return absent_symbol(); }\n",
    ] {
        fs::write(directory.path().join("main.c"), source).unwrap();
        let failed = command("clang")
            .args(["main.c", "-o", "main"])
            .output()
            .unwrap();
        assert!(!failed.status.success());
        assert_eq!(fs::read(directory.path().join("main")).unwrap(), previous);
    }
    println!("native-clang-driver-315: PASS compile/link failure preserves the old ELF");
    let mut tampered = previous;
    tampered[9] ^= 1;
    fs::write(directory.path().join("main"), tampered).unwrap();
    assert!(
        !command("msign")
            .args(["elf", "verify", "main"])
            .output()
            .unwrap()
            .status
            .success()
    );
    println!("native-clang-driver-315: PASS msign rejects tampering");
    unsafe { libc::alarm(0) };
    drop(directory);
    println!("native-clang-driver-315: PASS cleanup");
}
