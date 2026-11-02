//! Real mochiOS clang defaults, shared linker driver, signing and ./main.
//! Uses the normal PATH, or an explicitly selected diagnostic tool directory.
//! No compiler/SDK paths are passed to clang.
#[cfg(not(target_os = "mochios"))]
fn main() {
    eprintln!("native-clang-driver: requires mochiOS");
}

#[cfg(target_os = "mochios")]
fn main() {
    use mochios_file_publication::PrivateDirectory;
    use sha2::{Digest, Sha256};
    use std::{
        fs,
        path::{Path, PathBuf},
        process::Command,
        time::Instant,
    };

    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    let bin = match arguments.as_slice() {
        [] => None,
        [option, path] if option == "--tool-directory" => Some(PathBuf::from(path)),
        _ => panic!("usage: native-clang-driver [--tool-directory PATH]"),
    };
    const SOURCE: &str = r#"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#if !defined(__mochios__) || !defined(__unix__) || defined(__linux__)
#error wrong target environment
#endif
_Static_assert(sizeof(void *) == 8 && sizeof(long) == 8, "LP64 required");
static unsigned long native_call(unsigned long number, unsigned long a0, unsigned long a1, unsigned long a2) {
    __asm__ volatile("syscall" : "+a"(number), "+D"(a0), "+S"(a1), "+d"(a2)
        : : "rcx", "r11", "r8", "r9", "r10", "memory", "cc");
    return number;
}
int main(void) {
    const char *capabilities[] = { @CAPABILITIES@ };
    for (unsigned i=0; i<sizeof(capabilities)/sizeof(capabilities[0]); ++i)
        if (native_call(@CAP_QUERY@, (unsigned long)capabilities[i], strlen(capabilities[i]), 0) != 0) return 91;
    _Alignas(8) unsigned char context[@CONTEXT_SIZE@] = {0};
    if (native_call(@CONTEXT_QUERY@, 0, (unsigned long)context, sizeof(context)) != 0) return 92;
    const char *expected = getenv("EXPECT_PROGRAM_PACKAGE");
    unsigned length = context[@PACKAGE_LENGTH@] | ((unsigned)context[@PACKAGE_LENGTH@+1] << 8);
    if (!expected || length != strlen(expected) || memcmp(context+@PACKAGE_OFFSET@, expected, length) != 0) return 93;
    if (context[@PROVENANCE_OFFSET@] != @DEVELOPMENT@) return 94;
    puts("clang-driver315"); return 37;
}
"#;

    let source = SOURCE
        .replace(
            "@CAPABILITIES@",
            &mnu_abi::capability::CAPABILITIES
                .iter()
                .map(|cap| format!("{:?}", cap.name))
                .collect::<Vec<_>>()
                .join(",\n"),
        )
        .replace(
            "@CAP_QUERY@",
            &(mnu_abi::SyscallNumber::CapQuery as u64).to_string(),
        )
        .replace(
            "@CONTEXT_QUERY@",
            &(mnu_abi::SyscallNumber::GetThreadSecurityContext as u64).to_string(),
        )
        .replace(
            "@CONTEXT_SIZE@",
            &core::mem::size_of::<mnu_abi::ThreadSecurityContext>().to_string(),
        )
        .replace(
            "@PACKAGE_LENGTH@",
            &core::mem::offset_of!(mnu_abi::ThreadSecurityContext, package_id_len).to_string(),
        )
        .replace(
            "@PACKAGE_OFFSET@",
            &core::mem::offset_of!(mnu_abi::ThreadSecurityContext, package_id).to_string(),
        )
        .replace(
            "@PROVENANCE_OFFSET@",
            &core::mem::offset_of!(mnu_abi::ThreadSecurityContext, provenance).to_string(),
        )
        .replace(
            "@DEVELOPMENT@",
            &(mochios_signature_protocol::InstallProvenance::Development as u8).to_string(),
        );
    assert!(!source.contains('@'));

    unsafe { libc::alarm(900) };
    let began = Instant::now();
    let directory = PrivateDirectory::new_in(Path::new("/tmp"), "clang-driver315").unwrap();
    let command = |tool: &str| {
        let mut command = Command::new(
            bin.as_ref()
                .map(|bin| bin.join(tool))
                .unwrap_or_else(|| PathBuf::from(tool)),
        );
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
    println!(
        "native-clang-driver-315: target elapsed {} ms",
        began.elapsed().as_millis()
    );

    fs::write(directory.path().join("main.c"), source).unwrap();
    let compilation = Instant::now();
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
    println!(
        "native-clang-driver-315: compile/link/sign/verify elapsed {} ms",
        compilation.elapsed().as_millis()
    );
    let executed = Command::new("./main")
        .current_dir(directory.path())
        .env(
            "EXPECT_PROGRAM_PACKAGE",
            format!(
                "local.elf.{:x}",
                Sha256::digest(fs::read(directory.path().join("main")).unwrap())
            ),
        )
        .output()
        .unwrap();
    assert_eq!(executed.status.code(), Some(37));
    assert_eq!(executed.stdout, b"clang-driver315\n");
    println!("native-clang-driver-315: PASS ./main stdout and exit37");
    println!(
        "native-clang-driver-334: PASS generated C has the exact source identity and zero canonical capabilities"
    );

    let previous = fs::read(directory.path().join("main")).unwrap();
    for (stage, source) in [
        ("compile failure", "int main(void) { this is invalid C; }\n"),
        (
            "link failure",
            "extern int absent_symbol(void); int main(void) { return absent_symbol(); }\n",
        ),
    ] {
        println!("native-clang-driver-315: checking {stage}");
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
    let rejected = Command::new("./main")
        .current_dir(directory.path())
        .output()
        .unwrap_err();
    assert_eq!(rejected.kind(), std::io::ErrorKind::PermissionDenied);
    println!("native-clang-driver-334: PASS ordinary exec rejects the tampered ELF");
    unsafe { libc::alarm(0) };
    drop(directory);
    println!("native-clang-driver-315: PASS cleanup");
    println!(
        "native-clang-driver-315: total elapsed {} ms",
        began.elapsed().as_millis()
    );
}
