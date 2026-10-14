use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn production_jump_assembly_returns_twice_and_reopens_delivery_on_the_destination_stack() {
    let directory = std::env::temp_dir().join(format!("mochios-sigjump-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let object = directory.join("jump.o");
    let mut compiler = Command::new("cc")
        .args(["-x", "assembler", "-c", "-", "-o"])
        .arg(&object)
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = compiler.stdin.take().unwrap();
    input.write_all(b".intel_syntax noprefix\n").unwrap();
    input
        .write_all(include_bytes!(
            "../../../user/crates/newlib-runtime/src/signal_jump_x86_64.S"
        ))
        .unwrap();
    input
        .write_all(include_bytes!("support/sigjump_probe.S"))
        .unwrap();
    drop(input);
    let output = compiler.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    for optimization in ["-O0", "-O2"] {
        let binary = directory.join("probe");
        let output = Command::new("cc")
            .args([optimization, "-std=c11", "-Wall", "-Wextra", "-Werror"])
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/sigjump_assembly.c"
            ))
            .arg(&object)
            .arg("-o")
            .arg(&binary)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let output = Command::new(&binary).output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn public_header_unifies_jump_layout_and_exposes_real_posix_functions() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let sdk = root.join("out/newlib-port/sdk/sysroot/include");
    let header = root.join("user/libc-port/include");
    let builtin = Command::new("cc")
        .arg("-print-file-name=include")
        .output()
        .unwrap();
    assert!(builtin.status.success());
    let builtin = String::from_utf8(builtin.stdout).unwrap();
    let code = b"#define _POSIX_C_SOURCE 200809L\n#include <setjmp.h>\n\
        _Static_assert(sizeof(jmp_buf)==120,\"plain ABI\");\n\
        _Static_assert(sizeof(sigjmp_buf)==120,\"signal ABI\");\n\
        int (*plain_save)(jmp_buf)=&setjmp;\n\
        void (*plain_restore)(jmp_buf,int)=&longjmp;\n\
        int (*xsi_save)(jmp_buf)=&_setjmp;\n\
        void (*xsi_restore)(jmp_buf,int)=&_longjmp;\n\
        int (*save)(sigjmp_buf,int)=&sigsetjmp;\n\
        void (*restore)(sigjmp_buf,int)=&siglongjmp;\n";
    for (language, standard, code) in [
        ("c", "-std=c11", String::from_utf8(code.to_vec()).unwrap()),
        (
            "c++",
            "-std=c++17",
            String::from_utf8(code.to_vec())
                .unwrap()
                .replace("_Static_assert", "static_assert"),
        ),
    ] {
        let mut compiler = Command::new(if language == "c" { "cc" } else { "c++" })
            .args([
                standard,
                "-nostdinc",
                "-ffreestanding",
                "-Wall",
                "-Werror",
                "-fsyntax-only",
                "-x",
                language,
                "-",
            ])
            .arg("-I")
            .arg(&header)
            .arg("-I")
            .arg(&sdk)
            .arg("-isystem")
            .arg(builtin.trim())
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        compiler
            .stdin
            .take()
            .unwrap()
            .write_all(code.as_bytes())
            .unwrap();
        let output = compiler.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn sdk_publication_removes_only_runtime_owned_archive_backends_and_is_idempotent() {
    let script = include_str!("../../../user/scripts/build-newlib.sh");
    let begin = script.find("for runtime_library in ").unwrap();
    let end = begin
        + script[begin..]
            .find("\nperl \"$USER_ROOT/scripts/fix-newlib-signal-header.pl\"")
            .unwrap();
    let directory =
        std::env::temp_dir().join(format!("mochios-jump-archive-{}", std::process::id()));
    let library = directory.join("sysroot/lib");
    std::fs::create_dir_all(&library).unwrap();
    let keep = directory.join("keep.o");
    let mut compiler = Command::new("cc")
        .args(["-x", "c", "-c", "-", "-o"])
        .arg(&keep)
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    compiler
        .stdin
        .take()
        .unwrap()
        .write_all(b"void keep(void) {}\n")
        .unwrap();
    assert!(compiler.wait().unwrap().success());
    let raise = directory.join("libc_a-raise.o");
    let jump = directory.join("libc_a-setjmp.o");
    std::fs::copy(&keep, &raise).unwrap();
    std::fs::copy(&keep, &jump).unwrap();
    let archive = library.join("libc.a");
    assert!(Command::new("x86_64-elf-ar")
        .arg("rcs")
        .arg(&archive)
        .arg(&keep)
        .arg(&raise)
        .arg(&jump)
        .status()
        .unwrap()
        .success());
    // A distinct input archive must not be changed by publication.
    let input = directory.join("input-libc.a");
    std::fs::copy(&archive, &input).unwrap();
    let original = std::fs::read(&input).unwrap();
    let publish = || {
        let output = Command::new("bash")
            .args(["-euo", "pipefail", "-c", &script[begin..end]])
            .env("SDK", &directory)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    };
    let debug = library.join("libg.a");
    for arrangement in 0..3 {
        if debug.exists() {
            std::fs::remove_file(&debug).unwrap();
        }
        std::fs::copy(&input, &archive).unwrap();
        match arrangement {
            0 => {} // libg is optional.
            1 => {
                std::fs::copy(&input, &debug).unwrap();
            }
            _ => std::fs::hard_link(&archive, &debug).unwrap(),
        }
        publish();
        for path in [&archive, &debug].into_iter().filter(|path| path.exists()) {
            let members = Command::new("x86_64-elf-ar")
                .arg("t")
                .arg(path)
                .output()
                .unwrap();
            assert!(members.status.success());
            assert_eq!(String::from_utf8(members.stdout).unwrap().trim(), "keep.o");
        }
        let published = std::fs::read(&archive).unwrap();
        let debug_published = std::fs::read(&debug).ok();
        publish();
        assert_eq!(std::fs::read(&archive).unwrap(), published);
        assert_eq!(std::fs::read(&debug).ok(), debug_published);
        assert_eq!(std::fs::read(&input).unwrap(), original);
    }
    std::fs::remove_dir_all(directory).unwrap();
}
