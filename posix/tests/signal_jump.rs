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
fn public_header_preserves_plain_jump_layout_and_exposes_real_posix_functions() {
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
        _Static_assert(sizeof(jmp_buf)==64,\"plain ABI\");\n\
        _Static_assert(sizeof(sigjmp_buf)==120,\"signal ABI\");\n\
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
