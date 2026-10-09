use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn rust_vm_flags_match_the_sdk_c_header() {
    let rust = include_str!("../../../libraries/libc/newlib/mochios.rs");
    let header = include_str!("../../../user/libc-port/include/sys/mman.h");
    let upstream = include_str!("../../../libraries/libc/.generated/upstream-newlib-mod.rs");
    let mut source = String::new();
    let mut assertions = String::new();
    for name in [
        "PROT_NONE",
        "PROT_READ",
        "PROT_WRITE",
        "PROT_EXEC",
        "MAP_SHARED",
        "MAP_PRIVATE",
        "MAP_FIXED",
        "MAP_ANON",
        "MAP_ANONYMOUS",
        "MAP_STACK",
        "MAP_NORESERVE",
        "MS_ASYNC",
        "MS_INVALIDATE",
        "MS_SYNC",
    ] {
        // These platform definitions are publicly re-exported. Unlike
        // O_CLOEXEC, upstream must not shadow any of these local constants.
        assert!(!upstream.contains(&format!("pub const {name}:")));
        let prefix = format!("pub const {name}: c_int = ");
        let value = rust
            .lines()
            .find_map(|line| line.strip_prefix(&prefix))
            .expect("Rust VM sync flag")
            .trim_end_matches(';');
        let definition = header
            .lines()
            .find(|line| {
                let mut tokens = line.split_whitespace();
                tokens.next() == Some("#define") && tokens.next() == Some(name)
            })
            .expect("SDK VM sync flag");
        source.push_str(definition);
        source.push('\n');
        assertions.push_str(&format!(
            "\n_Static_assert({name} == {value}, \"Rust/SDK {name} mismatch\");\n"
        ));
    }
    source.push_str(&assertions);
    let mut compiler = Command::new("cc")
        .args(["-x", "c", "-std=c11", "-fsyntax-only", "-"])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    compiler
        .stdin
        .take()
        .unwrap()
        .write_all(source.as_bytes())
        .unwrap();
    let output = compiler.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
