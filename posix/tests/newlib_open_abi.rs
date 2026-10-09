use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn rust_close_on_exec_flag_matches_the_newlib_header() {
    let rust = include_str!("../../../libraries/libc/newlib/mochios.rs");
    let rust_value = rust
        .lines()
        .find_map(|line| line.strip_prefix("pub const O_CLOEXEC: c_int = "))
        .expect("mochiOS libc close-on-exec flag")
        .trim_end_matches(';');
    let header = include_str!("../../../libraries/newlib/newlib/libc/include/sys/_default_fcntl.h");
    let definition = |name: &str| {
        header
            .lines()
            .find(|line| {
                let mut tokens = line.split_whitespace();
                tokens.next() == Some("#define") && tokens.next() == Some(name)
            })
            .expect("newlib flag definition")
    };
    // Let the C compiler expand the real header aliases, rather than teaching
    // the test a second numeric value that could drift along with Rust.
    let source = format!(
        "{}\n{}\n_Static_assert(O_CLOEXEC == {rust_value}, \"Rust/newlib O_CLOEXEC mismatch\");\n",
        definition("_FNOINHERIT"),
        definition("O_CLOEXEC"),
    );
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
