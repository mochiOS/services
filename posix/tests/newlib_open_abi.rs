use std::fs;
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

struct Temporary(std::path::PathBuf);

impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn rust_close_on_exec_flag_matches_the_newlib_header() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let temporary = Temporary(std::env::temp_dir().join(format!(
        "mochios-newlib-flags-{}-{nonce}",
        std::process::id()
    )));
    fs::create_dir_all(&temporary.0).unwrap();
    let libc = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../libraries/libc")
        .canonicalize()
        .unwrap();
    let generator = temporary.0.join("generator");
    let output = Command::new("rustc")
        .arg(libc.join("build.rs"))
        .arg("-o")
        .arg(&generator)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = Command::new(generator)
        .env("CARGO_MANIFEST_DIR", libc)
        .env("OUT_DIR", &temporary.0)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let generated = fs::read_to_string(temporary.0.join("newlib_mod.rs")).unwrap();
    let constant = generated.find("pub const O_CLOEXEC:").unwrap();
    let start = generated[..constant].rfind("cfg_if! {").unwrap();
    let end = constant + generated[constant..].find("\n}\n").unwrap() + 2;
    let block = &generated[start..end];
    let rust = include_str!("../../../libraries/libc/newlib/mochios.rs");
    let rust_value = rust
        .lines()
        .find_map(|line| line.strip_prefix("pub const O_CLOEXEC: c_int = "))
        .expect("mochiOS libc close-on-exec flag")
        .trim_end_matches(';');
    // Compile the actual generated conditional definition. In particular this
    // catches upstream local items shadowing the platform's glob re-export.
    let probe = temporary.0.join("probe.rs");
    fs::write(
        &probe,
        format!(
            r#"
#[allow(non_camel_case_types)] type c_int = i32;
mod platform {{ pub const O_CLOEXEC: i32 = {rust_value}; }}
#[allow(unused_imports)] use platform::*;
macro_rules! cfg_if {{
    (if #[cfg($condition:meta)] {{ $($yes:item)* }} else {{ $($no:item)* }}) => {{
        $(#[cfg($condition)] $yes)*
        $(#[cfg(not($condition))] $no)*
    }};
}}
{block}
fn main() {{ println!("{{}}", O_CLOEXEC); }}
"#
        ),
    )
    .unwrap();
    let mut generated_value = None;
    for (target, expected) in [
        ("mochios", 0x40000),
        ("espidf", 0x40000),
        ("other", 0x80000),
    ] {
        let binary = temporary.0.join(target);
        let output = Command::new("rustc")
            .arg(&probe)
            .args(["-Aexplicit_builtin_cfgs_in_flags", "--cfg"])
            .arg(format!("target_os=\"{target}\""))
            .arg("-o")
            .arg(&binary)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let output = Command::new(binary).output().unwrap();
        assert!(output.status.success());
        let value: i32 = String::from_utf8(output.stdout)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert_eq!(value, expected, "generated public constant for {target}");
        if target == "mochios" {
            generated_value = Some(value);
        }
    }
    let rust_value = generated_value.unwrap();
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
