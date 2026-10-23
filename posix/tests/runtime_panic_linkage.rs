//! The same runtime archive must link into both C programs and Rust std
//! programs. A fallback handler must not replace the application's handler.
use std::process::{Command, Output};

struct Temporary(std::path::PathBuf);
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn success(output: Output) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn actual_fallback_links_with_c_and_yields_to_rust_std_panic_handler() {
    let directory = Temporary(std::env::temp_dir().join(format!(
        "mochios-runtime-panic-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    )));
    std::fs::create_dir(&directory.0).unwrap();
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let start = runtime.find("#[panic_handler]").unwrap();
    let end = start + runtime[start..].find("\n}\n").unwrap() + 3;
    let source = format!(
        r#"
#![no_std]
#![feature(linkage)]
{}
unsafe extern "C" {{fn _exit(code:i32)->!;}}
fn process_exit(code:i32)->!{{unsafe{{_exit(code)}}}}
#[unsafe(no_mangle)]
pub extern "C" fn runtime_probe(fail:bool)->i32{{
    assert!(!fail,"runtime panic probe");
    7
}}
"#,
        &runtime[start..end]
    );
    let library_source = directory.0.join("runtime.rs");
    let archive = directory.0.join("libruntime_probe.a");
    std::fs::write(&library_source, source).unwrap();
    success(
        Command::new("rustup")
            .args([
                "run",
                "nightly-2026-07-16",
                "rustc",
                "--edition=2024",
                "--crate-type=staticlib",
                "-Cpanic=abort",
                "-Ccodegen-units=1",
            ])
            .arg(&library_source)
            .arg("-o")
            .arg(&archive)
            .output()
            .unwrap(),
    );
    let c_source = directory.0.join("main.c");
    let c_program = directory.0.join("c-probe");
    std::fs::write(
        &c_source,
        r#"
#include <stdbool.h>
extern int runtime_probe(bool fail);
int main(int argc,char **argv){(void)argv;return runtime_probe(argc>1);}
"#,
    )
    .unwrap();
    success(
        Command::new("cc")
            .args(["-Wall", "-Wextra", "-Werror", "-Wl,--gc-sections"])
            .arg(&c_source)
            .arg(&archive)
            .arg("-o")
            .arg(&c_program)
            .output()
            .unwrap(),
    );
    assert_eq!(Command::new(&c_program).status().unwrap().code(), Some(7));
    assert_eq!(
        Command::new(&c_program)
            .arg("panic")
            .status()
            .unwrap()
            .code(),
        Some(127)
    );

    let rust_source = directory.0.join("main.rs");
    let rust_program = directory.0.join("rust-probe");
    std::fs::write(
        &rust_source,
        r#"
unsafe extern "C" {fn runtime_probe(fail:bool)->i32;}
fn main(){std::process::exit(unsafe{runtime_probe(std::env::args().len()>1)});}
"#,
    )
    .unwrap();
    success(
        Command::new("rustup")
            .args([
                "run",
                "nightly-2026-07-16",
                "rustc",
                "--edition=2024",
                "-Cpanic=abort",
            ])
            .arg(&rust_source)
            .arg("-L")
            .arg(format!("native={}", directory.0.display()))
            .arg("-lstatic=runtime_probe")
            .arg("-o")
            .arg(&rust_program)
            .output()
            .unwrap(),
    );
    assert_eq!(
        Command::new(&rust_program).status().unwrap().code(),
        Some(7)
    );
    let output = Command::new(&rust_program).arg("panic").output().unwrap();
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(
        output.status.signal(),
        Some(6),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("runtime panic probe"));
}
