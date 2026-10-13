#![cfg(all(target_arch = "x86_64", target_os = "linux"))]

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

fn compile(source: &str, arguments: &[&str], output: &Path) {
    let mut compiler = Command::new("rustc")
        .args(["--edition=2024", "-"])
        .args(arguments)
        .arg("-o")
        .arg(output)
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
    let result = compiler.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn independently_built_clients_share_one_snapshot_body() {
    let assembly = include_str!("../../../user/crates/posix-client/src/snapshot_x86_64.S");
    let library = format!(
        r#"
core::arch::global_asm!({assembly:?});
unsafe extern "C" {{ fn mochios_posix_capture_snapshot(); }}
pub fn capture_address() -> usize {{ mochios_posix_capture_snapshot as usize }}
"#
    );
    let directory = std::env::temp_dir().join(format!(
        "mochios-snapshot-linkage-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    let a = directory.join("libsnapshot_a.rlib");
    let b = directory.join("libsnapshot_b.rlib");
    compile(
        &library,
        &["--crate-name", "snapshot_a", "--crate-type", "rlib"],
        &a,
    );
    compile(
        &library,
        &["--crate-name", "snapshot_b", "--crate-type", "rlib"],
        &b,
    );
    for (index, (first, second)) in [("snapshot_a", "snapshot_b"), ("snapshot_b", "snapshot_a")]
        .into_iter()
        .enumerate()
    {
        let program = format!(
            r#"
extern crate {first};
extern crate {second};
unsafe extern "C" fn backend() -> u64 {{ 41 }}
fn main() {{
    let first = {first}::capture_address();
    let second = {second}::capture_address();
    assert_eq!(first, second);
    let capture: unsafe extern "C" fn(*mut u64, u64, unsafe extern "C" fn() -> u64) -> u64 =
        unsafe {{ std::mem::transmute(first) }};
    let mut context = [0u64; 22];
    assert_eq!(unsafe {{ capture(context.as_mut_ptr(), 0x1234000, backend) }}, 41);
    assert_ne!(context[0], 0);
    assert_ne!(context[1], 0);
    assert_eq!(context[3], 0x1234000);
}}
"#
        );
        let executable = directory.join(format!("probe-{index}"));
        let a_arg = format!("snapshot_a={}", a.display());
        let b_arg = format!("snapshot_b={}", b.display());
        let (first_arg, second_arg) = if index == 0 {
            (&a_arg, &b_arg)
        } else {
            (&b_arg, &a_arg)
        };
        compile(
            &program,
            &["--extern", first_arg, "--extern", second_arg],
            &executable,
        );
        let result = Command::new(executable).output().unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    std::fs::remove_dir_all(directory).unwrap();
}
