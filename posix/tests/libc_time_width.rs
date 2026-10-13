use std::{fs, process::Command};

#[test]
fn generated_libc_time_t_selects_sdk_64bit_seconds_for_mochios() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let libc = root.join("libraries/libc").canonicalize().unwrap();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let temp =
        std::env::temp_dir().join(format!("mochios-time-width-{}-{nonce}", std::process::id()));
    fs::create_dir(&temp).unwrap();
    let build = temp.join("build");
    assert!(
        Command::new("rustc")
            .arg(libc.join("build.rs"))
            .args(["--edition=2021", "-o"])
            .arg(&build)
            .status()
            .unwrap()
            .success()
    );
    let output = Command::new(&build)
        .env("CARGO_MANIFEST_DIR", &libc)
        .env("OUT_DIR", &temp)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let generated = fs::read_to_string(temp.join("newlib_mod.rs")).unwrap();
    let start = generated
        .find("cfg_if! {\n    if #[cfg(any(\n        target_os = \"horizon\",")
        .unwrap();
    let branch = &generated[start..];
    let end = branch.find("\n}\n").unwrap() + 3;
    let microsecond_start = generated
        .find("#[cfg(target_os = \"mochios\")]\npub type suseconds_t")
        .unwrap();
    let microseconds = &generated[microsecond_start..];
    let microsecond_end = microseconds.find("cfg_if!").unwrap();
    let source = format!(
        r#"
type c_longlong = i64;
type c_long = i64;
macro_rules! cfg_if {{
    (if #[cfg($condition:meta)] {{ $($yes:tt)* }} else {{ $($no:tt)* }}) => {{
        #[cfg($condition)] mod selected {{ use super::*; $($yes)* }}
        #[cfg(not($condition))] mod selected {{ use super::*; $($no)* }}
        pub use selected::*;
    }};
}}
{}
{}
const _: [(); 8] = [(); core::mem::size_of::<time_t>()];
const _: [(); 8] = [(); core::mem::size_of::<suseconds_t>()];
fn main() {{ let seconds: time_t = 5_000_000_000; assert_eq!(seconds, 5_000_000_000); }}
"#,
        &branch[..end],
        &microseconds[..microsecond_end]
    );
    fs::write(temp.join("time.rs"), source).unwrap();
    let binary = temp.join("time");
    assert!(
        Command::new("rustc")
            .arg(temp.join("time.rs"))
            .args([
                "--cfg",
                "target_os=\"mochios\"",
                "-Aexplicit_builtin_cfgs_in_flags",
                "-o"
            ])
            .arg(&binary)
            .status()
            .unwrap()
            .success()
    );
    assert!(Command::new(binary).status().unwrap().success());
    fs::remove_dir_all(&temp).unwrap();
}
