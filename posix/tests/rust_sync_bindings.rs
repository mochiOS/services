use std::{
    io::Write,
    process::{Command, Stdio},
};

#[test]
fn platform_sync_types_have_sdk_layouts_and_generator_selects_native_representations() {
    let platform = include_str!("../../../libraries/libc/newlib/mochios.rs");
    let mut program = String::from(
        r#"
type c_uint = u32; type c_int = i32;
macro_rules! s { ($(pub struct $name:ident { $($field:ident: $ty:ty),* $(,)? })*) => { $(
    #[repr(C)] #[derive(Clone, Copy)] pub struct $name { $($field: $ty),* }
)* }; }
"#,
    );
    for name in [
        "sem_t",
        "pthread_once_t",
        "pthread_barrier_t",
        "pthread_barrierattr_t",
        "pthread_rwlockattr_t",
    ] {
        let start = platform.find(&format!("pub struct {name} {{")).unwrap();
        let end = start + platform[start..].find('}').unwrap() + 1;
        program.push_str("s! { ");
        program.push_str(&platform[start..end]);
        program.push_str(" }\n");
    }
    program.push_str(
        r#"
type pthread_rwlock_t = c_uint;
fn main() {
    assert_eq!((size_of::<sem_t>(), align_of::<sem_t>()), (16, 8));
    assert_eq!(core::mem::offset_of!(sem_t, initialized), 8);
    assert_eq!((size_of::<pthread_once_t>(), align_of::<pthread_once_t>()), (8, 4));
    assert_eq!((size_of::<pthread_rwlock_t>(), align_of::<pthread_rwlock_t>()), (4, 4));
    assert_eq!((size_of::<pthread_rwlockattr_t>(), align_of::<pthread_rwlockattr_t>()), (8, 4));
    assert_eq!((size_of::<pthread_barrier_t>(), align_of::<pthread_barrier_t>()), (32, 8));
    assert_eq!(core::mem::offset_of!(pthread_barrier_t, entered), 8);
    assert_eq!(core::mem::offset_of!(pthread_barrier_t, completed), 16);
    assert_eq!(core::mem::offset_of!(pthread_barrier_t, departed), 24);
    assert_eq!((size_of::<pthread_barrierattr_t>(), align_of::<pthread_barrierattr_t>()), (8, 4));
}
use std::mem::{size_of, align_of};
"#,
    );
    let directory = std::env::temp_dir().join(format!(
        "mochios-rust-sync-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    let executable = directory.join("probe");
    let mut compiler = Command::new("rustc")
        .args(["--edition=2024", "-Awarnings", "-"])
        .arg("-o")
        .arg(&executable)
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    compiler
        .stdin
        .take()
        .unwrap()
        .write_all(program.as_bytes())
        .unwrap();
    let result = compiler.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(Command::new(&executable).status().unwrap().success());
    let generator = directory.join("generate");
    let crate_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../libraries/libc")
        .canonicalize()
        .unwrap();
    assert!(
        Command::new("rustc")
            .arg(crate_root.join("build.rs"))
            .arg("-o")
            .arg(&generator)
            .status()
            .unwrap()
            .success()
    );
    let generated = Command::new(&generator)
        .env("CARGO_MANIFEST_DIR", crate_root)
        .env("OUT_DIR", &directory)
        .output()
        .unwrap();
    assert!(
        generated.status.success(),
        "{}",
        String::from_utf8_lossy(&generated.stderr)
    );
    let generated = std::fs::read_to_string(directory.join("newlib_mod.rs")).unwrap();
    for name in ["sem_t", "pthread_rwlock_t", "pthread_rwlockattr_t"] {
        assert!(generated.contains(&format!(
            "#[cfg(not(target_os = \"mochios\"))]\n    pub struct {name}"
        )));
    }
    assert!(generated.contains("if cfg!(target_os = \"mochios\") { 4 } else { 56 }"));
    assert!(generated.contains("if cfg!(target_os = \"mochios\") { 8 } else { 4 }"));
    assert!(platform.contains("PTHREAD_RWLOCK_INITIALIZER: pthread_rwlock_t = c_uint::MAX"));
    assert!(platform.contains(
        "PTHREAD_ONCE_INIT: pthread_once_t = pthread_once_t { initialized: 1, executed: 0 }"
    ));
    std::fs::remove_dir_all(directory).unwrap();
}
