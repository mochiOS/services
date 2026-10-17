use std::{fs, process::Command};

#[test]
fn production_resident_read_holds_root_lock_and_rejects_stale_or_missing_identity() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let source = fs::read_to_string(root.join("core/src/syscall/mod.rs")).unwrap();
    let helper = source
        .split("fn copy_out_of_current_root(")
        .nth(1)
        .unwrap()
        .split("/// Resident usercopy")
        .next()
        .unwrap();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory =
        std::env::temp_dir().join(format!("mochios-read-root-{}-{nonce}", std::process::id()));
    fs::create_dir(&directory).unwrap();
    let program = format!(
        r#"
#[derive(Debug, PartialEq)] pub enum Kernel {{ Memory(result::Memory) }}
mod result {{
    #[derive(Debug, PartialEq)] pub enum Memory {{ InvalidAddress }}
    pub type Result<T> = core::result::Result<T, crate::Kernel>;
}}
thread_local! {{
    static PID: std::cell::Cell<Option<u64>> = const {{ std::cell::Cell::new(Some(7)) }};
    static ROOT: std::cell::Cell<Option<u64>> = const {{ std::cell::Cell::new(Some(4096)) }};
    static LOCKED: std::cell::Cell<bool> = const {{ std::cell::Cell::new(false) }};
    static CALLS: std::cell::Cell<u64> = const {{ std::cell::Cell::new(0) }};
    static PRESENT: std::cell::Cell<bool> = const {{ std::cell::Cell::new(true) }};
}}
mod security {{ pub fn current_process_id() -> Option<u64> {{ super::PID.with(|pid| pid.get()) }} }}
mod task {{
    pub struct Process;
    impl Process {{
        pub fn page_table(&self) -> Option<u64> {{ super::ROOT.with(|root| root.get()) }}
        pub fn memory_regions(&self) -> &[()] {{ &[] }}
    }}
    pub fn with_process<T>(pid: u64, f: impl FnOnce(&Process) -> T) -> Option<T> {{
        assert_eq!(pid, 7);
        if !super::PRESENT.with(|present| present.get()) {{ return None; }}
        super::LOCKED.with(|locked| {{ assert!(!locked.replace(true)); }});
        let value = f(&Process);
        super::LOCKED.with(|locked| locked.set(false));
        Some(value)
    }}
}}
mod mem {{
pub mod mapping_admission {{
    pub fn check_access(_: &[()], _: u64, _: u64) -> crate::result::Result<()> {{ Ok(()) }}
}}
pub mod paging {{
    pub fn copy_from_user_in_table(table: u64, address: u64, bytes: &mut [u8]) -> crate::result::Result<()> {{
        assert!(crate::LOCKED.with(|locked| locked.get()));
        assert_eq!(crate::ROOT.with(|root| root.get()), Some(table));
        assert_eq!(address, 8192);
        crate::CALLS.with(|calls| calls.set(calls.get()+1));
        bytes.fill(0x71);
        Ok(())
    }}
}} }}
fn copy_out_of_current_root({helper}
fn main() {{
    let mut bytes = [0; 4];
    assert_eq!(copy_out_of_current_root(4096, 8192, &mut bytes), Ok(()));
    assert_eq!(bytes, [0x71; 4]);
    assert!(copy_out_of_current_root(12288, 8192, &mut bytes).is_err());
    ROOT.with(|root| root.set(None));
    assert!(copy_out_of_current_root(4096, 8192, &mut bytes).is_err());
    PRESENT.with(|present| present.set(false));
    assert!(copy_out_of_current_root(4096, 8192, &mut bytes).is_err());
    PID.with(|pid| pid.set(None));
    assert!(copy_out_of_current_root(4096, 8192, &mut bytes).is_err());
    assert_eq!(CALLS.with(|calls| calls.get()), 1);
}}
"#
    );
    let file = directory.join("probe.rs");
    fs::write(&file, program).unwrap();
    let executable = directory.join("probe");
    let compiled = Command::new("rustc")
        .arg(file)
        .args(["--edition=2024", "-o"])
        .arg(&executable)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    assert!(Command::new(executable).status().unwrap().success());
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn native_read_and_fault_preparation_revalidate_the_retained_root() {
    let source = include_str!("../../../core/src/syscall/mod.rs");
    let read = source
        .split("pub fn copy_from_user_native(")
        .nth(1)
        .unwrap()
        .split("fn fault_in_user_range(")
        .next()
        .unwrap();
    assert_eq!(
        read.matches("copy_out_of_current_root(user_pt, src_ptr, dst)")
            .count(),
        2
    );
    assert!(!read.contains("paging::copy_from_user_in_table"));
    let faults = source
        .split("fn fault_in_user_range(")
        .nth(1)
        .unwrap()
        .split("fn copy_out_of_current_root(")
        .next()
        .unwrap();
    assert!(faults.contains("with_process(pid"));
    assert!(faults.contains("process.page_table() != Some(table_phys)"));
}
