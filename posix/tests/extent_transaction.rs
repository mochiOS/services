//! Compose the production cache, target pins, PTE records and reserved cleanup
//! owner. Only physical page tables, IPC and scheduling are host substitutes.
use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn native_provider_memory_update_probe_tracks_the_authoritative_abi() {
    use mnu_abi::SyscallNumber as Number;
    let probe = include_str!("native_provider_memory_update.c");
    for (name, number) in [
        ("HANDLE_DUPLICATE", Number::HandleDuplicate),
        ("IPC_SEND", Number::IpcSendObjectHandles),
        ("HANDLE_RIGHTS_GET", Number::HandleRightsGet),
        ("HANDLE_CONTROL", Number::HandleControl),
        ("HANDLE_READ_AT", Number::HandleReadAt),
        (
            "PROVIDER_MEMORY_UPDATE_CREATE",
            Number::ProviderMemoryUpdateCreate,
        ),
    ] {
        assert!(probe.contains(&format!("{name} = {}", number as u64)));
    }
    assert_eq!(mnu_abi::memory_update::BEGIN, 1);
    assert_eq!(mnu_abi::memory_update::UNCHANGED, 2);
    assert_eq!(mnu_abi::memory_update::PUBLISH, 3);
}

#[test]
fn native_memory_admission_probe_uses_the_current_wait_and_creation_abi() {
    let probe = include_str!("native_memory_admission.c");
    assert!(probe.contains(&format!("HANDLE_WAIT_MANY = {}", mnu_abi::SyscallNumber::HandleWaitMany as u64)));
    assert!(probe.contains(&format!("PROVIDER_MEMORY_ADMISSION_CREATE = {}", mnu_abi::SyscallNumber::ProviderMemoryAdmissionCreate as u64)));
}

#[test]
fn owned_native_extent_composes_real_cache_records_and_cleanup_without_vm_lock_across_wait() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let fixture = include_str!("provider_cache_publication.rs")
        .replace("\"../../../core/", &format!("\"{}/core/", root.display()))
        .replace("mod task {", "mod task { pub(crate) use crate::native_extent_probe::deferred;")
        .replace("pub mod process {", "pub mod process { pub(crate) use crate::native_extent_probe::process::*;")
        .replace("mod paging {", "mod paging { pub(crate) use crate::native_extent_probe::paging::*;")
        .replace("mod mem {", "mod mem { pub(crate) use crate::native_extent_probe::{mapping_targets, tlb_shootdown, extent_transaction};")
        .replace("mod syscall {", "mod syscall { pub const EFAULT:u64=(-14i64) as u64;");
    let probe = include_str!("support/native_extent_transaction.rs")
        .replace(
            "\"../../../../core/",
            &format!("\"{}/core/", root.display()),
        )
        .replace(
            "\"../../../../../core/",
            &format!("\"{}/core/", root.display()),
        );
    let mut program = format!(
        "#![feature(allocator_api)]\n{fixture}\nextern crate self as mnu_abi;\npub const HANDLE_SEEK_START:u64={}; pub const HANDLE_SEEK_CURRENT:u64={}; pub const HANDLE_SEEK_END:u64={};\npub const HANDLE_SIGNAL_READABLE:u64={}; pub const HANDLE_SIGNAL_PEER_CLOSED:u64={};\n#[path={:?}] pub mod provider;\nmod native_extent_probe {{ {probe} }}\nmod cpu {{ pub struct SmapSmepGuard; impl SmapSmepGuard {{ pub fn new()->Self {{Self}} }} }}\n",
        mnu_abi::HANDLE_SEEK_START,
        mnu_abi::HANDLE_SEEK_CURRENT,
        mnu_abi::HANDLE_SEEK_END,
        mnu_abi::HANDLE_SIGNAL_READABLE,
        mnu_abi::HANDLE_SIGNAL_PEER_CLOSED,
        root.join("core/crates/abi/src/provider.rs")
    );
    // The production generation gate uses the native error domain. Keep the
    // composed fixture on that ABI too, rather than supplying errno stubs.
    program.push_str(&format!(
        "#[path={:?}] pub mod status;\n",
        root.join("core/crates/abi/src/status.rs")
    ));
    let scheduler = include_str!("../../../core/src/task/scheduler.rs");
    let start = scheduler.find("pub fn yield_now() {").unwrap();
    let end = start + scheduler[start..].find("\n}\n").unwrap() + 3;
    program.push_str("mod actual_scheduler {\n");
    program.push_str(&scheduler[start..end]);
    program.push_str(
        r#"
fn is_scheduler_enabled()->bool {false}
fn schedule_with_slot()->Option<(u64,usize)> {None}
fn current_thread_id()->Option<u64> {None}
unsafe fn switch_to_thread_with_slots(_:Option<u64>,_:u64,_:usize) {panic!("unexpected scheduling")}
mod x86_64 {pub mod instructions {pub mod interrupts {
    pub fn without_interrupts(f:impl FnOnce()) {f()}
}}}
}
"#,
    );
    let directory = std::env::temp_dir().join(format!(
        "mochios-owned-extent-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    let binary = directory.join("probe");
    let mut compiler = Command::new("rustup")
        .args([
            "run",
            "nightly-2026-07-16",
            "rustc",
            "--edition=2024",
            "--test",
            "-Awarnings",
            "-Cstrip=symbols",
            "-",
        ])
        .arg("-o")
        .arg(&binary)
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
    let compiled = compiler.wait_with_output().unwrap();
    if !compiled.status.success() {
        std::fs::remove_dir_all(&directory).unwrap();
    }
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let executed = Command::new(&binary)
        .args(["native_extent_probe::", "--nocapture", "--test-threads=1"])
        .output()
        .unwrap();
    std::fs::remove_dir_all(&directory).unwrap();
    assert!(
        executed.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&executed.stdout),
        String::from_utf8_lossy(&executed.stderr)
    );
    print!("{}", String::from_utf8_lossy(&executed.stdout));
}
