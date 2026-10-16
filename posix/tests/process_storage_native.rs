//! Run the production Process container constructor with allocation faults.
//! No scheduler, address-space installation, or publication is simulated here.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn process_container_allocation_failure_releases_every_unpublished_owner() {
    let process = include_str!("../../../core/src/task/process.rs");
    let table = include_str!("../../../core/src/task/handle_table.rs");
    let launch = include_str!("../../../core/src/task/launch_context.rs");
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let mut program = String::from(
        r#"
#![feature(allocator_api)]
#![allow(dead_code)]
extern crate alloc;
extern crate self as mnu_abi;
use alloc::{boxed::Box,string::String,sync::Arc,vec::Vec};
use std::sync::atomic::{AtomicU8,AtomicU64,AtomicUsize,Ordering};
static FAIL_AFTER:AtomicUsize=AtomicUsize::new(usize::MAX);
static LIVE:AtomicUsize=AtomicUsize::new(0);
struct Allocator;
unsafe impl std::alloc::GlobalAlloc for Allocator {
    unsafe fn alloc(&self,layout:std::alloc::Layout)->*mut u8 {
        let remaining=FAIL_AFTER.load(Ordering::Relaxed);
        if remaining!=usize::MAX {
            if remaining==0 {FAIL_AFTER.store(usize::MAX,Ordering::Relaxed);return std::ptr::null_mut();}
            FAIL_AFTER.store(remaining-1,Ordering::Relaxed);
        }
        let pointer=unsafe{std::alloc::System.alloc(layout)};
        if !pointer.is_null(){LIVE.fetch_add(1,Ordering::Relaxed);}pointer
    }
    unsafe fn dealloc(&self,pointer:*mut u8,layout:std::alloc::Layout) {
        LIVE.fetch_sub(1,Ordering::Relaxed);
        unsafe{std::alloc::System.dealloc(pointer,layout)}
    }
}
#[global_allocator]static ALLOCATOR:Allocator=Allocator;
pub mod status {
"#,
    );
    program.push_str(include_str!("../../../core/crates/abi/src/status.rs"));
    program.push_str("}\n");
    program.push_str(&format!(
        "#[path={:?}]mod ids;\nuse ids::{{ProcessId,ProcessState,PrivilegeLevel}};\n",
        root.join("core/src/task/ids.rs")
    ));
    probe::constants(
        &mut program,
        include_str!("../../../core/crates/abi/src/lib.rs"),
        &["PROCESS_STATE_RUNNING"],
    );
    // Types stored in empty/None fields are not exercised by construction.
    program.push_str(
        r#"
mod mem {pub mod detached_roots {pub struct Root;}}
type ApplicationIdentity=(); type PendingExecSecurity=(); type MemoryRegion=();
type MmioMapping=(); type DmaBuffer=();
mod config {
    pub struct Ipc {pub mailbox_cap:usize,pub max_msg_size:usize}
    pub struct Kernel {pub ipc:Ipc}
    pub fn kernel()->Kernel {Kernel{ipc:Ipc{mailbox_cap:64,max_msg_size:4096}}}
}
"#,
    );
    let capability = include_str!("../../../core/src/capability/mod.rs");
    program.push_str("type Capability=();type KernelAuthority=();\n");
    program.push_str(probe::between(
        capability,
        "#[derive(Clone, Debug, Default)]\npub struct CapabilitySet",
        "/// capability 文字列の解析エラー",
    ));
    for name in ["CapabilitySet", "KernelAuthoritySet"] {
        let methods = &capability[capability.find(&format!("impl {name} {{")).unwrap()..];
        program.push_str(&format!("impl {name} {{\n"));
        let empty = &methods[methods.find("    pub fn empty()").unwrap()..];
        let end = empty.find("\n    }\n").unwrap() + "\n    }\n".len();
        program.push_str(&empty[..end]);
        program.push_str("\n}\n");
    }
    // Use the production empty table layout/constructor; mutation has its own
    // real-table differential tests in handle_storage_native.rs.
    program.push_str("type ObjectHandle=u32;type ObjectHandleEntry=();\n");
    program.push_str(probe::between(
        table,
        "#[derive(Clone, Debug)]\npub struct ObjectHandleTable",
        "    pub fn new_boxed()",
    ));
    program.push_str("}\n");
    program.push_str(probe::between(
        launch,
        "pub const PROCESS_MAX_INHERITED_HANDLES",
        "    pub fn new_boxed()",
    ));
    program.push_str("}\nuse status::Error;\n");
    program.push_str(probe::between(
        process,
        "#[derive(Clone, Copy, Debug)]\npub struct ResourceLimits",
        "#[derive(Clone, Debug)]\npub enum MemoryBacking",
    ));
    program.push_str(probe::between(
        process,
        "#[derive(Debug)]\npub struct ProcessObject",
        "    pub const fn id(&self)",
    ));
    program.push_str("}\n");
    program.push_str(probe::between(
        process,
        "pub struct Process {",
        "    /// プロセスIDを取得",
    ));
    program.push_str(
        r#"
}
fn main() {
    let baseline=LIVE.load(Ordering::Relaxed);
    for failure in 0..3 {
        FAIL_AFTER.store(failure,Ordering::Relaxed);
        let result=Process::try_new("unpublished",PrivilegeLevel::User,8);
        assert!(matches!(result,Err(Error::ResourceUnavailable)));
        assert_eq!(FAIL_AFTER.load(Ordering::Relaxed),usize::MAX);
        assert_eq!(LIVE.load(Ordering::Relaxed),baseline,"failure {failure} leaked an owner");
    }
    for name in ["","process","abcdefghijklmnopqrstuvwxyz0123456789"] {
        FAIL_AFTER.store(3,Ordering::Relaxed);
        let process=Process::try_new(name,PrivilegeLevel::User,8).unwrap();
        assert_eq!(FAIL_AFTER.swap(usize::MAX,Ordering::Relaxed),0,"unexpected allocation");
        assert_eq!(LIVE.load(Ordering::Relaxed),baseline+3);
        let length=name.len().min(32);
        assert_eq!(process.name_len,length);
        assert_eq!(&process.name[..length],&name.as_bytes()[..length]);
        assert_eq!(process.state,ProcessState::Running);
        assert_eq!(process.privilege,PrivilegeLevel::User);
        assert_eq!(process.priority,8);
        assert_eq!(process.object.id,process.id);
        assert_eq!(process.object.state.load(Ordering::Relaxed),PROCESS_STATE_RUNNING as u8);
        assert_eq!(process.object.exit_code.load(Ordering::Relaxed),0);
        assert!(process.object_handles.entries.is_empty());assert_eq!(process.object_handles.next,1);
        assert_eq!(process.launch_context.inherited_handles.len(),0);
        assert_eq!(process.launch_context.inherited_values.len(),0);
        assert!(process.capabilities.caps.is_empty());assert!(process.kernel_authorities.authorities.is_empty());
        assert!(process.page_table.is_none());assert!(process.pending_image_root.is_none());
        assert!(process.memory_regions.is_empty());assert!(process.exe_path.is_empty());
        drop(process);assert_eq!(LIVE.load(Ordering::Relaxed),baseline);
    }
}
"#,
    );
    probe::run_with_toolchain(&program, "nightly-2026-07-16");
}

#[test]
fn all_process_creation_paths_use_fallible_containers_before_publication() {
    let exec = include_str!("../../../core/src/syscall/exec.rs");
    let kernel = include_str!("../../../core/src/kernel.rs");
    for source in [exec, kernel] {
        assert!(!source.contains("Process::new("));
        assert_eq!(source.matches("Process::try_new(").count(), 2);
    }
    let snapshot = &exec[exec.find("fn create_from_address_space(").unwrap()..];
    assert!(
        snapshot.find("Process::try_new(").unwrap()
            < snapshot.find("consume_address_space_for_create(").unwrap()
    );
    assert!(
        snapshot.find("Process::try_new(").unwrap()
            < snapshot.find("retain_created_process(").unwrap()
    );
    let idle = probe::between(
        kernel,
        "fn spawn_ap_idle_thread()",
        "/// カーネルメイン関数",
    );
    let failure = probe::between(idle, "Err(_) => {", "    let idle_pid");
    assert!(failure.contains("task::free_kernel_stack(kernel_stack)"));
    assert!(failure.contains("Kernel::Memory(crate::result::Memory::OutOfMemory)"));
}
