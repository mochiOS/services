use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn production_capture_pins_exact_objects_and_attenuates_without_duplicate_authority() {
    let source = include_str!("../../../core/src/task/handle_table.rs");
    let identity_end = source.find("/// Kernel object identity stored").unwrap();
    let identity_start = source[..source.find("pub struct ObjectHandle(u32)").unwrap()]
        .rfind("#[derive(")
        .unwrap();
    let identity = &source[identity_start..identity_end];
    let entry_start = source[..source.find("pub struct ObjectHandleEntry {").unwrap()]
        .rfind("#[derive(")
        .unwrap();
    let table =
        &source[entry_start..source[entry_start..].find("#[cfg(test)]").unwrap() + entry_start];
    let snapshot = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../core/src/task/handle_snapshot.rs")
        .canonicalize()
        .unwrap();
    let wire = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../core/crates/abi/src/handle_snapshot.rs")
        .canonicalize()
        .unwrap();
    // The production identity, rights, table, entry and snapshot code executes
    // here. Only resource payloads are replaced with observable Arc values.
    let program = format!(
        r#"
#![allow(dead_code)]
extern crate alloc;
extern crate self as mnu_abi;
#[path={wire:?}] pub mod handle_snapshot;
use std::sync::{{Arc, atomic::{{AtomicBool, Ordering}}}};
static FAIL_NEXT:AtomicBool=AtomicBool::new(false);
struct Allocator;
unsafe impl std::alloc::GlobalAlloc for Allocator {{
    unsafe fn alloc(&self,layout:std::alloc::Layout)->*mut u8 {{
        if FAIL_NEXT.swap(false,Ordering::Relaxed) {{ return std::ptr::null_mut(); }}
        unsafe {{ std::alloc::System.alloc(layout) }}
    }}
    unsafe fn dealloc(&self,pointer:*mut u8,layout:std::alloc::Layout) {{ unsafe {{std::alloc::System.dealloc(pointer,layout)}} }}
    unsafe fn realloc(&self,pointer:*mut u8,layout:std::alloc::Layout,size:usize)->*mut u8 {{
        if FAIL_NEXT.swap(false,Ordering::Relaxed) {{ return std::ptr::null_mut(); }}
        unsafe {{std::alloc::System.realloc(pointer,layout,size)}}
    }}
}}
#[global_allocator] static ALLOCATOR:Allocator=Allocator;
#[derive(Debug)] pub struct HandleInfo {{ pub handle:u32,pub reserved:u32,pub rights:u64 }}
mod task {{
    pub mod handle_table {{
        use alloc::{{boxed::Box,collections::BTreeMap,sync::Arc,vec::Vec}};
        pub const PROCESS_MAX_OBJECT_HANDLES:usize=4096;
        #[derive(Clone,Debug)] pub struct KernelObject(pub Arc<u64>);
        {identity}
        {table}
    }}
    #[path={snapshot:?}] pub mod handle_snapshot;
}}
use task::handle_table::*;
use task::handle_snapshot::ExportError;
fn entry(object:&Arc<u64>,rights:HandleRights)->ObjectHandleEntry {{ ObjectHandleEntry::new(KernelObject(object.clone()),rights) }}
fn main() {{
    let mut table=ObjectHandleTable::new_boxed();
    let original=Arc::new(17);
    let original_weak=Arc::downgrade(&original);
    let rights=HandleRights::READ.union(HandleRights::TRANSFER);
    let handle=table.insert(entry(&original,rights)).unwrap();
    assert!(table.duplicate_restricted(handle,HandleRights::READ).is_none());
    let snapshot=table.capture().unwrap();
    assert_eq!(snapshot.len(),1);
    let metadata:Vec<_>=snapshot.describe().collect();
    assert_eq!((metadata[0].handle,metadata[0].reserved,metadata[0].rights),(handle.raw(),0,rights.bits()));
    let mut description=[0xa5;64];
    let length=snapshot.read_at(0,&mut description);
    assert_eq!(length,32);
    assert_eq!(u32::from_le_bytes(description[0..4].try_into().unwrap()),1);
    assert_eq!(u32::from_le_bytes(description[4..8].try_into().unwrap()),1);
    assert_eq!(u32::from_le_bytes(description[8..12].try_into().unwrap()),16);
    assert_eq!(&description[12..16],&[0;4]);
    assert_eq!(u32::from_le_bytes(description[16..20].try_into().unwrap()),handle.raw());
    assert_eq!(u64::from_le_bytes(description[24..32].try_into().unwrap()),rights.bits());
    assert_eq!(&description[32..],&[0xa5;32]);
    for offset in 0..36 {{ for size in 0..35 {{
        let mut output=[0xa5;40];
        let copied=snapshot.read_at(offset as u64,&mut output[..size]);
        let expected=size.min(length.saturating_sub(offset));
        assert_eq!(copied,expected);
        if expected>0 {{ assert_eq!(&output[..expected],&description[offset..offset+expected]); }}
        assert!(output[expected..].iter().all(|value|*value==0xa5));
    }} }}
    assert_eq!(snapshot.read_at(u64::MAX,&mut [0;1]),0);
    assert!(table.close(handle));
    let replacement=Arc::new(29);
    // Drive the real allocation cursor around to reuse the same native slot.
    for _ in 1..PROCESS_MAX_OBJECT_HANDLES {{
        let transient=table.insert(entry(&replacement,rights)).unwrap();
        assert!(table.close(transient));
    }}
    let reused=table.insert(entry(&replacement,rights)).unwrap();
    assert_eq!(reused,handle);
    let delegated=snapshot.export_restricted(handle,HandleRights::READ).unwrap();
    assert!(Arc::ptr_eq(&delegated.object().0,&original));
    assert_eq!(delegated.rights(),HandleRights::READ);
    let live=table.export_restricted(handle,HandleRights::READ).unwrap();
    assert!(Arc::ptr_eq(&live.object().0,&replacement));
    assert!(matches!(snapshot.export_restricted(handle,HandleRights::WRITE),Err(ExportError::Denied)));
    assert!(matches!(snapshot.export_restricted(handle,HandleRights::DUPLICATE),Err(ExportError::Denied)));
    assert!(matches!(snapshot.export_restricted(ObjectHandle::from_raw(2).unwrap(),HandleRights::empty()),Err(ExportError::Missing)));
    drop(original);
    assert!(original_weak.upgrade().is_some());
    drop(snapshot);
    assert!(original_weak.upgrade().is_some()); // delegated ownership remains
    drop(delegated);
    assert!(original_weak.upgrade().is_none());

    let private=Arc::new(41);
    let private_weak=Arc::downgrade(&private);
    let private_rights=HandleRights::READ.union(HandleRights::DUPLICATE);
    let private_handle=table.insert(entry(&private,private_rights)).unwrap();
    let snapshot=table.capture().unwrap();
    assert_eq!(snapshot.len(),2);
    assert!(matches!(snapshot.export_restricted(private_handle,HandleRights::READ),Err(ExportError::Denied)));
    assert!(matches!(snapshot.export_restricted(private_handle,HandleRights::empty()),Err(ExportError::Denied)));
    assert!(snapshot.describe().any(|info|info.handle==private_handle.raw() && info.rights==private_rights.bits()));
    assert!(table.close(private_handle));
    drop(private);
    assert!(private_weak.upgrade().is_none()); // metadata does not pin nontransferable objects
    drop(snapshot);

    let before=Arc::strong_count(&replacement);
    FAIL_NEXT.store(true,Ordering::Relaxed);
    assert!(table.capture().is_err());
    assert!(!FAIL_NEXT.load(Ordering::Relaxed));
    assert_eq!(Arc::strong_count(&replacement),before);
    assert_eq!(table.describe().len(),1);
    assert!(table.close(handle));
    let empty=table.capture().unwrap();
    assert_eq!(empty.len(),0);
    assert_eq!(empty.describe().count(),0);
    assert!(matches!(empty.export_restricted(handle,HandleRights::empty()),Err(ExportError::Missing)));
}}
"#
    );
    let directory = std::env::temp_dir().join(format!(
        "mochios-handle-reference-snapshot-{}",
        std::process::id()
    ));
    std::fs::create_dir(&directory).unwrap();
    let executable = directory.join("probe");
    let mut compile = Command::new("rustc")
        .args([
            "--edition=2024",
            "--crate-name=handle_reference_snapshot",
            "-",
            "-o",
        ])
        .arg(&executable)
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    compile
        .stdin
        .take()
        .unwrap()
        .write_all(program.as_bytes())
        .unwrap();
    let result = compile.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let executed = Command::new(executable).output().unwrap();
    std::fs::remove_dir_all(directory).unwrap();
    assert!(
        executed.status.success(),
        "{}",
        String::from_utf8_lossy(&executed.stderr)
    );
}
