use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn actual_outgoing_decoder_rejects_forged_native_delivery_flags() {
    let source = include_str!("../../../core/src/syscall/ipc.rs");
    let start = source.find("fn decode_outgoing_object_handles(").unwrap();
    let end = start + source[start..].find("\n}\n").unwrap() + 3;
    let mut program = String::from(
        r#"
extern crate self as mnu_abi;
#[repr(C)] struct IpcObjectHandles { count: u32, delivery_flags: u32, handles: [u64; 8] }
const MAX_OBJECT_HANDLES: usize = 4;
const EFAULT: u64 = status::Error::InvalidAddress.into_raw();
const EINVAL: u64 = status::Error::InvalidArgument.into_raw();
const EBADF: u64 = (-9i64) as u64;
#[derive(Debug)] struct ObjectHandle(u32);
impl ObjectHandle { fn from_raw(raw: u32) -> Option<Self> { (raw != 0).then_some(Self(raw)) } }
struct HandleRights(u64);
impl HandleRights { fn from_bits(bits: u64) -> Option<Self> { (bits <= 511).then_some(Self(bits)) } }
#[derive(Debug)] struct ObjectHandleAttachments { count: usize, handles: [Option<u64>; 4] }
impl ObjectHandleAttachments { fn empty() -> Self { Self { count: 0, handles: [None; 4] } } }
static EXPORTS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
mod syscall {
    pub fn copy_from_user_native(pointer: u64, output: &mut [u8]) -> Result<(), crate::status::Error> {
        unsafe { output.copy_from_slice(std::slice::from_raw_parts(pointer as *const u8, output.len())); }
        Ok(())
    }
    pub mod security { pub fn current_process_id() -> Option<u64> { Some(42) } }
}
fn export_object_handle(pid: u64, handle: ObjectHandle, rights: HandleRights) -> Result<u64, u64> {
    assert_eq!((pid, handle.0, rights.0), (42, 7, 1));
    EXPORTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    Ok(7)
}
"#,
    );
    program.push_str("pub mod status {\n");
    program.push_str(include_str!("../../../core/crates/abi/src/status.rs"));
    program.push_str("}\n");
    program.push_str(&source[start..end]);
    program.push_str(
        r#"
fn main() {
    let mut bytes = [0u8; 72];
    bytes[..4].copy_from_slice(&1u32.to_le_bytes());
    bytes[8..12].copy_from_slice(&7u32.to_le_bytes());
    bytes[16..24].copy_from_slice(&1u64.to_le_bytes());
    for flags in [1u32, 2, u32::MAX] {
        bytes[4..8].copy_from_slice(&flags.to_le_bytes());
        assert_eq!(decode_outgoing_object_handles(bytes.as_ptr() as u64).unwrap_err(), EINVAL);
    }
    assert_eq!(EXPORTS.load(std::sync::atomic::Ordering::Relaxed), 0);
    bytes[4..8].fill(0);
    assert_eq!(decode_outgoing_object_handles(bytes.as_ptr() as u64).unwrap().count, 1);
    assert_eq!(EXPORTS.load(std::sync::atomic::Ordering::Relaxed), 1);
    assert_eq!(decode_outgoing_object_handles(0).unwrap_err(), EFAULT);
}
"#,
    );
    run_probe(&program);
}

fn run_probe(program: &str) {
    let directory = std::env::temp_dir().join(format!(
        "mochios-native-delivery-{}-{}",
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
    let result = Command::new(executable).output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn actual_destination_resolver_marks_only_validated_send_handles() {
    let source = include_str!("../../../core/src/syscall/ipc.rs");
    let start = source.find("fn resolve_call_destination(").unwrap();
    let end = start + source[start..].find("\n}\n").unwrap() + 3;
    let mut program = String::from(
        r#"
extern crate self as mnu_abi;
const IPC_DELIVERY_ENDPOINT_HANDLE: u32 = 2;
const NOT_FOUND: u64 = status::Error::NotFound.into_raw();
const EACCES: u64 = status::Error::AccessDenied.into_raw();
mod task { pub const PROCESS_MAX_OBJECT_HANDLES: usize = 4096; }
struct HandleRights;
impl HandleRights { const SEND: Self = Self; }
struct EndpointRights(u32);
impl EndpointRights {
    const RECV: Self = Self(1);
    fn contains(&self, other: Self) -> bool { self.0 & other.0 == other.0 }
}
struct Endpoint { thread_id: u64 }
struct Record { thread_id: u64, rights: EndpointRights }
fn process_local_endpoint(raw: u64, _: HandleRights) -> Result<Endpoint, u64> {
    if raw == 7 { Ok(Endpoint { thread_id: 19 }) } else { Err(EACCES) }
}
fn ensure_endpoint_for_thread(thread: u64) -> Option<u64> {
    assert_eq!(thread, 19); Some(5001)
}
fn endpoint_record_from_handle(raw: u64) -> Option<Record> {
    match raw {
        5001 => Some(Record { thread_id: 19, rights: EndpointRights(1) }),
        5002 => Some(Record { thread_id: 20, rights: EndpointRights(0) }),
        _ => None,
    }
}
"#,
    );
    program.push_str(&source[start..end]);
    program.push_str(
        r#"
fn main() {
    assert_eq!(resolve_call_destination(7), Ok((19, 5001, 2)));
    assert_eq!(resolve_call_destination(8), Err(EACCES));
    assert_eq!(resolve_call_destination(5001), Ok((19, 5001, 0)));
    assert_eq!(resolve_call_destination(5002), Err(EACCES));
    assert_eq!(resolve_call_destination(6000), Err(NOT_FOUND));
}
"#,
    );
    program.push_str("pub mod status {\n");
    program.push_str(include_str!("../../../core/crates/abi/src/status.rs"));
    program.push_str("}\n");
    run_probe(&program);
}

#[test]
fn provider_dispatch_requires_native_origin_and_abi_layout_is_unchanged() {
    assert_eq!(std::mem::size_of::<mnu_abi::IpcObjectHandles>(), 72);
    assert_eq!(
        std::mem::offset_of!(mnu_abi::IpcObjectHandles, delivery_flags),
        4
    );
    for source in [
        include_str!("../../filesystem/src/main.rs"),
        include_str!("../src/main.rs"),
    ] {
        assert!(source.contains("delivery_flags != mnu_abi::IPC_DELIVERY_NATIVE_OBJECT"));
    }
    let ipc = include_str!("../../../core/src/syscall/ipc.rs");
    let native = &ipc[ipc
        .find("pub(crate) fn call_provider_from_kernel(")
        .unwrap()..ipc.find("fn call_endpoint_from_kernel(").unwrap()];
    assert!(native.contains("attachments.delivery_flags = mnu_abi::IPC_DELIVERY_NATIVE_OBJECT"));
    assert!(
        ipc.contains("output[4..8].copy_from_slice(&attachments.delivery_flags.to_le_bytes())")
    );
    let generic = &ipc[ipc.find("pub fn call_from_kernel(").unwrap()
        ..ipc
            .find("pub(crate) fn call_provider_from_kernel(")
            .unwrap()];
    assert!(!generic.contains("IPC_DELIVERY_NATIVE_OBJECT"));
}

#[test]
fn ordinary_delivery_flags_exclude_native_object_and_unknown_origin() {
    let mut handles = mnu_abi::IpcObjectHandles::default();
    for flags in [0, mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE] {
        handles.delivery_flags = flags;
        assert!(handles.is_user_delivery());
    }
    for flags in [mnu_abi::IPC_DELIVERY_NATIVE_OBJECT, 3, u32::MAX] {
        handles.delivery_flags = flags;
        assert!(!handles.is_user_delivery());
    }
    let filesystem = include_str!("../../filesystem/src/main.rs");
    assert!(filesystem.contains("delivery_flags != mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE"));
}
