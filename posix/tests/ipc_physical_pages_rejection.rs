use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn actual_legacy_page_sender_rejects_physical_arrays_before_lookup_or_dereference() {
    let source = include_str!("../../../core/src/syscall/ipc.rs");
    let start = source.find("pub fn send_pages(").unwrap();
    let end = source[start..]
        .find("fn map_external_pages_for_receiver(")
        .unwrap()
        + start;
    let mut program = String::from(
        r#"
use std::sync::atomic::{AtomicBool,AtomicUsize,Ordering};
const EINVAL:u64=(-22i64) as u64;const EACCES:u64=(-13i64) as u64;const EFAULT:u64=(-14i64) as u64;const EAGAIN:u64=(-11i64) as u64;
static ALLOWED:AtomicBool=AtomicBool::new(true);static LOOKUPS:AtomicUsize=AtomicUsize::new(0);static SENT:AtomicUsize=AtomicUsize::new(0);
fn ipc_max_external_pages()->usize {1024}
struct EndpointRights;impl EndpointRights {const RECV:Self=Self;fn contains(&self,_:Self)->bool {true}}
struct Record {rights:EndpointRights,thread_id:u64}
fn endpoint_record_from_handle(_:u64)->Option<Record> {None}
mod capability {pub enum Capability {IpcClient,IpcServer}}
mod syscall {pub mod security {
    pub fn caller_has_any_capability(_: &[crate::capability::Capability])->bool {crate::ALLOWED.load(crate::Ordering::Acquire)}
    pub fn current_process_id()->Option<u64> {Some(1)}
}}
mod task {
    pub struct Process;impl Process {pub fn page_table(&self)->Option<u64> {Some(4096)}}
    pub fn with_process<T>(_:u64,f:impl FnOnce(&Process)->T)->Option<T> {Some(f(&Process))}
    pub fn thread_slot_index_and_generation_by_u64(endpoint:u64)->Option<(usize,u64)> {crate::LOOKUPS.fetch_add(1,crate::Ordering::AcqRel);(endpoint==9).then_some((1,1))}
}
fn send_virtual_pages_from_kernel(dest:u64,start:u64,total:u64,count:usize,table:u64,source:u64)->bool {
    assert_eq!((dest,start,total,count,table,source),(9,0x10000,8192,2,4096,0x10000));SENT.fetch_add(1,Ordering::AcqRel);true
}
"#,
    );
    program.push_str(&source[start..end]);
    program.push_str(
        r#"
fn main() {
    for pointer in [1,0xdeadbeef,u64::MAX] {assert_eq!(send_pages(9,pointer,2,0x10000),EINVAL);}
    assert_eq!(LOOKUPS.load(Ordering::Acquire),0);assert_eq!(SENT.load(Ordering::Acquire),0);
    assert_eq!(send_pages(9,0,0,0x10000),EINVAL);
    assert_eq!(send_pages(9,0,1025,0x10000),EINVAL);
    assert_eq!(send_pages(9,0,2,0x10001),EINVAL);
    assert_eq!(send_pages(9,0,2,0x10000),0);assert_eq!(SENT.load(Ordering::Acquire),1);
    ALLOWED.store(false,Ordering::Release);assert_eq!(send_pages(9,u64::MAX,2,0x10000),EACCES);
    assert_eq!(SENT.load(Ordering::Acquire),1);
}
"#,
    );
    let directory = std::env::temp_dir().join(format!(
        "mochios-ipc-physical-{}-{}",
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
    let result = Command::new(&executable).output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    std::fs::remove_dir_all(directory).unwrap();
}
