use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn native_wait_root_probe_matches_current_native_abi() {
    let source = include_str!("native_address_wait_root.c");
    assert!(source.contains(&format!(
        "number = {};",
        mnu_abi::SyscallNumber::WaitOnAddress as u64
    )));
}

#[test]
fn actual_wait_key_and_atomic_load_retain_root_and_reject_replaced_frames() {
    let source = include_str!("../../../core/src/syscall/address_wait.rs");
    let mut program = String::from(
        r#"
use std::sync::atomic::{AtomicU8, AtomicU16, AtomicU32, AtomicU64, Ordering};
const EFAULT:u64=Error::InvalidAddress.into_raw(); const EINVAL:u64=Error::InvalidArgument.into_raw();
thread_local! {
    static PID:std::cell::Cell<Option<u64>>=const {std::cell::Cell::new(Some(7))};
    static ROOT:std::cell::Cell<Option<u64>>=const {std::cell::Cell::new(Some(4096))};
    static MAPPED:std::cell::Cell<bool>=const {std::cell::Cell::new(true)};
    static PRESENT:std::cell::Cell<bool>=const {std::cell::Cell::new(true)};
    static LOCKED:std::cell::Cell<bool>=const {std::cell::Cell::new(false)};
    static PHYSICAL:std::cell::Cell<u64>=const {std::cell::Cell::new(0)};
    static LOADS:std::cell::Cell<u64>=const {std::cell::Cell::new(0)};
    static COPY_ERROR:std::cell::Cell<Option<Error>>=const {std::cell::Cell::new(None)};
    static OFFSET:std::cell::Cell<Option<u64>>=const {std::cell::Cell::new(Some(0))};
}
fn locked() {assert!(LOCKED.with(|v|v.get()));}
fn validate_user_ptr(_:u64,_:u64)->bool {assert!(!LOCKED.with(|v|v.get()));true}
fn copy_from_user_native(_:u64,bytes:&mut[u8])->Result<(),Error> {
    assert!(!LOCKED.with(|v|v.get()));if let Some(error)=COPY_ERROR.with(|v|v.get()){return Err(error);}
    bytes.fill(0);Ok(())
}
mod security {pub fn current_process_id()->Option<u64> {crate::PID.with(|v|v.get())}}
mod task {
    pub struct Process;
    impl Process {pub fn page_table(&self)->Option<u64> {crate::locked();crate::ROOT.with(|v|v.get())}}
    pub fn with_process<T>(pid:u64,f:impl FnOnce(&Process)->T)->Option<T> {
        assert_eq!(pid,7); if !crate::PRESENT.with(|v|v.get()) {return None;}
        crate::LOCKED.with(|v|assert!(!v.replace(true)));
        let result=f(&Process);crate::LOCKED.with(|v|v.set(false));Some(result)
    }
}
struct VirtAddr(u64); impl VirtAddr {fn new(address:u64)->Self {Self(address)}}
struct Physical(u64); impl Physical {fn as_u64(&self)->u64 {self.0}}
mod mem {pub mod paging {
    pub fn is_user_range_mapped_in_table(root:u64,address:u64,_:u64)->bool {
        crate::locked();assert_eq!(crate::ROOT.with(|v|v.get()),Some(root));assert_eq!(address,8192);
        crate::MAPPED.with(|v|v.get())
    }
    pub fn translate_addr_in_table(root:u64,address:crate::VirtAddr)->Option<(crate::Physical,())> {
        crate::locked();assert_eq!(crate::ROOT.with(|v|v.get()),Some(root));assert_eq!(address.0,8192);
        Some((crate::Physical(crate::PHYSICAL.with(|v|v.get())),()))
    }
    pub fn physical_memory_offset()->Option<u64> {
        crate::locked();crate::LOADS.with(|v|v.set(v.get()+1));crate::OFFSET.with(|v|v.get())
    }
}}
mod cpu {pub struct SmapSmepGuard; impl SmapSmepGuard {pub fn new()->Self {crate::locked();Self}}}
mod actual {use super::*;
"#,
    );
    program.insert_str(
        0,
        &format!(
            "mod status {{\n{}\n}}\nuse status::Error;\n",
            include_str!("../../../core/crates/abi/src/status.rs")
        ),
    );
    for entry in [
        "struct AddressKey {",
        "fn resolve_key(",
        "pub(crate) fn read_upcall_defer_word(",
        "fn load_value(",
        "fn load_resident_value(",
    ] {
        let start = source.find(entry).unwrap();
        let end = start + source[start..].find("\n}\n").unwrap() + 3;
        if entry.starts_with("struct") {
            program.push_str("#[derive(Clone, Copy)]\n");
        }
        program.push_str(&source[start..end]);
    }
    program.push_str(
        r#"
pub fn test() {
    let word=AtomicU64::new(0x12345678);
    PHYSICAL.with(|v|v.set(&word as *const AtomicU64 as u64));
    let key=resolve_key(8192,8).unwrap();
    for (size,expected) in [(1,0x78),(2,0x5678),(4,0x12345678),(8,0x12345678)] {
        assert_eq!(load_value(key,size),Ok(expected));
    }
    assert_eq!(LOADS.with(|v|v.get()),4);
    assert_eq!(read_upcall_defer_word(8192),Ok(0x12345678));
    for error in [Error::InvalidAddress,Error::ResourceUnavailable,Error::BackingFailure]{
        COPY_ERROR.with(|v|v.set(Some(error)));
        assert_eq!(resolve_key(8192,8).err(),Some(error.into_raw()));
        assert_eq!(read_upcall_defer_word(8192),Err(error.into_raw()));
    }
    COPY_ERROR.with(|v|v.set(None));
    for offset in [None,Some(u64::MAX)]{
        OFFSET.with(|v|v.set(offset));assert_eq!(load_value(key,8),Err(Error::BackingFailure.into_raw()));
    }
    OFFSET.with(|v|v.set(Some(0)));
    assert_eq!(load_value(key,3),Err(EINVAL));
    let unaligned=AddressKey {virtual_address:8193,..key};
    assert_eq!(load_value(unaligned,8),Err(EINVAL));
    PHYSICAL.with(|v|v.set(v.get()+4096)); assert_eq!(load_value(key,8),Err(EFAULT));
    PHYSICAL.with(|v|v.set(key.physical_address));
    MAPPED.with(|v|v.set(false));
    assert!(resolve_key(8192,8).is_err());assert_eq!(load_value(key,8),Err(EFAULT));
    MAPPED.with(|v|v.set(true)); ROOT.with(|v|v.set(Some(12288)));
    assert_eq!(load_value(key,8),Err(EFAULT));
    ROOT.with(|v|v.set(None)); assert_eq!(load_value(key,8),Err(EFAULT));
    assert!(resolve_key(8192,8).is_err());
    PRESENT.with(|v|v.set(false));assert_eq!(load_value(key,8),Err(Error::NotReady.into_raw()));
    PID.with(|v|v.set(None));assert_eq!(load_value(key,8),Err(Error::NotReady.into_raw()));
    assert_eq!(LOADS.with(|v|v.get()),7); assert!(!LOCKED.with(|v|v.get()));
}
}
fn main() {actual::test();}
"#,
    );
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory =
        std::env::temp_dir().join(format!("mochios-wait-root-{}-{nonce}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let executable = directory.join("probe");
    let mut compile = Command::new("rustc")
        .args(["--edition=2024", "--crate-name=wait_root_probe", "-", "-o"])
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
    let output = compile.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(Command::new(executable).status().unwrap().success());
    std::fs::remove_dir_all(directory).unwrap();
}
