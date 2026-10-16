use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn production_resize_checks_control_and_propagates_type_and_backend_errors() {
    let source = include_str!("../../../core/src/syscall/handle.rs");
    let start = source.find("pub fn memory_object_resize(").unwrap();
    let end = start + source[start..].find("\n}\n").unwrap() + 3;
    let mut program = String::from(
        r#"
const SUCCESS:u64=0;const EINVAL:u64=22;
#[derive(Clone,Copy,Debug,PartialEq)]struct HandleRights(u64);
impl HandleRights {const CONTROL:Self=Self(256);}
enum KernelObject {VmObject(Memory),Other}
struct Memory;
thread_local! {static CALLS:std::cell::Cell<u64>=const {std::cell::Cell::new(0)};}
impl Memory {fn resize_memory(&self,length:u64)->Result<(),status::Error> {
    CALLS.with(|v|v.set(v.get()+1)); if length==u64::MAX {Err(status::Error::ResourceUnavailable)} else {Ok(())}
}}
fn object(raw:u64,rights:HandleRights)->Result<KernelObject,u64> {
    assert_eq!(rights,HandleRights::CONTROL);
    match raw {7=>Ok(KernelObject::VmObject(Memory)),8=>Err(13),9=>Ok(KernelObject::Other),_=>Err(9)}
}
"#,
    );
    program.push_str(&source[start..end]);
    program.push_str(
        r#"
fn main() {
    assert_eq!(memory_object_resize(7,0),0);assert_eq!(memory_object_resize(7,4097),0);
    assert_eq!(memory_object_resize(7,u64::MAX),status::Error::ResourceUnavailable.into_raw());
    assert_eq!(memory_object_resize(8,4097),13);assert_eq!(memory_object_resize(9,0),22);
    assert_eq!(memory_object_resize(0,0),9);assert_eq!(memory_object_resize(u64::MAX,0),9);
    assert_eq!(CALLS.with(|v|v.get()),3);
}
"#,
    );
    program.push_str("\nextern crate self as mnu_abi;\npub mod status {\n");
    program.push_str(include_str!("../../../core/crates/abi/src/status.rs"));
    program.push_str("\n}\n");
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "mochios-resize-authority-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir(&directory).unwrap();
    let executable = directory.join("probe");
    let mut compile = Command::new("rustc")
        .args(["--edition=2024", "--crate-name=resize_authority", "-", "-o"])
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

#[test]
fn native_resize_probe_matches_mechanism_abi() {
    use mnu_abi::SyscallNumber as Number;
    let source = include_str!("native_memory_object_resize.c");
    for (name, number) in [
        ("CREATE", Number::MemoryObjectCreate),
        ("LENGTH", Number::MemoryObjectLength),
        ("RESIZE", Number::MemoryObjectResize),
        ("MAP", Number::MemoryMap),
        ("UNMAP", Number::MemoryUnmap),
        ("CLOSE", Number::HandleClose),
        ("DUPLICATE", Number::HandleDuplicate),
        ("RIGHTS", Number::HandleRightsGet),
        ("IMAGE_CLONE", Number::AddressSpaceClone),
    ] {
        assert!(source.contains(&format!("{name} = {}", number as u64)));
    }
    assert_eq!(mnu_abi::MEMORY_OBJECT_RESIZABLE, 1);
    assert_eq!(mnu_abi::HANDLE_RIGHT_CONTROL, 256);
}

#[test]
fn production_ram_dirty_admission_includes_partial_last_pages_without_overflow() {
    let source = include_str!("../../../core/src/mem/vm_object.rs");
    let dirty = source.split("pub fn mark_page_dirty(").nth(1).unwrap();
    let predicate = dirty
        .split("return if ")
        .nth(1)
        .unwrap()
        .split("\n            {")
        .next()
        .unwrap();
    let program = format!(
        r#"
const PAGE_BYTES:usize=4096;
struct Memory(u64);impl Memory {{fn length(&self)->u64 {{self.0}}}}
fn permits(page_index:u64,length:u64)->bool {{let memory=Memory(length);{predicate}}}
fn main() {{
    for length in [0u64,1,4095,4096,4097,8191,8192,8193,u64::MAX] {{
        for index in [0u64,1,2,3,u64::MAX/4096,u64::MAX] {{
            let expected=(index as u128)*4096 < length as u128;
            assert_eq!(permits(index,length),expected,"index={{index}} length={{length}}");
        }}
    }}
}}
"#
    );
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "mochios-partial-dirty-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir(&directory).unwrap();
    let executable = directory.join("probe");
    let mut compile = Command::new("rustc")
        .args(["--edition=2024", "--crate-name=partial_dirty", "-", "-o"])
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
