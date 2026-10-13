use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn production_fault_translation_retains_root_and_rejects_stale_identity() {
    let source = include_str!("../../../core/src/interrupt/idt.rs");
    let start = source.find("fn translate_current_user_fault(").unwrap();
    let end = start + source[start..].find("\n}\n").unwrap() + 3;
    let function = &source[start..end];
    let mut program = String::from(
        r#"
thread_local! {
    static PID:std::cell::Cell<Option<u64>>=const {std::cell::Cell::new(Some(7))};
    static ROOT:std::cell::Cell<Option<u64>>=const {std::cell::Cell::new(Some(4096))};
    static PRESENT:std::cell::Cell<bool>=const {std::cell::Cell::new(true)};
    static LOCKED:std::cell::Cell<bool>=const {std::cell::Cell::new(false)};
    static CALLS:std::cell::Cell<u64>=const {std::cell::Cell::new(0)};
}
mod syscall {pub mod security {pub fn current_process_id()->Option<u64> {crate::PID.with(|v|v.get())}}}
mod task {
    pub struct Process;
    impl Process {pub fn page_table(&self)->Option<u64> {
        assert!(crate::LOCKED.with(|v|v.get()));crate::ROOT.with(|v|v.get())
    }}
    pub fn with_process<T>(pid:u64,f:impl FnOnce(&Process)->T)->Option<T> {
        assert_eq!(pid,7);if !crate::PRESENT.with(|v|v.get()) {return None;}
        crate::LOCKED.with(|v|assert!(!v.replace(true)));
        let result=f(&Process);crate::LOCKED.with(|v|v.set(false));Some(result)
    }
}
mod mem {pub mod paging {
    pub fn virt_to_phys_in_table(root:u64,address:u64)->Option<u64> {
        assert!(crate::LOCKED.with(|v|v.get()));
        assert_eq!(crate::ROOT.with(|v|v.get()),Some(root));
        crate::CALLS.with(|v|v.set(v.get()+1));
        if address==8192 {Some(0x12345000)} else {None}
    }
}}
"#,
    );
    program.push_str(function);
    program.push_str(
        r#"
fn main() {
    assert_eq!(translate_current_user_fault(4096,8192),Some(0x12345000));
    assert_eq!(translate_current_user_fault(4096,0),None);
    assert_eq!(translate_current_user_fault(12288,8192),None);
    ROOT.with(|v|v.set(None));assert_eq!(translate_current_user_fault(4096,8192),None);
    PRESENT.with(|v|v.set(false));assert_eq!(translate_current_user_fault(4096,8192),None);
    PID.with(|v|v.set(None));assert_eq!(translate_current_user_fault(4096,8192),None);
    assert_eq!(CALLS.with(|v|v.get()),2);assert!(!LOCKED.with(|v|v.get()));
}
"#,
    );
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory =
        std::env::temp_dir().join(format!("mochios-fault-root-{}-{nonce}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let executable = directory.join("probe");
    let mut compile = Command::new("rustc")
        .args(["--edition=2024", "--crate-name=fault_root_probe", "-", "-o"])
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
fn user_fault_paths_do_not_walk_active_kernel_cr3_after_entering_kpti() {
    let source = include_str!("../../../core/src/interrupt/idt.rs");
    let protection = source
        .split("fn general_protection_fault_handler(")
        .nth(1)
        .unwrap()
        .split("fn translate_current_user_fault(")
        .next()
        .unwrap();
    assert!(!protection.contains("dump_invalid_opcode_diagnostics"));
    let fault = source
        .split("fn page_fault_handler(")
        .nth(1)
        .unwrap()
        .split("fn try_grow_user_stack(")
        .next()
        .unwrap();
    assert!(fault.contains("translate_current_user_fault(table, faulting_addr.as_u64())"));
    assert!(!fault.contains("virt_to_phys_in_table"));
}
