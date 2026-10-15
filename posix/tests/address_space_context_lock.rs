use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn production_image_consume_serializes_context_walk_with_backing_revocation() {
    let source = include_str!("../../../core/src/syscall/exec.rs");
    let start = source.find("fn consume_address_space_for_create(").unwrap();
    let end = start + source[start..].find("\n}\n").unwrap() + 3;
    let mut program = String::from(
        r#"
thread_local! {
    static LOCKED:std::cell::Cell<bool>=const {std::cell::Cell::new(false)};
    static PID:std::cell::Cell<Option<u64>>=const {std::cell::Cell::new(Some(7))};
    static PRESENT:std::cell::Cell<bool>=const {std::cell::Cell::new(true)};
    static MODE:std::cell::Cell<u64>=const {std::cell::Cell::new(0)};
    static CALLS:std::cell::Cell<u64>=const {std::cell::Cell::new(0)};
}
mod syscall {
    pub mod types {pub const EACCES:u64=13;pub const EAGAIN:u64=11;pub const EFAULT:u64=14;}
    pub mod security {pub fn current_process_id()->Option<u64> {crate::PID.with(|v|v.get())}}
}
mod task {
    pub mod process {pub struct PendingExecSecurity;}
    pub fn with_process<T>(pid:u64,f:impl FnOnce(&())->T)->Option<T> {
        assert_eq!(pid,7);if !crate::PRESENT.with(|v|v.get()) {return None;}
        crate::LOCKED.with(|v|assert!(!v.replace(true)));
        let result=f(&());crate::LOCKED.with(|v|v.set(false));Some(result)
    }
}
mod mnu_abi {pub struct ThreadCreateContext;}
mod mem {pub mod address_space {
    pub enum ConsumeError {Consumed,Authorization,BackingBusy,Context}
    #[derive(Debug,PartialEq)]pub struct AddressSpaceImage;
    pub struct AddressSpaceObject;
    impl AddressSpaceObject {
        pub fn consume(&self,_:&crate::task::process::PendingExecSecurity,_:&crate::mnu_abi::ThreadCreateContext)
            ->Result<AddressSpaceImage,ConsumeError> {
            assert!(crate::LOCKED.with(|v|v.get()));
            crate::CALLS.with(|v|v.set(v.get()+1));
            match crate::MODE.with(|v|v.get()) {
                0=>Ok(AddressSpaceImage),1=>Err(ConsumeError::Consumed),
                2=>Err(ConsumeError::Authorization),4=>Err(ConsumeError::BackingBusy),_=>Err(ConsumeError::Context),
            }
        }
    }
}}
"#,
    );
    program.push_str(&source[start..end]);
    program.push_str(r#"
fn main() {
    let image=mem::address_space::AddressSpaceObject;
    let authorization=task::process::PendingExecSecurity;let context=mnu_abi::ThreadCreateContext;
    assert_eq!(consume_address_space_for_create(&image,&authorization,&context),Ok(mem::address_space::AddressSpaceImage));
    for (mode,error) in [(1,11),(2,13),(3,14),(4,11)] {
        MODE.with(|v|v.set(mode));
        assert_eq!(consume_address_space_for_create(&image,&authorization,&context),Err(error));
    }
    PRESENT.with(|v|v.set(false));
    assert_eq!(consume_address_space_for_create(&image,&authorization,&context),Err(13));
    PID.with(|v|v.set(None));
    assert_eq!(consume_address_space_for_create(&image,&authorization,&context),Err(13));
    assert_eq!(CALLS.with(|v|v.get()),5);assert!(!LOCKED.with(|v|v.get()));
}
"#);
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory =
        std::env::temp_dir().join(format!("mochios-image-lock-{}-{nonce}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let executable = directory.join("probe");
    let mut compile = Command::new("rustc")
        .args(["--edition=2024", "--crate-name=image_lock_probe", "-", "-o"])
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
fn native_creation_uses_locked_image_consumption_only() {
    let source = include_str!("../../../core/src/syscall/exec.rs");
    let creation = source
        .split("fn create_from_address_space(")
        .nth(1)
        .unwrap();
    assert!(creation.contains("consume_address_space_for_create(&image, &authorization, &context)"));
    assert!(!creation.contains("image.consume("));
    assert_eq!(source.matches("image.consume(").count(), 1);
}
