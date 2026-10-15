//! Compile the actual fault classification and interrupt resolution branch.
//! Mock only scheduling, backing resolution and exception delivery.
use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn native_retry_probe_uses_the_authoritative_native_abi() {
    let probe = include_str!("native_vm_fault_retry.c");
    for (name, number) in [
        ("MEMORY_MAP", mnu_abi::SyscallNumber::MemoryMap),
        ("MEMORY_UNMAP", mnu_abi::SyscallNumber::MemoryUnmap),
        ("HANDLE_CLOSE", mnu_abi::SyscallNumber::HandleClose),
        ("ENDPOINT_CREATE", mnu_abi::SyscallNumber::IpcCreateHandle),
        ("IPC_RECV", mnu_abi::SyscallNumber::IpcRecvObjectHandles),
        ("IPC_REPLY", mnu_abi::SyscallNumber::IpcReplyObjectHandles),
        (
            "PROVIDER_CREATE",
            mnu_abi::SyscallNumber::ProviderObjectCreate,
        ),
    ] {
        assert!(probe.contains(&format!("{name} = {}", number as u64)));
    }
    assert_eq!(mnu_abi::provider::REQUEST_HEADER_LEN, 48);
    assert_eq!(mnu_abi::provider::RESPONSE_HEADER_LEN, 40);
    assert_eq!(mnu_abi::provider::OP_MEMORY_OBJECT, 9);
    assert_eq!(mnu_abi::provider::OP_READ_AT, 6);
    assert_eq!(mnu_abi::provider::OP_RELEASE, 4);
}

#[test]
fn transient_vm_faults_yield_without_exception_or_register_changes() {
    let process = include_str!("../../../core/src/syscall/process.rs");
    let start = process.find("pub(crate) enum MemoryFault {").unwrap();
    let end = process.find("/// Resolves one page,").unwrap();
    let faults = &process[start..end];
    let idt = include_str!("../../../core/src/interrupt/idt.rs");
    let start = idt
        .find("    let mut fault_cause = mnu_abi::MemoryFaultCause::Unresolved;")
        .unwrap();
    let end = start + idt[start..].find("    error!(").unwrap();
    let handler = &idt[start..end];
    let mut program = String::from(
        r#"
use std::cell::Cell;
mod mnu_abi {
    #[derive(Clone,Copy,Debug,PartialEq,Eq)]
    pub enum MemoryFaultCause {Unmapped,AccessDenied,OutsideBacking,ResourceUnavailable,BackingFailure,Unresolved}
}
mod mem {pub mod vm_object {
    #[derive(Clone,Copy,Debug,PartialEq,Eq)] pub enum VmPageError {OutsideBacking,Operation(u64)}
}}
mod syscall {
    pub const EAGAIN:u64=(-11i64) as u64; pub const ENOMEM:u64=(-12i64) as u64;
    pub mod process {
        use crate::{mnu_abi,syscall::{EAGAIN,ENOMEM}};
        #[derive(Clone,Copy,Debug,PartialEq,Eq)]
"#,
    );
    program.push_str(faults);
    program.push_str(r#"
        pub(crate) fn handle_user_memory_fault(address:u64, write:bool, execute:bool)->Result<(),MemoryFault> {
            assert_eq!(address,0x5000); assert!(write); assert!(!execute);
            crate::RESOLVES.with(|count|count.set(count.get()+1));
            crate::OUTCOME.with(Cell::get)
        }
        use std::cell::Cell;
    }
    pub fn prepare_user_exception(registers:&mut [u64;21], address:u64, cause:crate::mnu_abi::MemoryFaultCause)->bool {
        assert_eq!(address,0x5000); registers[0]=0xdead;
        crate::DELIVERED.with(|slot|slot.set(Some(cause))); true
    }
}
mod task {pub fn yield_now() {crate::YIELDS.with(|count|count.set(count.get()+1));}}
#[derive(Clone,Copy)] struct Address(u64);
impl Address {fn as_u64(self)->u64 {self.0}}
mod x86_64 {pub mod structures {pub mod idt {
    #[derive(Clone,Copy)] pub struct PageFaultErrorCode(pub u64);
    impl PageFaultErrorCode {
        pub const PROTECTION_VIOLATION:Self=Self(1);
        pub const CAUSED_BY_WRITE:Self=Self(2);
        pub const INSTRUCTION_FETCH:Self=Self(4);
        pub fn contains(self, other:Self)->bool {self.0&other.0!=0}
    }
}}}
use syscall::process::MemoryFault as Fault;
use mem::vm_object::VmPageError as Backing;
use mnu_abi::MemoryFaultCause as Cause;
thread_local! {
    static OUTCOME:Cell<Result<(),Fault>>=const {Cell::new(Ok(()))};
    static YIELDS:Cell<usize>=const {Cell::new(0)};
    static LEAVES:Cell<usize>=const {Cell::new(0)};
    static FATAL:Cell<usize>=const {Cell::new(0)};
    static RESOLVES:Cell<usize>=const {Cell::new(0)};
    static GROWS:Cell<usize>=const {Cell::new(0)};
    static DELIVERED:Cell<Option<Cause>>=const {Cell::new(None)};
}
fn leave_to_user(entered:bool) {assert!(entered); LEAVES.with(|count|count.set(count.get()+1));}
fn try_grow_user_stack(address:u64)->bool {assert_eq!(address,0x5000); GROWS.with(|count|count.set(count.get()+1)); false}
fn actual_handler(registers:&mut [u64;21], is_user_mode:bool, copy_on_write_failed:bool) {
    let faulting_addr=Address(0x5000);
    let error_code=x86_64::structures::idt::PageFaultErrorCode(3);
    let entered_from_user=is_user_mode;
"#);
    program.push_str(handler);
    program.push_str(r#"
    FATAL.with(|count|count.set(count.get()+1));
}
fn run(outcome:Result<(),Fault>, expected_yields:usize, expected_cause:Option<Cause>) {
    OUTCOME.with(|slot|slot.set(outcome));
    YIELDS.with(|slot|slot.set(0)); LEAVES.with(|slot|slot.set(0));
    FATAL.with(|slot|slot.set(0)); RESOLVES.with(|slot|slot.set(0));
    GROWS.with(|slot|slot.set(0)); DELIVERED.with(|slot|slot.set(None));
    let mut registers=core::array::from_fn::<_,21,_>(|index|0x100+index as u64);
    let original=registers;
    actual_handler(&mut registers,true,false);
    assert_eq!(YIELDS.with(Cell::get),expected_yields);
    assert_eq!(DELIVERED.with(Cell::get),expected_cause);
    assert_eq!(LEAVES.with(Cell::get),1); assert_eq!(FATAL.with(Cell::get),0);
    assert_eq!(RESOLVES.with(Cell::get),1); assert_eq!(GROWS.with(Cell::get),0);
    if expected_cause.is_none() {assert_eq!(registers,original);}
}
fn main() {
    run(Ok(()),0,None);
    for fault in [Fault::Operation(syscall::EAGAIN),Fault::Backing(Backing::Operation(syscall::EAGAIN))] {
        assert!(fault.is_retryable()); run(Err(fault),1,None);
    }
    for (fault,cause) in [
        (Fault::Unmapped,Cause::Unmapped), (Fault::AccessDenied,Cause::AccessDenied),
        (Fault::Backing(Backing::OutsideBacking),Cause::OutsideBacking),
        (Fault::Operation(syscall::ENOMEM),Cause::ResourceUnavailable),
        (Fault::Backing(Backing::Operation(syscall::ENOMEM)),Cause::ResourceUnavailable),
        (Fault::Backing(Backing::Operation((-5i64) as u64)),Cause::BackingFailure),
        (Fault::Operation((-22i64) as u64),Cause::Unresolved),
    ] {assert!(!fault.is_retryable());run(Err(fault),0,Some(cause));}
    OUTCOME.with(|slot|slot.set(Err(Fault::Operation(syscall::EAGAIN))));
    YIELDS.with(|slot|slot.set(0)); LEAVES.with(|slot|slot.set(0));
    FATAL.with(|slot|slot.set(0)); RESOLVES.with(|slot|slot.set(0));
    let mut registers=[0x77;21];
    actual_handler(&mut registers,false,false);
    assert_eq!(FATAL.with(Cell::get),1); assert_eq!(YIELDS.with(Cell::get),0);
    assert_eq!(RESOLVES.with(Cell::get),0); assert_eq!(LEAVES.with(Cell::get),0);
    assert_eq!(registers,[0x77;21]);
}
"#);
    let directory = std::env::temp_dir().join(format!(
        "mochios-vm-retry-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    let binary = directory.join("probe");
    let mut compiler = Command::new("rustc")
        .args(["--edition=2024", "-Awarnings", "-"])
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
    let result = compiler.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let result = Command::new(&binary).output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    std::fs::remove_dir_all(directory).unwrap();
}
