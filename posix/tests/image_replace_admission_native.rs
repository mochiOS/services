//! Execute real copy, wire decode and admission, stopping at a failed image
//! preparation backend. This is not a scheduler, SHA or usermode-entry test.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn replacement_admission_preserves_native_errors_and_one_shot_authorization() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let mut program = String::from("#![allow(dead_code,unused_attributes)]\nextern crate alloc;\n");
    program.push_str(&format!(
        "extern crate self as mnu_abi;\n#[path={:?}]mod abi;\npub use abi::*;\nmod util {{#[path={:?}]pub mod object_snapshot;}}\n#[path={:?}]mod storage;\n",
        root.join("core/crates/abi/src/lib.rs"),
        root.join("core/src/util/object_snapshot.rs"),
        root.join("core/src/syscall/exec/storage.rs")
    ));
    program.push_str(
        r#"
use std::{cell::{Cell,RefCell},sync::atomic::{AtomicUsize,Ordering}};
use mnu_abi::{status::Error,exec::ExecutionClass};
thread_local! {
    static FAIL_AFTER:Cell<Option<usize>>=const {Cell::new(None)};
    static CAPABLE:Cell<bool>=const {Cell::new(true)};
    static OWNER:Cell<Option<u64>>=const {Cell::new(Some(19))};
    static THREAD:Cell<Option<u64>>=const {Cell::new(Some(23))};
    static PRESENT:Cell<bool>=const {Cell::new(true)};
    static COPY_ERROR:Cell<Option<(u64,Error)>>=const {Cell::new(None)};
    static READ_ERROR:Cell<Option<u64>>=const {Cell::new(None)};
    static REPLACE_ERROR:Cell<u64>=const {Cell::new(Error::BackingFailure.into_raw())};
    static IDENTITY:RefCell<Vec<u8>>=const {RefCell::new(Vec::new())};
    static STARTUP:RefCell<Vec<u8>>=const {RefCell::new(Vec::new())};
    static COPIES:Cell<usize>=const {Cell::new(0)};
    static TAKES:Cell<usize>=const {Cell::new(0)};
    static READS:Cell<usize>=const {Cell::new(0)};
    static REPLACES:Cell<usize>=const {Cell::new(0)};
    static PROCESS:RefCell<task::Process>=const {RefCell::new(task::Process{authorization:None})};
}
static ALLOCATIONS:AtomicUsize=AtomicUsize::new(0);
struct Allocator;
unsafe impl std::alloc::GlobalAlloc for Allocator {
    unsafe fn alloc(&self,layout:std::alloc::Layout)->*mut u8 {
        if FAIL_AFTER.with(|s|match s.get(){Some(0)=>{s.set(None);true},Some(n)=>{s.set(Some(n-1));false},None=>false}) {return std::ptr::null_mut();}
        let p=unsafe {std::alloc::System.alloc(layout)};
        if !p.is_null(){ALLOCATIONS.fetch_add(1,Ordering::Relaxed);}p
    }
    unsafe fn dealloc(&self,p:*mut u8,layout:std::alloc::Layout) {
        ALLOCATIONS.fetch_sub(1,Ordering::Relaxed);unsafe {std::alloc::System.dealloc(p,layout)}
    }
}
#[global_allocator]static ALLOCATOR:Allocator=Allocator;
mod task {
    pub mod process {
        #[derive(PartialEq)]pub enum PendingExecKind {Spawn,ImageReplace}
        pub struct PendingExecSecurity {pub kind:PendingExecKind,pub execution_class:crate::ExecutionClass,pub executable_digest:[u8;32]}
    }
    pub struct Process {pub authorization:Option<process::PendingExecSecurity>}
    impl Process {
        pub fn take_exec_authorization(&mut self,identity:&str,thread:u64)->Option<process::PendingExecSecurity> {
            crate::TAKES.set(crate::TAKES.get()+1);assert_eq!(thread,23);
            if identity!="authorized" {return None;}self.authorization.take()
        }
    }
    pub fn current_thread_id()->Option<u64> {crate::THREAD.get()}
    pub fn with_process_mut<T>(owner:u64,body:impl FnOnce(&mut Process)->T)->Option<T> {
        assert_eq!(owner,19);if !crate::PRESENT.get(){return None;}Some(crate::PROCESS.with_borrow_mut(body))
    }
    pub unsafe fn jump_to_usermode(_:u64,_:u64,_:u64)->! {panic!("must not reach usermode")}
}
mod syscall {
    pub mod security {pub fn current_process_id()->Option<u64> {crate::OWNER.get()}}
    pub fn copy_from_user_native(pointer:u64,bytes:&mut [u8])->Result<(),crate::Error> {
        crate::COPIES.set(crate::COPIES.get()+1);
        if let Some((fault,error))=crate::COPY_ERROR.get(){if fault==pointer {return Err(error);}}
        match pointer {41=>crate::IDENTITY.with_borrow(|s|bytes.copy_from_slice(s)),42=>crate::STARTUP.with_borrow(|s|bytes.copy_from_slice(s)),_=>panic!("unexpected pointer")};Ok(())
    }
    pub fn copy_from_user(_:u64,_:&mut [u8])->Result<(),u64> {panic!("must use native usercopy")}
    pub mod handle {pub fn read_all(image:u64,maximum:usize)->Result<Vec<u8>,u64> {
        assert_eq!(image,9);assert_eq!(maximum,mnu_abi::exec::MAX_CAPTURED_IMAGE_BYTES);crate::READS.set(crate::READS.get()+1);
        if let Some(error)=crate::READ_ERROR.get(){Err(error)}else{Ok(Vec::new())}
    }}
}
mod x86_64 {pub mod instructions {pub mod interrupts {pub fn disable(){panic!("failed preparation must not change interrupt state")}}}}
mod mem {pub mod paging {pub unsafe fn switch_page_table(_:u64){panic!("must not commit")}}}
fn caller_has_process_spawn_capability()->bool {CAPABLE.get()}
struct Sha256;impl Sha256 {fn digest(bytes:&[u8])->[u8;32] {assert!(bytes.is_empty());[7;32]}}
struct ExecMeasurement;impl ExecMeasurement {fn start()->Self {Self}}
fn replace_current_process_image(bytes:&[u8],identity:&str,authorization:task::process::PendingExecSecurity,startup:mnu_abi::process_image::StartupImage<'_>,ceiling:u64,_:ExecMeasurement)->Result<(u64,u64,u64),u64> {
    assert!(bytes.is_empty());assert_eq!(identity,"authorized");assert_eq!(authorization.executable_digest,[7;32]);
    assert_eq!(startup.stack(),[0;8]);assert_eq!(ceiling,12345);REPLACES.set(REPLACES.get()+1);Err(REPLACE_ERROR.get())
}
"#,
    );
    program.push_str(probe::between(
        include_str!("../../../core/src/syscall/exec.rs"),
        "fn process_image_replace_impl(",
        "/// Creates a stopped process",
    ));
    program.push_str(
        r#"
fn reset()->(u64,u64) {
    FAIL_AFTER.set(None);CAPABLE.set(true);OWNER.set(Some(19));THREAD.set(Some(23));PRESENT.set(true);
    COPY_ERROR.set(None);READ_ERROR.set(None);REPLACE_ERROR.set(Error::BackingFailure.into_raw());
    COPIES.set(0);TAKES.set(0);READS.set(0);REPLACES.set(0);
    PROCESS.with_borrow_mut(|p|p.authorization=Some(task::process::PendingExecSecurity{
        kind:task::process::PendingExecKind::ImageReplace,execution_class:ExecutionClass::Unprivileged,executable_digest:[7;32]
    }));
    IDENTITY.with_borrow_mut(|s|*s=b"authorized".to_vec());
    let mut bytes=[0;128];let length=mnu_abi::process_image::encode(0,&[0;8],&[],&mut bytes).unwrap();
    STARTUP.with_borrow_mut(|s|*s=bytes[..length].to_vec());(10,length as u64)
}
fn authorized()->bool {PROCESS.with_borrow(|p|p.authorization.is_some())}
fn check(lengths:(u64,u64),expected:u64) {
    let allocations=ALLOCATIONS.load(Ordering::Relaxed);
    assert_eq!(process_image_replace_impl(9,41,lengths.0,42,lengths.1,12345),expected);
    assert_eq!(ALLOCATIONS.load(Ordering::Relaxed),allocations,"failed replacement must release both owned inputs");
}
fn main() {
    let lengths=reset();CAPABLE.set(false);check(lengths,Error::AccessDenied.into_raw());assert_eq!(COPIES.get(),0);assert!(authorized());
    for lengths in [(0,40),(257,40),(10,0),(10,mnu_abi::process_image::MAX_IMAGE_BYTES as u64+1),(u64::MAX,40),(10,u64::MAX)] {
        reset();check(lengths,Error::InvalidArgument.into_raw());assert_eq!(COPIES.get(),0);assert_eq!(TAKES.get(),0);assert!(authorized());
    }
    for invalid in [0,0xff] {
        let lengths=reset();IDENTITY.with_borrow_mut(|s|s[0]=invalid);
        check(lengths,Error::InvalidArgument.into_raw());assert_eq!(COPIES.get(),1);assert_eq!(TAKES.get(),0);assert!(authorized());
    }
    let lengths=reset();STARTUP.with_borrow_mut(|s|s[0]=0);check(lengths,Error::InvalidArgument.into_raw());assert_eq!(TAKES.get(),0);assert!(authorized());
    for pointer in [41,42] {for error in [Error::InvalidAddress,Error::ResourceUnavailable,Error::BackingFailure] {
        let lengths=reset();COPY_ERROR.set(Some((pointer,error)));check(lengths,error.into_raw());assert_eq!(TAKES.get(),0);assert!(authorized());
    }}
    for allocation in 0..2 {
        let lengths=reset();FAIL_AFTER.set(Some(allocation));check(lengths,Error::ResourceUnavailable.into_raw());
        assert_eq!(FAIL_AFTER.get(),None);assert_eq!(TAKES.get(),0);assert!(authorized());
    }
    for missing in 0..3 {
        let lengths=reset();match missing {0=>OWNER.set(None),1=>THREAD.set(None),_=>PRESENT.set(false)};
        check(lengths,Error::NotReady.into_raw());assert_eq!(TAKES.get(),0);assert!(authorized());
    }
    let lengths=reset();IDENTITY.with_borrow_mut(|s|s[0]=b'x');check(lengths,Error::AccessDenied.into_raw());assert!(authorized());assert_eq!(READS.get(),0);
    for rejected in 0..3 {
        let lengths=reset();PROCESS.with_borrow_mut(|p|match rejected {0=>p.authorization=None,1=>p.authorization.as_mut().unwrap().kind=task::process::PendingExecKind::Spawn,_=>p.authorization.as_mut().unwrap().execution_class=ExecutionClass::Privileged});
        check(lengths,Error::AccessDenied.into_raw());assert!(!authorized());assert_eq!(READS.get(),0);
    }
    for error in [Error::InvalidArgument.into_raw(),Error::BackingFailure.into_raw(),(-5i64) as u64] {
        let lengths=reset();READ_ERROR.set(Some(error));check(lengths,error);assert!(!authorized());assert_eq!(REPLACES.get(),0);
    }
    let lengths=reset();PROCESS.with_borrow_mut(|p|p.authorization.as_mut().unwrap().executable_digest=[8;32]);
    check(lengths,Error::AccessDenied.into_raw());assert!(!authorized());assert_eq!(REPLACES.get(),0);
    for error in [Error::NotReady.into_raw(),Error::ResourceUnavailable.into_raw(),(-12i64) as u64] {
        let lengths=reset();REPLACE_ERROR.set(error);check(lengths,error);assert!(!authorized());assert_eq!(REPLACES.get(),1);
        check(lengths,Error::AccessDenied.into_raw());assert_eq!(REPLACES.get(),1,"consumed authorization cannot be replayed");
    }
}
"#,
    );
    probe::run(&program);
}
