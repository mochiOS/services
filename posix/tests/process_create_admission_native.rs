//! Execute real request copying, decoding and admission. Later creation is a
//! counted backend; this test neither simulates SHA correctness nor a scheduler.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn admission_preserves_authorization_order_and_native_failure_provenance() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let mut program = String::from("#![allow(dead_code,unused_attributes)]\nextern crate alloc;\n");
    program.push_str(&format!(
        "extern crate self as mnu_abi;\n#[path={:?}]mod abi;\npub use abi::*;\n",
        root.join("core/crates/abi/src/lib.rs")
    ));
    program.push_str(
        r#"
use std::{cell::{Cell,RefCell},sync::atomic::{AtomicUsize,Ordering}};
use mnu_abi::status::Error;
use mnu_abi::exec::ExecutionClass;
mod kernel {
    pub fn early_serial(text:&str) {
        assert_eq!(text,"ProcessCreate: image snapshot failed\n");
    }
}
static ALLOCATIONS:AtomicUsize=AtomicUsize::new(0);
thread_local! {
    static FAIL_AFTER:Cell<Option<usize>>=const {Cell::new(None)};
    static CAPABLE:Cell<bool>=const {Cell::new(true)};
    static OWNER:Cell<Option<u64>>=const {Cell::new(Some(19))};
    static THREAD:Cell<Option<u64>>=const {Cell::new(Some(23))};
    static PRESENT:Cell<bool>=const {Cell::new(true)};
    static COPY_ERROR:Cell<Option<Error>>=const {Cell::new(None)};
    static EXPORT_ERROR:Cell<Option<Error>>=const {Cell::new(None)};
    static BYTES:RefCell<Vec<u8>>=const {RefCell::new(Vec::new())};
    static COPIES:Cell<usize>=const {Cell::new(0)};
    static TAKES:Cell<usize>=const {Cell::new(0)};
    static EXPORTS:Cell<usize>=const {Cell::new(0)};
    static CREATES:Cell<usize>=const {Cell::new(0)};
    static PROCESS:RefCell<task::Process>=const {RefCell::new(task::Process{authorization:None})};
}
struct Allocator;
unsafe impl std::alloc::GlobalAlloc for Allocator {
    unsafe fn alloc(&self,layout:std::alloc::Layout)->*mut u8 {
        if FAIL_AFTER.with(|s|match s.get(){Some(0)=>{s.set(None);true},Some(n)=>{s.set(Some(n-1));false},None=>false}) {return std::ptr::null_mut();}
        let pointer=unsafe {std::alloc::System.alloc(layout)};
        if !pointer.is_null(){ALLOCATIONS.fetch_add(1,Ordering::Relaxed);}pointer
    }
    unsafe fn dealloc(&self,p:*mut u8,layout:std::alloc::Layout) {
        ALLOCATIONS.fetch_sub(1,Ordering::Relaxed);unsafe {std::alloc::System.dealloc(p,layout)}
    }
}
#[global_allocator]static ALLOCATOR:Allocator=Allocator;
mod task {
    pub mod process {
        #[derive(PartialEq)]pub enum PendingExecKind {Spawn,ImageReplace}
        pub struct PendingExecSecurity {
            pub kind:PendingExecKind,pub executable_digest:[u8;32],pub execution_class:crate::ExecutionClass,
            pub capabilities:(),pub kernel_authorities:(),pub identity:(),
        }
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
    pub enum PrivilegeLevel {Service,User}
    #[derive(Clone,Debug)]pub struct ObjectHandleEntry;
"#,
    );
    program.push_str(probe::between(
        include_str!("../../../core/src/task/handle_table.rs"),
        "#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]",
        "/// Kernel object identity",
    ));
    program.push_str(
        r#"
}
mod syscall {
    pub mod security {pub fn current_process_id()->Option<u64> {crate::OWNER.get()}}
    pub fn copy_from_user_native(pointer:u64,bytes:&mut [u8])->Result<(),crate::Error> {
        assert_eq!(pointer,42);crate::COPIES.set(crate::COPIES.get()+1);
        if let Some(error)=crate::COPY_ERROR.get(){return Err(error);}
        crate::BYTES.with_borrow(|source|bytes.copy_from_slice(source));Ok(())
    }
    pub fn copy_from_user(pointer:u64,bytes:&mut [u8])->Result<(),u64> {
        copy_from_user_native(pointer,bytes).map_err(crate::Error::into_raw)
    }
    pub mod handle {pub fn read_all(_:u64,_:usize)->Result<Vec<u8>,u64> {panic!("not a VM request")}}
}
"#,
    );
    program.push_str(&format!(
        "mod util {{#[path={:?}]pub mod object_snapshot;}}\n#[path={:?}]mod storage;\n",
        root.join("core/src/util/object_snapshot.rs"),
        root.join("core/src/syscall/exec/storage.rs")
    ));
    let exec = include_str!("../../../core/src/syscall/exec.rs");
    program.push_str(probe::between(
        exec,
        "#[derive(Clone, Copy, Debug, PartialEq, Eq)]\nstruct InheritedHandleSpec",
        "struct InitialUserStack",
    ));
    program.push_str(
        r#"
fn caller_has_process_spawn_capability()->bool {CAPABLE.get()}
fn export_inherited_handles(owner:Option<u64>,specs:&[InheritedHandleSpec])->Result<Vec<InheritedHandleGrant>,Error> {
    assert_eq!(owner,Some(19));assert_eq!(specs.len(),1);assert_eq!(specs[0].source.raw(),7);
    EXPORTS.set(EXPORTS.get()+1);EXPORT_ERROR.get().map_or(Ok(Vec::new()),Err)
}
mod captured_handles {pub fn export(_:u64,_:&[crate::InheritedHandleSpec])->Result<Vec<crate::InheritedHandleGrant>,crate::Error> {panic!("live-table plan")}}
fn create_from_address_space(image:u64,request:&mnu_abi::process_create::Request<'_>,context:mnu_abi::ThreadCreateContext,
    _:task::process::PendingExecSecurity,grants:&[InheritedHandleGrant],values:&[InheritedValueSpec])->u64 {
    assert_eq!(image,9);assert_eq!(request.identity,"authorized");assert_eq!(request.label,"label");
    assert_eq!((context.entry,context.stack_pointer),(0x1000,0x2000));assert!(grants.is_empty());
    assert_eq!(values.len(),1);assert_eq!(values[0].value,u64::MAX);
    CREATES.set(CREATES.get()+1);991
}
struct Sha256;impl Sha256 {fn digest(_:&[u8])->[u8;32] {panic!("VM request has no ELF digest step")}}
enum ImageLaunch<'a>{Created(mnu_abi::process_image::StartupImage<'a>)}
struct ExecMeasurement;impl ExecMeasurement {fn start()->Self {Self}fn finish(self,result:u64)->u64 {result}}
fn exec_with_data(_:&[u8],_:&str,_:&str,_:Option<()>,_:Option<()>,_:Option<task::PrivilegeLevel>,_:Option<()>,_:&[InheritedHandleGrant],_:&[InheritedValueSpec],_:ImageLaunch<'_>,_:&mut ExecMeasurement)->u64 {panic!("not an ELF request")}
"#,
    );
    program.push_str(probe::between(
        exec,
        "pub fn process_create_syscall(",
        "fn consume_address_space_for_create(",
    ));
    program.push_str(
        r#"
fn reset()->usize {
    FAIL_AFTER.set(None);CAPABLE.set(true);OWNER.set(Some(19));THREAD.set(Some(23));PRESENT.set(true);
    COPY_ERROR.set(None);EXPORT_ERROR.set(None);COPIES.set(0);TAKES.set(0);EXPORTS.set(0);CREATES.set(0);
    PROCESS.with_borrow_mut(|p|p.authorization=Some(task::process::PendingExecSecurity{
        kind:task::process::PendingExecKind::Spawn,executable_digest:[0;32],execution_class:ExecutionClass::Unprivileged,
        capabilities:(),kernel_authorities:(),identity:(),
    }));
    let mut bytes=[0u8;1024];let context=mnu_abi::ThreadCreateContext{entry:0x1000,stack_pointer:0x2000,..Default::default()};
    let length=mnu_abi::process_create::encode_context("authorized","label",&context,
        &[mnu_abi::process_create::HandleGrant{key:5,source:7,target:0,rights:1}],
        &[mnu_abi::process_create::Value{key:6,value:u64::MAX}],&mut bytes).unwrap();
    BYTES.with_borrow_mut(|storage|*storage=bytes[..length].to_vec());length
}
fn check(length:usize,expected:u64) {
    let allocations=ALLOCATIONS.load(Ordering::Relaxed);
    assert_eq!(process_create_syscall(9,42,length as u64),expected);
    assert_eq!(ALLOCATIONS.load(Ordering::Relaxed),allocations,"failed preparation must free its owned input and vectors");
}
fn authorized()->bool {PROCESS.with_borrow(|p|p.authorization.is_some())}
fn main() {
    let length=reset();CAPABLE.set(false);check(length,Error::AccessDenied.into_raw());
    assert_eq!(COPIES.get(),0);assert_eq!(TAKES.get(),0);assert!(authorized());
    for invalid in [0,mnu_abi::process_create::MAX_REQUEST_BYTES+1,usize::MAX] {
        reset();check(invalid,Error::InvalidArgument.into_raw());assert_eq!(COPIES.get(),0);assert!(authorized());
    }
    let length=reset();BYTES.with_borrow_mut(|bytes|bytes[0]=0);
    check(length,Error::InvalidArgument.into_raw());assert_eq!(TAKES.get(),0);assert!(authorized());
    for error in [Error::InvalidAddress,Error::ResourceUnavailable,Error::BackingFailure] {
        let length=reset();COPY_ERROR.set(Some(error));check(length,error.into_raw());assert_eq!(TAKES.get(),0);assert!(authorized());
    }
    for mode in 0..3 {
        let length=reset();match mode {0=>OWNER.set(None),1=>THREAD.set(None),_=>PRESENT.set(false)};
        check(length,Error::NotReady.into_raw());assert_eq!(TAKES.get(),0);assert!(authorized());
    }
    let length=reset();PROCESS.with_borrow_mut(|p|p.authorization=None);
    check(length,Error::AccessDenied.into_raw());assert_eq!(TAKES.get(),1);assert_eq!(EXPORTS.get(),0);
    let length=reset();BYTES.with_borrow_mut(|bytes|bytes[mnu_abi::process_create::HEADER_LEN]=b'x');
    check(length,Error::AccessDenied.into_raw());assert!(authorized());assert_eq!(EXPORTS.get(),0);
    let length=reset();PROCESS.with_borrow_mut(|p|p.authorization.as_mut().unwrap().kind=task::process::PendingExecKind::ImageReplace);
    check(length,Error::AccessDenied.into_raw());assert!(!authorized());assert_eq!(EXPORTS.get(),0);
    let length=reset();BYTES.with_borrow_mut(|bytes| {
        let offset=bytes.len()-mnu_abi::process_create::VALUE_LEN-mnu_abi::process_create::HANDLE_LEN+16;
        bytes[offset..offset+8].copy_from_slice(&u64::MAX.to_le_bytes());
    });
    check(length,Error::InvalidArgument.into_raw());assert!(!authorized());assert_eq!(EXPORTS.get(),0);
    // The request, Handle spec and value arrays are the three allocations.
    for allocation in 0..3 {
        let length=reset();FAIL_AFTER.set(Some(allocation));check(length,Error::ResourceUnavailable.into_raw());
        assert_eq!(FAIL_AFTER.get(),None);assert_eq!(authorized(),allocation==0);assert_eq!(CREATES.get(),0);
        assert_eq!(TAKES.get(),usize::from(allocation!=0));
    }
    for error in [Error::AccessDenied,Error::InvalidArgument,Error::NotReady,Error::ResourceUnavailable] {
        let length=reset();EXPORT_ERROR.set(Some(error));check(length,error.into_raw());
        assert!(!authorized());assert_eq!(CREATES.get(),0);
    }
    let length=reset();check(length,991);assert!(!authorized());assert_eq!(CREATES.get(),1);
    check(length,Error::AccessDenied.into_raw());assert_eq!(CREATES.get(),1,"an authorization cannot be replayed");
}
"#,
    );
    probe::run(&program);
}
