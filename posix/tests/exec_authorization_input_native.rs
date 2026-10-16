//! Real authorization input readers, storage and allocation failure handling.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn authorization_inputs_preserve_bounds_native_usercopy_and_fallible_ownership() {
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
use status::Error;
thread_local! {
    static FAIL_AFTER:Cell<Option<usize>>=const {Cell::new(None)};
    static CALLS:Cell<usize>=const {Cell::new(0)};
    static COPIES:Cell<usize>=const {Cell::new(0)};
    static COPY_ERROR:Cell<Option<Error>>=const {Cell::new(None)};
    static BYTES:RefCell<Vec<u8>>=const {RefCell::new(Vec::new())};
}
static LIVE:AtomicUsize=AtomicUsize::new(0);
struct Allocator;
unsafe impl std::alloc::GlobalAlloc for Allocator {
    unsafe fn alloc(&self,layout:std::alloc::Layout)->*mut u8 {
        CALLS.set(CALLS.get()+1);
        if FAIL_AFTER.with(|s|match s.get(){Some(0)=>{s.set(None);true},Some(n)=>{s.set(Some(n-1));false},None=>false}) {return std::ptr::null_mut();}
        let p=unsafe{std::alloc::System.alloc(layout)};if !p.is_null(){LIVE.fetch_add(1,Ordering::Relaxed);}p
    }
    unsafe fn dealloc(&self,p:*mut u8,layout:std::alloc::Layout){LIVE.fetch_sub(1,Ordering::Relaxed);unsafe{std::alloc::System.dealloc(p,layout)}}
}
#[global_allocator]static ALLOCATOR:Allocator=Allocator;
mod syscall {
    pub fn copy_from_user_native(pointer:u64,output:&mut [u8])->Result<(),crate::Error> {
        assert_eq!(pointer,42);crate::COPIES.set(crate::COPIES.get()+1);
        if let Some(error)=crate::COPY_ERROR.get(){return Err(error);}
        crate::BYTES.with_borrow(|bytes|output.copy_from_slice(bytes));Ok(())
    }
}
"#,
    );
    program.push_str(probe::between(
        include_str!("../../../core/src/syscall/exec.rs"),
        "fn read_nul_identity_fields(",
        "fn caller_has_process_spawn_capability(",
    ));
    program.push_str(
        r#"
fn input(bytes:&[u8])->usize {
    FAIL_AFTER.set(None);COPY_ERROR.set(None);COPIES.set(0);BYTES.with_borrow_mut(|s|*s=bytes.to_vec());bytes.len()
}
fn read(identity:bool,length:usize)->Result<Vec<String>,Error> {
    if identity {read_nul_identity_fields(42,length,7)}else{read_nul_caps_from_user(42,length as u64)}
}
fn error(identity:bool,length:usize,expected:Error) {
    let live=LIVE.load(Ordering::Relaxed);assert_eq!(read(identity,length),Err(expected));
    assert_eq!(LIVE.load(Ordering::Relaxed),live,"failed decoding must release partial strings, vector and request buffer");
}
fn main(){
    for identity in [false,true] {
        let length=input(b"one\0two\0three\0four\0five\0");CALLS.set(0);
        let result=read(identity,length).unwrap();let allocations=CALLS.get();
        assert_eq!(result,["one","two","three","four","five"]);assert!(allocations>=8);drop(result);
        for allocation in 0..allocations {
            COPIES.set(0);FAIL_AFTER.set(Some(allocation));error(identity,length,Error::ResourceUnavailable);
            assert_eq!(FAIL_AFTER.get(),None);assert_eq!(COPIES.get(),usize::from(allocation!=0));
        }
        for failure in [Error::InvalidAddress,Error::BackingFailure,Error::ResourceUnavailable] {
            COPY_ERROR.set(Some(failure));error(identity,length,failure);
        }
        let length=input(b"valid\0\xff");error(identity,length,Error::InvalidArgument);
        let length=input("名前\0two".as_bytes());assert_eq!(read(identity,length).unwrap(),["名前","two"]);
    }
    let length=input(b"first\0\0\xff");assert_eq!(read(true,length).unwrap(),["first"]);error(false,length,Error::InvalidArgument);
    let length=input(b"one\0two\0three");assert_eq!(read_nul_identity_fields(42,length,2).unwrap(),["one","two"]);
    input(b"unused");FAIL_AFTER.set(Some(0));assert!(read_nul_identity_fields(0,1024,7).unwrap().is_empty());assert_eq!(FAIL_AFTER.get(),Some(0));FAIL_AFTER.set(None);assert_eq!(COPIES.get(),0);
    FAIL_AFTER.set(Some(0));assert!(read_nul_caps_from_user(99,0).unwrap().is_empty());assert_eq!(FAIL_AFTER.get(),Some(0));FAIL_AFTER.set(None);assert_eq!(COPIES.get(),0);
    for (pointer,length) in [(0,1),(42,1025),(42,u64::MAX)] {
        assert_eq!(read_nul_caps_from_user(pointer,length),Err(Error::InvalidArgument));assert_eq!(COPIES.get(),0);
    }
    let bytes=b"x\0".repeat(130);let length=input(&bytes);assert_eq!(read_nul_caps_from_user(42,length as u64).unwrap().len(),128);
}
"#,
    );
    probe::run(&program);
}
