//! Execute the public wrappers and actual fault-safe group-array conversion.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn group_array_faults_do_not_escape_or_mutate_service_state() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let mut program = String::from(
        r#"use core::ffi::{c_int,c_char};
const EFAULT:i32=14;const EINVAL:i32=22;const EOVERFLOW:i32=139;
const EIO:i32=5;const ENOENT:i32=2;const ENAMETOOLONG:i32=91;
const PAGE_SIZE:usize=4096;
use std::cell::{Cell,RefCell};
thread_local!{
 static ERRNO:Cell<i32>=const{Cell::new(123)};
 static GETS:Cell<usize>=const{Cell::new(0)};
 static SETS:Cell<usize>=const{Cell::new(0)};
 static VALUES:RefCell<Vec<u32>>=const{RefCell::new(Vec::new())};
 static FAILURE:Cell<Option<i32>>=const{Cell::new(None)};
}
struct Client;
fn posix_client()->Result<Client,i32>{Ok(Client)}
fn map_posix_client_error(error:i32)->i32{error}
impl Client{
 fn get_groups(&self,output:&mut[u32])->Result<usize,i32>{
  GETS.set(GETS.get()+1);
  if let Some(error)=FAILURE.get(){return Err(error)}
  VALUES.with_borrow(|values|{
   output[..values.len()].copy_from_slice(values);Ok(values.len())
  })
 }
 fn set_groups(&self,values:&[u32])->Result<(),i32>{
  SETS.set(SETS.get()+1);
  if let Some(error)=FAILURE.get(){return Err(error)}
  VALUES.with_borrow_mut(|output|*output=values.to_vec());Ok(())
 }
}
fn result_with_errno(result:Result<i32,i32>,failure:i32)->i32{
 match result{Ok(value)=>value,Err(error)=>{ERRNO.set(error);failure}}
}
fn reset(values:&[u32]){
 ERRNO.set(123);GETS.set(0);SETS.set(0);FAILURE.set(None);
 VALUES.with_borrow_mut(|output|*output=values.to_vec());
 user_copy_native::CALLS.with_borrow_mut(Vec::clear);
 user_copy_native::DENIED.with_borrow_mut(|value|*value=None);
}
fn failed(result:i32,error:i32){assert_eq!(result,-1);assert_eq!(ERRNO.get(),error)}
"#,
    );
    for (name, path) in [
        (
            "user_copy_native",
            "services/posix/tests/support/user_copy_native.rs",
        ),
        ("groups", "user/crates/newlib-runtime/src/groups.rs"),
        (
            "groups_memory",
            "user/crates/newlib-runtime/src/groups_memory.rs",
        ),
        ("user_copy", "user/crates/newlib-runtime/src/user_copy.rs"),
    ] {
        program.push_str(&format!("#[path={:?}]mod {name};\n", root.join(path)));
    }
    program.push_str("use user_copy_native::{syscall,syscall_errno};\n");
    program.push_str("mod posix_protocol {\n");
    probe::constants(
        &mut program,
        include_str!("../../../user/crates/posix-protocol/src/lib.rs"),
        &["MAX_SUPPLEMENTARY_GROUPS", "MAX_PATH_LEN"],
    );
    program.push_str("}\n");
    program.insert_str(
        0,
        &format!(
            "extern crate self as mnu_abi;\n#[path={:?}]mod native_abi;pub use native_abi::*;\n",
            root.join("core/crates/abi/src/lib.rs")
        ),
    );
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    program.push_str(
        &probe::between(
            runtime,
            "pub extern \"C\" fn getgroups(",
            "#[unsafe(no_mangle)]\npub extern \"C\" fn umask(",
        )
        .replace("#[unsafe(no_mangle)]", ""),
    );
    program.push_str(
        r#"
fn main(){
 // Counts use the ABI's two-byte gid_t stride, even at unaligned addresses.
 let mut bytes=[0xa5u8;8];let pointer=bytes.as_mut_ptr().wrapping_add(1).cast();
 reset(&[0,65535,1234]);assert_eq!(getgroups(3,pointer),3);
 assert_eq!(bytes,[0xa5,0,0,255,255,210,4,0xa5]);assert_eq!(ERRNO.get(),123);
 assert_eq!(setgroups(3,pointer),0);
 VALUES.with_borrow(|values|assert_eq!(values,&[0,65535,1234]));
 assert_eq!(SETS.get(),1);assert_eq!(ERRNO.get(),123);
 // Insufficient capacity and narrowing overflow leave all output untouched.
 for (values,capacity,error) in [(&[1,2][..],1,EINVAL),(&[1,65536][..],2,EOVERFLOW)]{
  reset(values);bytes.fill(0xa5);failed(getgroups(capacity,pointer),error);
  assert_eq!(bytes,[0xa5;8]);assert_eq!(SETS.get(),0);
  user_copy_native::CALLS.with_borrow(|calls|assert!(calls.is_empty()));
 }
 // Count-only queries must not dereference even a nonnull invalid pointer.
 for address in [0,1,usize::MAX]{
  reset(&[1,2]);assert_eq!(getgroups(0,address as *mut _),2);
  assert_eq!(ERRNO.get(),123);
  user_copy_native::CALLS.with_borrow(|calls|assert!(calls.is_empty()));
  assert_eq!(setgroups(0,address as *const _),0);
  VALUES.with_borrow(|values|assert!(values.is_empty()));assert_eq!(SETS.get(),1);
 }
 for address in [0,1,usize::MAX]{
  reset(&[7]);failed(setgroups(1,address as *const _),EFAULT);
  VALUES.with_borrow(|values|assert_eq!(values,&[7]));assert_eq!(SETS.get(),0);
  failed(getgroups(1,address as *mut _),EFAULT);
  assert_eq!(SETS.get(),0);
 }
 // Reject invalid counts before reading memory or issuing any RPC.
 for count in [-1,33,i32::MAX]{
  reset(&[7]);failed(setgroups(count,1 as *const _),EINVAL);
  assert_eq!(SETS.get(),0);assert_eq!(GETS.get(),0);
  user_copy_native::CALLS.with_borrow(|calls|assert!(calls.is_empty()));
 }
 reset(&[7]);failed(getgroups(-1,pointer),EINVAL);assert_eq!(GETS.get(),0);
 // An inaccessible later part of an input cannot install a captured prefix.
 reset(&[7]);user_copy_native::DENIED.with_borrow_mut(|value|{
  *value=Some(pointer.addr()+2..pointer.addr()+4)
 });
 failed(setgroups(2,pointer),EFAULT);assert_eq!(SETS.get(),0);
 VALUES.with_borrow(|values|assert_eq!(values,&[7]));
 // Permission and service errors survive unchanged after successful capture.
 for error in [1,5,13,38]{
  reset(&[7]);FAILURE.set(Some(error));bytes.fill(0xa5);
  failed(setgroups(2,pointer),error);assert_eq!(SETS.get(),1);
  VALUES.with_borrow(|values|assert_eq!(values,&[7]));
  failed(getgroups(2,pointer),error);assert_eq!(bytes,[0xa5;8]);
 }
 // Exercise every permitted entry; output is not sized from caller capacity.
 let all:Vec<u32>=(0..32).map(|i|i*2000).collect();
 let mut output=[65535u16;34];reset(&all);
 assert_eq!(getgroups(i32::MAX,output.as_mut_ptr().wrapping_add(1)),32);
 assert_eq!((output[0],output[33]),(65535,65535));
 assert_eq!(setgroups(32,output.as_ptr().wrapping_add(1)),0);
 VALUES.with_borrow(|values|assert_eq!(values,&all));
}
"#,
    );
    probe::run(&program);
}
