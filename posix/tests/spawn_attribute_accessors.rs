//! Execute every exported attribute accessor with the real checked-copy code.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn exported_accessors_copy_fields_without_dereferencing_application_pointers() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let mut program = format!(
        r#"
#![allow(dead_code)]
use std::ffi::{{c_int,c_char,c_void}};
use std::ptr;
use std::sync::atomic::{{AtomicU32,Ordering}};
extern crate self as mnu_abi;
extern crate self as mochios_posix_client;
#[derive(Debug,PartialEq)]pub enum SyscallNumber{{MemoryCopy}}
pub mod memory_copy{{pub const MAX_BYTES:usize=4096;}}
mod posix_protocol{{pub const MAX_PATH_LEN:usize=4096;}}
const EFAULT:i32=14;const EINVAL:i32=22;const EIO:i32=5;
const ENOSYS:i32=88;const ENOENT:i32=2;const ENAMETOOLONG:i32=91;
const PAGE_SIZE:usize=4096;
#[path={:?}]pub mod spawn;
#[path={:?}]pub mod upcall_guard;
#[path={:?}]mod user_copy_native;
#[path={:?}]mod user_copy;
#[path={:?}]mod spawn_attributes;
static NATIVE:AtomicU32=AtomicU32::new(0);
static CALLS:AtomicU32=AtomicU32::new(0);
static FAIL_AT:AtomicU32=AtomicU32::new(0);
static SHORT_AT:AtomicU32=AtomicU32::new(0);
fn defer_native_delivery()->Option<upcall_guard::Guard<'static>>{{upcall_guard::Guard::enter(&NATIVE)}}
fn syscall_errno(result:Result<u64,i32>)->Result<u64,i32>{{result}}
mod syscall{{
 pub use crate::SyscallNumber;
 pub fn raw_syscall3(number:SyscallNumber,destination:u64,source:u64,length:u64)->Result<u64,i32>{{
  assert_ne!(crate::NATIVE.load(crate::Ordering::Relaxed),0);
  let call=crate::CALLS.fetch_add(1,crate::Ordering::Relaxed)+1;
  if call==crate::FAIL_AT.load(crate::Ordering::Relaxed){{return Err(crate::EFAULT)}}
  if call==crate::SHORT_AT.load(crate::Ordering::Relaxed){{return Ok(length-1)}}
  crate::user_copy_native::syscall::raw_syscall3(number,destination,source,length)
 }}
}}
fn reset(){{
 assert_eq!(NATIVE.load(Ordering::Relaxed),0);
 CALLS.store(0,Ordering::Relaxed);FAIL_AT.store(0,Ordering::Relaxed);SHORT_AT.store(0,Ordering::Relaxed);
 user_copy_native::DENIED.with_borrow_mut(|denied|*denied=None);
}}
unsafe extern "C"{{
 fn mmap(address:*mut c_void,length:usize,protection:i32,flags:i32,fd:i32,offset:isize)->*mut c_void;
 fn mprotect(address:*mut c_void,length:usize,protection:i32)->i32;
 fn munmap(address:*mut c_void,length:usize)->i32;
}}
"#,
        root.join("user/crates/posix-client/src/spawn.rs"),
        root.join("user/crates/posix-client/src/upcall_guard.rs"),
        root.join("services/posix/tests/support/user_copy_native.rs"),
        root.join("user/crates/newlib-runtime/src/user_copy.rs"),
        root.join("user/crates/newlib-runtime/src/spawn_attributes.rs"),
    );
    program.push_str(probe::between(
        runtime,
        "#[repr(C)]\n#[derive(Clone, Copy)]\npub struct SchedParam",
        "#[repr(C)]\n#[derive(Clone, Copy)]\npub struct PthreadAttr",
    ));
    // Remove symbol export only in the host probe; execute the exact bodies
    // without interposing on the host libc's different opaque-object ABI.
    program.push_str(
        &probe::between(
            runtime,
            "#[unsafe(no_mangle)]\npub extern \"C\" fn posix_spawnattr_getflags(",
            "#[unsafe(no_mangle)]\npub extern \"C\" fn posix_spawn_file_actions_init(",
        )
        .replace("#[unsafe(no_mangle)]", ""),
    );
    program.push_str(
        r#"
fn main(){
 type Get=fn(*const *mut PosixSpawnAttr,*mut u8)->i32;
 type Set=fn(*mut *mut PosixSpawnAttr,*const u8)->i32;
 let cases:[(usize,usize,Get,Set,&[u8]);6]=[
  (0,2,|a,o|posix_spawnattr_getflags(a,o.cast()),
   |a,i|posix_spawnattr_setflags(a,i16::from_ne_bytes(unsafe{ptr::read_unaligned(i.cast())})),&0x3fi16.to_ne_bytes()),
  (4,4,|a,o|posix_spawnattr_getpgroup(a,o.cast()),
   |a,i|posix_spawnattr_setpgroup(a,i32::from_ne_bytes(unsafe{ptr::read_unaligned(i.cast())})),&(-17i32).to_ne_bytes()),
  (8,4,|a,o|posix_spawnattr_getschedparam(a,o.cast()),
   |a,i|posix_spawnattr_setschedparam(a,i.cast()),&73i32.to_ne_bytes()),
  (12,4,|a,o|posix_spawnattr_getschedpolicy(a,o.cast()),
   |a,i|posix_spawnattr_setschedpolicy(a,i32::from_ne_bytes(unsafe{ptr::read_unaligned(i.cast())})),&3i32.to_ne_bytes()),
  (16,8,|a,o|posix_spawnattr_getsigdefault(a,o.cast()),
   |a,i|posix_spawnattr_setsigdefault(a,i.cast()),&0xfedc_ba98_7654_3210u64.to_ne_bytes()),
  (24,8,|a,o|posix_spawnattr_getsigmask(a,o.cast()),
   |a,i|posix_spawnattr_setsigmask(a,i.cast()),&u64::MAX.to_ne_bytes()),
 ];
 assert_eq!(std::mem::size_of::<PosixSpawnAttr>(),32);
 for (offset,length,get,set,expected) in cases{
  // Both the opaque handle and its object are deliberately unaligned.
  let mut object=[0xa5u8;33];
  let mut handle=[0u8;9];
  let base=object.as_mut_ptr().wrapping_add(1);
  handle[1..].copy_from_slice(&(base as usize).to_ne_bytes());
  let attr=handle.as_mut_ptr().wrapping_add(1).cast::<*mut PosixSpawnAttr>();
  let mut input=[0xcc;9];input[1..1+length].copy_from_slice(expected);
  reset();assert_eq!(set(attr,input.as_ptr().wrapping_add(1)),0);
  assert_eq!(&object[1+offset..1+offset+length],expected);
  assert!(object[..1+offset].iter().all(|&v|v==0xa5));
  assert!(object[1+offset+length..].iter().all(|&v|v==0xa5));
  let mut output=[0xcc;10];
  reset();assert_eq!(get(attr,output.as_mut_ptr().wrapping_add(1)),0);
  assert_eq!(&output[1..1+length],expected);
  assert_eq!(output[0],0xcc);assert!(output[1+length..].iter().all(|&v|v==0xcc));
  assert_eq!(CALLS.load(Ordering::Relaxed),3);
  assert_eq!(NATIVE.load(Ordering::Relaxed),0);
  // No accessor validates unrelated flag/group fields, or reads padding.
  reset();user_copy_native::DENIED.with_borrow_mut(|d|*d=Some(base as usize+2..base as usize+4));
  assert_eq!(get(attr,output.as_mut_ptr()),0);
  reset();assert_eq!(get(attr,ptr::null_mut()),EINVAL);
  reset();assert_eq!(get(ptr::null(),output.as_mut_ptr()),EINVAL);
  for address in [1usize,usize::MAX]{
   reset();assert_eq!(get(address as *const _,output.as_mut_ptr()),EFAULT);
   reset();assert_eq!(get(attr,address as *mut _),EFAULT);
   reset();assert_eq!(set(address as *mut _,input.as_ptr().wrapping_add(1)),EFAULT);
  }
  for inner in [0usize,1,usize::MAX]{
   let mut bad=inner as *mut PosixSpawnAttr;
   reset();assert_eq!(get(&bad,output.as_mut_ptr()),if inner==0{EINVAL}else{EFAULT});
   reset();assert_eq!(set(&mut bad,input.as_ptr().wrapping_add(1)),if inner==0{EINVAL}else{EFAULT});
  }
  let previous=object;
  for stage in 1..=3{
   for short in [false,true]{
    reset();if short{SHORT_AT.store(stage,Ordering::Relaxed)}else{FAIL_AT.store(stage,Ordering::Relaxed)}
    output.fill(0x5a);
    assert_eq!(get(attr,output.as_mut_ptr()),if short{EIO}else{EFAULT});
    assert_eq!(output,[0x5a;10]);
    reset();if short{SHORT_AT.store(stage,Ordering::Relaxed)}else{FAIL_AT.store(stage,Ordering::Relaxed)}
    assert_eq!(set(attr,input.as_ptr().wrapping_add(1)),if short{EIO}else{EFAULT});
    assert_eq!(object,previous);
   }
  }
  // All destinations, including opaque objects, honor actual page protection.
  let page=unsafe{mmap(ptr::null_mut(),4096,3,0x22,-1,0)};
  assert_ne!(page as usize,usize::MAX);
  unsafe{ptr::copy_nonoverlapping(object.as_ptr().add(1),page.cast(),32)};
  assert_eq!(unsafe{mprotect(page,4096,1)},0);
  reset();assert_eq!(get(attr,page.cast()),EFAULT);
  let mut readonly=page.cast::<PosixSpawnAttr>();
  reset();assert_eq!(set(&mut readonly,input.as_ptr().wrapping_add(1)),EFAULT);
  // A getter succeeds on the same read-only attribute object.
  reset();assert_eq!(get(&readonly,output.as_mut_ptr()),0);
  assert_eq!(unsafe{munmap(page,4096)},0);
  assert_eq!(NATIVE.load(Ordering::Relaxed),0);
 }
 let mut object=PosixSpawnAttr::new();let mut handle=&mut object as *mut _;
 reset();assert_eq!(posix_spawnattr_setschedparam(&mut handle,ptr::null()),EINVAL);
 reset();assert_eq!(posix_spawnattr_setsigdefault(&mut handle,ptr::null()),EINVAL);
 reset();assert_eq!(posix_spawnattr_setsigmask(&mut handle,ptr::null()),EINVAL);
 for bad in [1usize,usize::MAX]{
  reset();assert_eq!(posix_spawnattr_setschedparam(&mut handle,bad as *const _),EFAULT);
  reset();assert_eq!(posix_spawnattr_setsigdefault(&mut handle,bad as *const _),EFAULT);
  reset();assert_eq!(posix_spawnattr_setsigmask(&mut handle,bad as *const _),EFAULT);
 }
 reset();assert_eq!(posix_spawnattr_setflags(1usize as *mut _,0x40),EINVAL);
 assert_eq!(CALLS.load(Ordering::Relaxed),0);
 // Capture a setter's input even when it aliases another field of the object.
 object.sa_sigdefault=0x1234_5678_90ab_cdef;
 let input=ptr::addr_of!(object.sa_sigdefault);
 reset();assert_eq!(posix_spawnattr_setsigmask(&mut handle,input),0);
 assert_eq!(object.sa_sigmask,object.sa_sigdefault);
 // The output may overlap the opaque handle itself: resolve it once, before
 // copying out the selected field, rather than consulting it again afterward.
 let mut overlapping=&mut object as *mut PosixSpawnAttr;
 let outer=ptr::addr_of_mut!(overlapping);
 reset();assert_eq!(posix_spawnattr_getsigmask(outer,outer.cast()),0);
 assert_eq!(overlapping as usize,0x1234_5678_90ab_cdef);
 assert_eq!(CALLS.load(Ordering::Relaxed),3);
 // A scalar straddling an inaccessible page cannot partially update an
 // otherwise writable attribute. This is an actual mapping failure.
 let pages=unsafe{mmap(ptr::null_mut(),8192,3,0x22,-1,0)};
 assert_ne!(pages as usize,usize::MAX);
 assert_eq!(unsafe{mprotect(pages.cast::<u8>().add(4096).cast(),4096,0)},0);
 let truncated=unsafe{pages.cast::<u8>().add(4092)};
 unsafe{ptr::write_unaligned(truncated.cast::<u32>(),0xdead_beef)};
 let previous=object.sa_sigmask;
 reset();assert_eq!(posix_spawnattr_setsigmask(&mut handle,truncated.cast()),EFAULT);
 assert_eq!(object.sa_sigmask,previous);
 assert_eq!(unsafe{munmap(pages,8192)},0);
 // Known-but-unsupported scheduler flags are storable. Admission, not the
 // attribute accessors, rejects them when the caller actually spawns.
 reset();assert_eq!(posix_spawnattr_setflags(&mut handle,spawn::SET_SCHEDULER),0);
 assert_eq!(spawn_attributes::read_optional((&handle as *const *mut PosixSpawnAttr).cast()).map(|_|()),Err(ENOSYS));
 assert_eq!(NATIVE.load(Ordering::Relaxed),0);
}
"#,
    );
    probe::run(&program);
}
