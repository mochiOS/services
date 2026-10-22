//! Run exported C builders with real checked-copy/mapping boundaries.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn initialization_and_path_builders_check_caller_memory_and_release_failed_allocations() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let paths = include_str!("../../../user/crates/newlib-runtime/src/spawn_file_actions.rs");
    let mut program = format!(
        r#"
#![allow(dead_code)]
use std::ffi::{{c_int,c_char,c_void}};
use std::ptr;
use std::sync::atomic::{{AtomicU32,Ordering}};
extern crate self as mnu_abi;
#[derive(Debug,PartialEq)]pub enum SyscallNumber{{MemoryCopy}}
pub mod memory_copy{{pub const MAX_BYTES:usize=4096;}}
mod posix_protocol{{pub const MAX_PATH_LEN:usize=4096;}}
const EFAULT:i32=14;const EINVAL:i32=22;const EIO:i32=5;const ENOMEM:i32=12;
const EBADF:i32=9;const ENOENT:i32=2;const ENAMETOOLONG:i32=91;
const PAGE_SIZE:usize=4096;
#[path={:?}]mod upcall_guard;
#[path={:?}]mod user_copy_native;
#[path={:?}]mod user_copy;
static NATIVE:AtomicU32=AtomicU32::new(0);
static CALLS:AtomicU32=AtomicU32::new(0);
static FAIL_COPY:AtomicU32=AtomicU32::new(0);
static SHORT_COPY:AtomicU32=AtomicU32::new(0);
static ALLOC_CALLS:AtomicU32=AtomicU32::new(0);
static FAIL_ALLOC:AtomicU32=AtomicU32::new(0);
static LIVE:std::sync::Mutex<std::collections::BTreeSet<usize>>=
 std::sync::Mutex::new(std::collections::BTreeSet::new());
unsafe extern "C"{{
 #[link_name="malloc"]fn host_malloc(bytes:usize)->*mut c_void;
 #[link_name="free"]fn host_free(pointer:*mut c_void);
 fn mmap(address:*mut c_void,length:usize,protection:i32,flags:i32,fd:i32,offset:isize)->*mut c_void;
 fn mprotect(address:*mut c_void,length:usize,protection:i32)->i32;
 fn munmap(address:*mut c_void,length:usize)->i32;
}}
unsafe fn malloc(bytes:usize)->*mut c_void{{
 assert_ne!(NATIVE.load(Ordering::Relaxed),0);
 let call=ALLOC_CALLS.fetch_add(1,Ordering::Relaxed)+1;
 if call==FAIL_ALLOC.load(Ordering::Relaxed){{return ptr::null_mut()}}
 let p=unsafe{{host_malloc(bytes)}};
 if !p.is_null(){{assert!(LIVE.lock().unwrap().insert(p as usize));}}p
}}
unsafe fn free(pointer:*mut c_void){{
 assert_ne!(NATIVE.load(Ordering::Relaxed),0);
 assert!(LIVE.lock().unwrap().remove(&(pointer as usize)));
 unsafe{{host_free(pointer)}};
}}
fn defer_native_delivery()->Option<upcall_guard::Guard<'static>>{{upcall_guard::Guard::enter(&NATIVE)}}
fn syscall_errno(result:Result<u64,i32>)->Result<u64,i32>{{result}}
mod syscall{{
 pub use crate::SyscallNumber;
 pub fn raw_syscall3(number:SyscallNumber,destination:u64,source:u64,length:u64)->Result<u64,i32>{{
  assert_ne!(crate::NATIVE.load(crate::Ordering::Relaxed),0);
  let call=crate::CALLS.fetch_add(1,crate::Ordering::Relaxed)+1;
  let fail=crate::FAIL_COPY.load(crate::Ordering::Relaxed);
  if fail!=0 && call>=fail{{return Err(crate::EFAULT)}}
  if call==crate::SHORT_COPY.load(crate::Ordering::Relaxed){{return Ok(length-1)}}
  crate::user_copy_native::syscall::raw_syscall3(number,destination,source,length)
 }}
}}
fn reset(){{
 assert_eq!(NATIVE.load(Ordering::Relaxed),0);
 CALLS.store(0,Ordering::Relaxed);FAIL_COPY.store(0,Ordering::Relaxed);SHORT_COPY.store(0,Ordering::Relaxed);
 ALLOC_CALLS.store(0,Ordering::Relaxed);FAIL_ALLOC.store(0,Ordering::Relaxed);
}}
"#,
        root.join("user/crates/posix-client/src/upcall_guard.rs"),
        root.join("services/posix/tests/support/user_copy_native.rs"),
        root.join("user/crates/newlib-runtime/src/user_copy.rs"),
    );
    program.push_str(probe::between(
        runtime,
        "#[repr(C)]\n#[derive(Clone, Copy)]\npub struct PosixSpawnFileActions",
        "#[derive(Clone, Copy, PartialEq, Eq)]\n#[repr(u8)]\nenum FdKind",
    ));
    program.push_str("mod spawn_file_actions {use super::*;\n");
    program.push_str(probe::between(
        paths,
        "pub(super) struct Path",
        "pub(super) enum Action",
    ));
    program.push_str("}\n");
    program.push_str(probe::between(
        runtime,
        "unsafe fn init_file_actions_list(",
        "fn clone_current_fd_table(",
    ));
    program.push_str(
        &probe::between(
            runtime,
            "#[unsafe(no_mangle)]\npub extern \"C\" fn posix_spawn_file_actions_init(",
            "#[unsafe(no_mangle)]\npub extern \"C\" fn _posix_spawn(",
        )
        .replace("#[unsafe(no_mangle)]", ""),
    );
    program.push_str(
        r#"
fn main(){
 let mut actions: *mut PosixSpawnFileActions=ptr::null_mut();
 reset();assert_eq!(posix_spawn_file_actions_init(ptr::null_mut()),EINVAL);
 for address in [1usize,usize::MAX]{
  reset();assert_eq!(posix_spawn_file_actions_init(address as *mut _),EFAULT);
  assert!(LIVE.lock().unwrap().is_empty());
 }
 reset();FAIL_ALLOC.store(1,Ordering::Relaxed);
 assert_eq!(posix_spawn_file_actions_init(&mut actions),ENOMEM);assert!(actions.is_null());
 for short in [false,true]{
  reset();if short{SHORT_COPY.store(1,Ordering::Relaxed)}else{FAIL_COPY.store(1,Ordering::Relaxed)};
  assert_eq!(posix_spawn_file_actions_init(&mut actions),if short{EIO}else{EFAULT});
  assert!(actions.is_null());assert!(LIVE.lock().unwrap().is_empty());
 }
 // Publication may target an unaligned C opaque-handle slot.
 let mut slot=[0u8;9];let outer=slot.as_mut_ptr().wrapping_add(1).cast();
 reset();assert_eq!(posix_spawn_file_actions_init(outer),0);
 let value=usize::from_ne_bytes(slot[1..].try_into().unwrap()) as *mut PosixSpawnFileActions;
 assert!(!value.is_null());assert_eq!(slot[0],0);
 unsafe{assert!((*value).fa_list.stqh_first.is_null());
 assert_eq!((*value).fa_list.stqh_last,ptr::addr_of_mut!((*value).fa_list.stqh_first));}
 reset();assert_eq!(posix_spawn_file_actions_addclose(outer,3),0);
 reset();assert_eq!(posix_spawn_file_actions_destroy(outer),0);
 assert_eq!(slot,[0u8;9]);
 assert!(LIVE.lock().unwrap().is_empty());
 let pages=unsafe{mmap(ptr::null_mut(),8192,3,0x22,-1,0)};
 assert_ne!(pages as usize,usize::MAX);
 let protected=pages.cast::<*mut PosixSpawnFileActions>();
 unsafe{ptr::write(protected,0x1234usize as *mut _)};
 assert_eq!(unsafe{mprotect(pages,4096,1)},0);
 reset();assert_eq!(posix_spawn_file_actions_init(protected),EFAULT);
 assert_eq!(unsafe{ptr::read(protected)} as usize,0x1234);
 assert!(LIVE.lock().unwrap().is_empty());
 assert_eq!(unsafe{mprotect(pages,4096,3)},0);
 reset();assert_eq!(posix_spawn_file_actions_init(&mut actions),0);
 type Add=fn(*mut *mut PosixSpawnFileActions,*const c_char)->i32;
 let builders:[Add;3]=[
  |a,p|posix_spawn_file_actions_addopen(a,7,p,0x1234,0o640),
  |a,p|posix_spawn_file_actions_addchdir_np(a,p),
  |a,p|posix_spawn_file_actions_addchdir(a,p),
 ];
 for add in builders{
  let before=unsafe{(*actions).fa_list};let live=LIVE.lock().unwrap().len();
  for address in [1usize,usize::MAX]{
   reset();assert_eq!(add(address as *mut _,c"kept".as_ptr()),EFAULT);
  }
  for call in [1,2]{
   for short in [false,true]{
    reset();if short{SHORT_COPY.store(call,Ordering::Relaxed)}else{FAIL_COPY.store(call,Ordering::Relaxed)};
    assert_eq!(add(&mut actions,c"kept".as_ptr()),if short{EIO}else{EFAULT});
    assert_eq!(LIVE.lock().unwrap().len(),live);
   }
  }
  for address in [1usize,usize::MAX]{
   reset();assert_eq!(add(&mut actions,address as *const _),EFAULT);
   assert_eq!(LIVE.lock().unwrap().len(),live);
   unsafe{assert_eq!((*actions).fa_list.stqh_first,before.stqh_first);
   assert_eq!((*actions).fa_list.stqh_last,before.stqh_last);}
  }
  // Limit applies before allocation, including a missing NUL.
  let oversized=vec![b'x';4097];
  reset();assert_eq!(add(&mut actions,oversized.as_ptr().cast()),ENAMETOOLONG);
  assert_eq!(LIVE.lock().unwrap().len(),live);
  for fail in [1,2]{
   reset();FAIL_ALLOC.store(fail,Ordering::Relaxed);
   assert_eq!(add(&mut actions,c"kept".as_ptr()),ENOMEM);
   assert_eq!(LIVE.lock().unwrap().len(),live);
   unsafe{assert_eq!((*actions).fa_list.stqh_first,before.stqh_first);
   assert_eq!((*actions).fa_list.stqh_last,before.stqh_last);}
  }
  // NUL at a page end is valid; no speculative access to the next page.
  let text=unsafe{pages.cast::<u8>().add(4091)};
  unsafe{ptr::copy_nonoverlapping(b"test\0".as_ptr(),text,5)};
  assert_eq!(unsafe{mprotect(pages.cast::<u8>().add(4096).cast(),4096,0)},0);
  reset();assert_eq!(add(&mut actions,text.cast()),0);
  unsafe{ptr::write(text,b'X')};
  let mut node=unsafe{(*actions).fa_list.stqh_first};
  while !unsafe{(*node).fae_list.stqe_next}.is_null(){node=unsafe{(*node).fae_list.stqe_next};}
  let path=unsafe{if (*node).fae_action==FAE_OPEN{(*node).fae_data.open.path}else{(*node).fae_data.dir}};
  assert_eq!(unsafe{std::ffi::CStr::from_ptr(path)}.to_bytes(),b"test");
  // Unterminated prefix must fail without adding a node or keeping text.
  unsafe{ptr::write(text.add(4),b'x')};
  let live=LIVE.lock().unwrap().len();
  reset();assert_eq!(add(&mut actions,text.cast()),EFAULT);
  assert_eq!(LIVE.lock().unwrap().len(),live);
  assert!(unsafe{(*node).fae_list.stqe_next}.is_null());
 }
 reset();assert_eq!(posix_spawn_file_actions_addclose(&mut actions,4),0);
 reset();assert_eq!(posix_spawn_file_actions_adddup2(&mut actions,4,5),0);
 reset();assert_eq!(posix_spawn_file_actions_addfchdir(&mut actions,6),0);
 // Every other builder resolves the opaque slot through checked copies too.
 for address in [1usize,usize::MAX]{
  reset();assert_eq!(posix_spawn_file_actions_addclose(address as *mut _,4),EFAULT);
  reset();assert_eq!(posix_spawn_file_actions_adddup2(address as *mut _,4,5),EFAULT);
  reset();assert_eq!(posix_spawn_file_actions_addfchdir(address as *mut _,6),EFAULT);
  reset();assert_eq!(posix_spawn_file_actions_destroy(address as *mut _),EFAULT);
 }
 let live=LIVE.lock().unwrap().len();let previous=actions;
 for call in [1,2]{
  for short in [false,true]{
   reset();if short{SHORT_COPY.store(call,Ordering::Relaxed)}else{FAIL_COPY.store(call,Ordering::Relaxed)};
   assert_eq!(posix_spawn_file_actions_destroy(&mut actions),if short{EIO}else{EFAULT});
   assert_eq!(actions,previous);assert_eq!(LIVE.lock().unwrap().len(),live);
  }
 }
 // Read-only opaque storage cannot be cleared: keep its list and all paths.
 unsafe{ptr::write(protected,actions)};
 assert_eq!(unsafe{mprotect(pages,4096,1)},0);
 reset();assert_eq!(posix_spawn_file_actions_destroy(protected),EFAULT);
 assert_eq!(unsafe{ptr::read(protected)},actions);
 assert_eq!(LIVE.lock().unwrap().len(),live);
 assert_eq!(unsafe{mprotect(pages,4096,3)},0);
 reset();assert_eq!(posix_spawn_file_actions_destroy(&mut actions),0);
 assert!(actions.is_null());assert!(LIVE.lock().unwrap().is_empty());
 assert_eq!(NATIVE.load(Ordering::Relaxed),0);
 assert_eq!(unsafe{munmap(pages,8192)},0);
}
"#,
    );
    probe::run(&program);
}
