#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn ptsname_uses_thread_owned_storage_preserves_errors_and_allows_reentrant_control() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let mut program = format!(
        r#"
#![allow(dead_code,non_camel_case_types)]
extern crate self as mnu_abi;
#[path={:?}]mod abi;pub use abi::*;pub use abi::status;
#[path={:?}]mod posix_protocol;pub use posix_protocol::*;
use std::ffi::{{c_char,c_int,CStr}};
use std::ptr;
const EAGAIN:i32=11;const EFAULT:i32=14;const EIO:i32=5;const ERANGE:i32=34;
#[path={:?}]mod terminal_name;
struct ThreadControl{{ptsname_buffer:terminal_name::Buffer}}
static CONTROLS:[ThreadControl;2]=[const{{ThreadControl{{ptsname_buffer:terminal_name::Buffer::new()}}}};2];
thread_local!{{
 static INDEX:std::cell::Cell<usize>=const{{std::cell::Cell::new(0)}};
 static FAIL_REGISTER:std::cell::Cell<bool>=const{{std::cell::Cell::new(false)}};
 static ERRNO:std::cell::Cell<i32>=const{{std::cell::Cell::new(123)}};
 static ERROR:std::cell::Cell<i32>=const{{std::cell::Cell::new(0)}};
 static FAULT:std::cell::Cell<bool>=const{{std::cell::Cell::new(false)}};
 static NESTED:std::cell::Cell<bool>=const{{std::cell::Cell::new(false)}};
 static LEASES:std::cell::Cell<u32>=const{{std::cell::Cell::new(0)}};
 static COMPONENT:std::cell::RefCell<Vec<u8>>=std::cell::RefCell::new(b"81-37".to_vec());
}}
fn register_current_thread()->Option<(u32,&'static ThreadControl)>{{
 if FAIL_REGISTER.get(){{None}}else{{Some((INDEX.get() as u32,&CONTROLS[INDEX.get()]))}}
}}
fn set_errno(error:i32){{ERRNO.set(error)}}
#[derive(Clone,Copy)]struct FdEntry;
struct Lease(FdEntry);
impl std::ops::Deref for Lease{{type Target=FdEntry;fn deref(&self)->&FdEntry{{&self.0}}}}
impl Drop for Lease{{fn drop(&mut self){{LEASES.set(LEASES.get()-1)}}}}
fn with_fd_entry(fd:i32)->Result<Lease,i32>{{
 if fd!=4{{return Err(9)}}LEASES.set(LEASES.get()+1);Ok(Lease(FdEntry))
}}
mod io_resources{{pub fn with<R,T>(prepare:impl FnOnce()->Result<R,i32>,operation:impl FnOnce(&mut R)->Result<T,i32>)->Result<T,i32>{{
 let mut resource=prepare()?;operation(&mut resource)
}}}}
fn terminal_control(_:FdEntry,code:u64,input:&[u8],output:&mut[u8])->Result<usize,i32>{{
 assert_eq!(code,posix_protocol::PTY_CONTROL_GET_SLAVE_NAME);assert!(input.is_empty());
 assert!(LEASES.get()>0);
 if ERROR.get()!=0{{return Err(ERROR.get())}}
 if NESTED.replace(false){{
  COMPONENT.with_borrow_mut(|name|*name=b"81-88".to_vec());
  let nested=ptsname(4);assert!(!nested.is_null());
  assert_eq!(unsafe{{CStr::from_ptr(nested)}}.to_bytes(),b"/dev/pts/81-88");
  COMPONENT.with_borrow_mut(|name|*name=b"81-37".to_vec());
 }}
 COMPONENT.with_borrow(|name|posix_protocol::pty_name::encode(name,output).map_err(|_|EIO))
}}
mod user_copy{{pub fn write(output:*mut u8,bytes:&[u8])->Result<(),i32>{{
 if super::FAULT.get(){{return Err(super::EFAULT)}}
 // This probe writes only the live calling thread's actual Buffer storage.
 // Native MemoryCopy pointer enforcement is covered by its separate tests.
 unsafe{{std::ptr::copy_nonoverlapping(bytes.as_ptr(),output,bytes.len())}};Ok(())
}}}}
"#,
        root.join("core/crates/abi/src/lib.rs"),
        root.join("user/crates/posix-protocol/src/lib.rs"),
        root.join("user/crates/newlib-runtime/src/terminal_name.rs"),
    );
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    program.push_str(probe::between(
        runtime,
        "pub extern \"C\" fn ptsname(",
        "#[unsafe(no_mangle)]\npub extern \"C\" fn openpty(",
    ));
    program.push_str(
        r#"
fn main(){
 let barrier=std::sync::Arc::new(std::sync::Barrier::new(2));
 let workers:Vec<_>=(0..2).map(|index|{
  let barrier=barrier.clone();std::thread::spawn(move||{
   INDEX.set(index);
   let component=format!("81-{}",37+index).into_bytes();
   COMPONENT.with_borrow_mut(|name|*name=component.clone());
   let expected=format!("/dev/pts/{}",std::str::from_utf8(&component).unwrap());
   for _ in 0..100{
    let output=ptsname(4);assert!(!output.is_null());
    assert_eq!(ERRNO.get(),123);assert_eq!(LEASES.get(),0);
    barrier.wait();
    assert_eq!(unsafe{CStr::from_ptr(output)}.to_bytes(),expected.as_bytes());
    barrier.wait();
   }
  })
 }).collect();
 for worker in workers{worker.join().unwrap()}
 INDEX.set(0);
 COMPONENT.with_borrow_mut(|name|*name=b"81-37".to_vec());
 let first=ptsname(4);assert!(!first.is_null());
 COMPONENT.with_borrow_mut(|name|*name=b"81-99".to_vec());
 let second=ptsname(4);assert_eq!(first,second);
 assert_eq!(unsafe{CStr::from_ptr(second)}.to_bytes(),b"/dev/pts/81-99");
 NESTED.set(true);
 let outer=ptsname(4);assert_eq!(outer,first);
 assert_eq!(unsafe{CStr::from_ptr(outer)}.to_bytes(),b"/dev/pts/81-37");
 assert_eq!(LEASES.get(),0);
 assert!(ptsname(-1).is_null());assert_eq!(ERRNO.get(),9);
 for error in [5,13,25,32]{
  ERROR.set(error);assert!(ptsname(4).is_null());assert_eq!(ERRNO.get(),error);
  assert_eq!(LEASES.get(),0);
 }
 ERROR.set(0);FAULT.set(true);
 assert!(ptsname(4).is_null());assert_eq!(ERRNO.get(),EFAULT);
 assert_eq!(LEASES.get(),0);FAULT.set(false);
 FAIL_REGISTER.set(true);
 assert!(ptsname(4).is_null());assert_eq!(ERRNO.get(),EAGAIN);FAIL_REGISTER.set(false);
 // Both worker threads are joined. The runtime may now exclusively reuse
 // the old thread slot. No C string remains in application use; inspect the
 // owned storage byte directly to verify that old contents were discarded.
 unsafe{CONTROLS[0].ptsname_buffer.reset()};
 assert_eq!(unsafe{first.read()},0);
 let buffer=unsafe{terminal_name::owned(4,&CONTROLS[0].ptsname_buffer)}.unwrap();
 assert_eq!(unsafe{CStr::from_ptr(buffer)}.to_bytes(),b"/dev/pts/81-37");
}
"#,
    );
    probe::run(&program);
}

#[test]
fn reused_thread_slots_reset_name_storage_only_after_exclusive_claim() {
    // Structural wiring, not proof of native thread retirement or COW.
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let reserve = runtime
        .split("fn reserve_thread_control()")
        .nth(1)
        .unwrap()
        .split("enum ThreadReclamation")
        .next()
        .unwrap();
    let claim = reserve.find(".compare_exchange(").unwrap();
    let reset = reserve.find("control.ptsname_buffer.reset()").unwrap();
    let publish = reserve
        .find("return Some((token.raw(), control, preparation))")
        .unwrap();
    assert!(claim < reset && reset < publish);
    assert!(runtime.contains("ptsname_buffer: terminal_name::Buffer::new()"));
}
