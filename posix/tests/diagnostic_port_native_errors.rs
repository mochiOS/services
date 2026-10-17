#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn diagnostic_and_port_entries_fail_natively_before_output_or_hardware_access() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let mut program = format!(
        r#"
#![allow(dead_code)]
extern crate alloc;
extern crate self as mnu_abi;
#[path={status:?}]pub mod status;
use status::Error;
use std::cell::{{Cell,RefCell}};
use util::console;
const SUCCESS:u64=0;
thread_local!{{
 static FAIL_ALLOC:Cell<bool>=const{{Cell::new(false)}};
 static COPY_ERROR:Cell<Option<Error>>=const{{Cell::new(None)}};
 static COPIES:Cell<usize>=const{{Cell::new(0)}};
 static INPUT:RefCell<Vec<u8>>=const{{RefCell::new(Vec::new())}};
 static OUTPUT:RefCell<Vec<u8>>=const{{RefCell::new(Vec::new())}};
 static VGA:Cell<usize>=const{{Cell::new(0)}};
 static IRQS_OFF:Cell<bool>=const{{Cell::new(false)}};
 static ALLOWED:Cell<bool>=const{{Cell::new(false)}};
 static PORTS:Cell<usize>=const{{Cell::new(0)}};
}}
struct Allocator;
unsafe impl std::alloc::GlobalAlloc for Allocator{{
 unsafe fn alloc(&self,l:std::alloc::Layout)->*mut u8{{
  if FAIL_ALLOC.try_with(|f|f.replace(false)).unwrap_or(false){{std::ptr::null_mut()}}else{{unsafe{{std::alloc::System.alloc(l)}}}}
 }}
 unsafe fn dealloc(&self,p:*mut u8,l:std::alloc::Layout){{unsafe{{std::alloc::System.dealloc(p,l)}}}}
}}
#[global_allocator]static ALLOCATOR:Allocator=Allocator;
#[derive(Debug,PartialEq)]enum Capability{{UsbAccess,DeviceInput,DeviceGpu,DeviceNet,SerialAccess}}
mod syscall{{
 pub mod security{{pub fn caller_has_any_capability(caps:&[crate::Capability])->bool{{
  use crate::Capability::*;assert_eq!(caps,&[UsbAccess,DeviceInput,DeviceGpu,DeviceNet,SerialAccess]);crate::ALLOWED.get()
 }}}}
 pub fn copy_from_user_native(pointer:u64,bytes:&mut[u8])->Result<(),crate::Error>{{
  assert!(!crate::IRQS_OFF.get());assert_eq!(pointer,1);crate::COPIES.set(crate::COPIES.get()+1);
  if let Some(e)=crate::COPY_ERROR.get(){{return Err(e);}}
  crate::INPUT.with_borrow(|input|{{assert_eq!(input.len(),bytes.len());bytes.copy_from_slice(input);}});Ok(())
 }}
}}
mod util{{
 #[path={storage:?}]pub mod object_snapshot;
 pub mod console{{
  pub struct Serial;impl Serial{{pub fn send_byte(&mut self,b:u8){{assert!(crate::IRQS_OFF.get());crate::OUTPUT.with_borrow_mut(|v|v.push(b));}}}}
  pub static SERIAL:std::sync::Mutex<Serial>=std::sync::Mutex::new(Serial);
 }}
 pub mod vga{{pub fn print(args:core::fmt::Arguments<'_>){{assert!(!crate::IRQS_OFF.get());assert_eq!(args.to_string(),"abc");crate::VGA.set(crate::VGA.get()+1);}}}}
}}
mod x86_64{{pub mod instructions{{pub mod interrupts{{
 pub fn without_interrupts(f:impl FnOnce()){{assert!(!crate::IRQS_OFF.replace(true));f();assert!(crate::IRQS_OFF.replace(false));}}
}}}}}}
fn touched(port:u16){{assert_eq!(port,0x1234);PORTS.set(PORTS.get()+1);}}
fn read_port_u8(p:u16)->u8{{touched(p);0x78}}fn read_port_u16(p:u16)->u16{{touched(p);0x5678}}fn read_port_u32(p:u16)->u32{{touched(p);0x12345678}}
fn write_port_u8(p:u16,v:u8){{touched(p);assert_eq!(v,0x78);}}fn write_port_u16(p:u16,v:u16){{touched(p);assert_eq!(v,0x5678);}}fn write_port_u32(p:u16,v:u32){{touched(p);assert_eq!(v,0x12345678);}}
"#,
        status = root.join("core/crates/abi/src/status.rs"),
        storage = root.join("core/src/util/object_snapshot.rs")
    );
    let source = include_str!("../../../core/src/syscall/io.rs");
    program.push_str(probe::between(
        source,
        "fn caller_has_port_io_access(",
        "/// Writes raw bytes",
    ));
    program.push_str(probe::between(
        source,
        "pub fn debug_write(",
        "fn read_port_u8(",
    ));
    program.push_str(&source[source.find("pub fn port_in(").unwrap()..]);
    program.push_str(r#"
fn reset(input:&[u8]){
 assert!(!IRQS_OFF.get());FAIL_ALLOC.set(false);COPY_ERROR.set(None);COPIES.set(0);VGA.set(0);PORTS.set(0);
 INPUT.with_borrow_mut(|v|{v.clear();v.extend_from_slice(input);});OUTPUT.with_borrow_mut(|v|{v.clear();v.reserve(8);});
}
fn silent(){assert!(OUTPUT.with_borrow(|v|v.is_empty()));assert_eq!(VGA.get(),0);}
fn main(){
 reset(b"abc");assert_eq!(debug_write(1,3),3);assert_eq!(COPIES.get(),1);assert_eq!(VGA.get(),1);assert_eq!(OUTPUT.with_borrow(Clone::clone),b"abc");
 reset(&[0xff,0]);assert_eq!(debug_write(1,2),2);assert_eq!(VGA.get(),0);assert_eq!(OUTPUT.with_borrow(Clone::clone),[0xff,0]);
 reset(&[]);assert_eq!(debug_write(0,0),0);assert_eq!(COPIES.get(),0);silent();
 for (pointer,length,error) in [(0,1,Error::InvalidAddress),(u64::MAX,1,Error::InvalidAddress),(1,u64::MAX,Error::LimitExceeded)]{
  reset(&[]);assert_eq!(debug_write(pointer,length),error.into_raw());assert_eq!(COPIES.get(),0);silent();
 }
 reset(b"abc");FAIL_ALLOC.set(true);assert_eq!(debug_write(1,3),Error::ResourceUnavailable.into_raw());assert_eq!(COPIES.get(),0);silent();
 for error in [Error::InvalidAddress,Error::NotReady,Error::BackingFailure,Error::ResourceUnavailable]{
  reset(b"abc");COPY_ERROR.set(Some(error));assert_eq!(debug_write(1,3),error.into_raw());assert_eq!(COPIES.get(),1);silent();
 }
 reset(&[]);
 for allowed in [false,true]{ALLOWED.set(allowed);
  for width in [0,1,2,3,4,8]{for port in [0x1234,u16::MAX as u64+1,u64::MAX]{
   let before=PORTS.get();let input=port_in(port,width);let output=port_out(port,0x12345678,width);
   if !allowed{assert_eq!(input,Error::AccessDenied.into_raw());assert_eq!(output,input);assert_eq!(PORTS.get(),before);}
   else if port>u16::MAX as u64||!matches!(width,1|2|4){assert_eq!(input,Error::InvalidArgument.into_raw());assert_eq!(output,input);assert_eq!(PORTS.get(),before);}
   else{assert_eq!(input,match width{1=>0x78,2=>0x5678,_=>0x12345678});assert_eq!(output,0);assert_eq!(PORTS.get(),before+2);}
  }}
 }
}
"#);
    // Model only the serial lock adapter; production holds it after usercopy.
    program = program.replace("console::SERIAL.lock()", "console::SERIAL.lock().unwrap()");
    probe::run(&program);
}
