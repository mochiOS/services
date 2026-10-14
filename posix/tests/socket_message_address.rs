use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn runtime_address_wrappers_preserve_io_results_and_output_ownership() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/socket.rs");
    let start = source
        .find("#[unsafe(no_mangle)]\npub extern \"C\" fn sendto(")
        .unwrap();
    let mut program = String::from(
        r#"
use std::{ffi::c_void, ptr};
type c_int = i32;
const EFAULT:i32=14;
mod mochios_posix_client {pub mod socket {pub const MAX_SOCKADDR_LEN:usize=110;}}
static mut ERRNO:i32=0;
static mut CALLS:usize=0;
static mut RESULT:isize=3;
static mut QUERY_ERROR:i32=0;
static mut EXPECT_SENDING:bool=false;
fn pthread_testcancel() {}
fn result_with_errno(result:Result<isize,i32>,failure:isize)->isize {
 match result {Ok(value)=>value,Err(error)=>{unsafe{ERRNO=error;}failure}}
}
fn transfer(fd:i32,buffer:*const c_void,length:usize,flags:i32,sending:bool)->isize {
 unsafe {
  CALLS+=1;assert_eq!(fd,7);assert_eq!(buffer as usize,0x1234);
  assert_eq!((length,flags),(8,0x102));assert_eq!(sending,{EXPECT_SENDING});
  if RESULT<0 {ERRNO=11;} RESULT
 }
}
fn send(fd:i32,buffer:*const c_void,length:usize,flags:i32)->isize {transfer(fd,buffer,length,flags,true)}
fn recv(fd:i32,buffer:*mut c_void,length:usize,flags:i32)->isize {transfer(fd,buffer,length,flags,false)}
unsafe fn socket_name(fd:i32,address:*mut c_void,length:*mut u32,peer:bool)->Result<i32,i32> {
 assert_eq!(fd,7);assert!(peer);
 unsafe {
  if QUERY_ERROR!=0 {return Err(QUERY_ERROR);}
  assert!(*length>=6);ptr::copy_nonoverlapping(b"source".as_ptr(),address.cast(),6);*length=6;
 }
 Ok(0)
}
"#,
    );
    program.push_str(&source[start..]);
    program.push_str(r#"
fn main(){unsafe {
 let buffer=0x1234 as *mut c_void;
 EXPECT_SENDING=true;
 // An ignored stream destination must never be dereferenced or resolved.
 for destination in [ptr::null(),1 as *const c_void] {
  assert_eq!(sendto(7,buffer,8,0x102,destination,u32::MAX),3);
 }
 RESULT=-1;assert_eq!(sendto(7,buffer,8,0x102,ptr::null(),0),-1);assert_eq!({ERRNO},11);
 EXPECT_SENDING=false;RESULT=3;
 // Null source address ignores even an unusable length pointer.
 assert_eq!(recvfrom(7,buffer,8,0x102,ptr::null_mut(),1 as *mut u32),3);
 let mut address=[0x55u8;12];let mut length=12u32;
 let calls=CALLS;
 assert_eq!(recvfrom(7,buffer,8,0x102,address.as_mut_ptr().cast(),ptr::null_mut()),-1);
 assert_eq!({ERRNO},EFAULT);assert_eq!({CALLS},calls);
 // Metadata failure must not consume data or modify caller outputs.
 QUERY_ERROR=107;
 assert_eq!(recvfrom(7,buffer,8,0x102,address.as_mut_ptr().cast(),&mut length),-1);
 assert_eq!({ERRNO},107);assert_eq!({CALLS},calls);assert_eq!(length,12);assert_eq!(address,[0x55;12]);
 QUERY_ERROR=0;
 // Data failure also leaves the address and supplied capacity unchanged.
 RESULT=-1;
 assert_eq!(recvfrom(7,buffer,8,0x102,address.as_mut_ptr().cast(),&mut length),-1);
 assert_eq!({ERRNO},11);assert_eq!(length,12);assert_eq!(address,[0x55;12]);
 for result in [0,3,8] {for capacity in [0u32,2,6,12] {
  RESULT=result;address.fill(0x55);length=capacity;
  assert_eq!(recvfrom(7,buffer,8,0x102,address.as_mut_ptr().cast(),&mut length),result);
  assert_eq!(length,6);
  let copied=(capacity as usize).min(6);
  assert_eq!(&address[..copied],&b"source"[..copied]);
  assert!(address[copied..].iter().all(|byte|*byte==0x55));
 }}
}}
"#);
    let directory = std::env::temp_dir().join(format!(
        "mochios-socket-address-{}-{}",
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
    let compiled = compiler.wait_with_output().unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let executed = Command::new(&binary).output().unwrap();
    std::fs::remove_dir_all(directory).unwrap();
    assert!(
        executed.status.success(),
        "{}",
        String::from_utf8_lossy(&executed.stderr)
    );
}
