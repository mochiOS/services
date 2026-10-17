use mnu_abi::provider as wire;
use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn bounded_provider_wire_requires_position_and_preserves_generic_bound_status() {
    let request = wire::RequestHeader {
        opcode: wire::OP_WRITE_BOUNDED,
        object_id: 17,
        argument: 0,
        basis: 5,
        length: 3,
        data_length: 3,
    };
    let mut bytes = [0; wire::REQUEST_HEADER_LEN + 3];
    request.encode(b"abc", &mut bytes).unwrap();
    assert_eq!(
        wire::RequestHeader::decode(&bytes),
        Ok((request, &b"abc"[..]))
    );
    let mut output = [0; wire::RESPONSE_HEADER_LEN + 8];
    let reply = wire::ResponseHeader {
        opcode: request.opcode,
        object_id: 17,
        status: 0,
        value: 2,
        data_length: 8,
    };
    assert_eq!(
        reply.encode(&3u64.to_le_bytes(), &mut output),
        Ok(output.len())
    );
    assert!(
        wire::ResponseHeader {
            data_length: 0,
            ..reply
        }
        .encode(&[], &mut output)
        .is_err()
    );
    assert!(
        wire::ResponseHeader {
            value: wire::MAX_DATA_LEN as u64 + 1,
            ..reply
        }
        .encode(&[0; 8], &mut output)
        .is_err()
    );
    let denied = wire::ResponseHeader {
        status: wire::STATUS_BOUND_REACHED,
        value: 0,
        data_length: 0,
        ..reply
    };
    let length = denied.encode(&[], &mut output).unwrap();
    assert_eq!(
        wire::ResponseHeader::decode(&output[..length]),
        Ok((denied, &[][..]))
    );
    assert_eq!(mnu_abi::SyscallNumber::HandleWriteBounded as u64, 694);
}

fn function<'a>(source: &'a str, name: &str) -> &'a str {
    let start = source.find(name).unwrap();
    let body = start + source[start..].find('{').unwrap();
    let mut depth = 0;
    for (offset, byte) in source.as_bytes()[body..].iter().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return &source[start..=body + offset];
                }
            }
            _ => {}
        }
    }
    panic!("unterminated function");
}

#[test]
fn actual_kernel_write_loop_checks_bounds_partial_progress_and_copy_lock_order() {
    let source = include_str!("../../../core/src/syscall/handle.rs");
    let implementation = function(source, "fn provider_write_impl(");
    let native_status = include_str!("../../../core/crates/abi/src/status.rs");
    let native_storage = include_str!("../../../core/src/util/object_snapshot.rs");
    let program = format!(
        r#"
extern crate alloc;
extern crate self as mnu_abi;
pub mod status {{ {native_status} }}
pub mod util {{pub mod object_snapshot {{ {native_storage} }}}}
use std::sync::{{Mutex,atomic::{{AtomicBool,AtomicUsize,Ordering}}}};
static ALLOCATION:AtomicUsize=AtomicUsize::new(usize::MAX);
struct Allocator;
unsafe impl std::alloc::GlobalAlloc for Allocator{{
unsafe fn alloc(&self,l:std::alloc::Layout)->*mut u8{{
let remaining=ALLOCATION.load(Ordering::Relaxed);
if remaining==0{{return std::ptr::null_mut();}}
if remaining!=usize::MAX{{ALLOCATION.store(remaining-1,Ordering::Relaxed);}}
unsafe{{std::alloc::System.alloc(l)}}
}}
unsafe fn dealloc(&self,p:*mut u8,l:std::alloc::Layout){{unsafe{{std::alloc::System.dealloc(p,l)}}}}
}}
#[global_allocator]static ALLOCATOR:Allocator=Allocator;
pub mod provider {{
pub const OP_WRITE:u16=2; pub const OP_WRITE_BOUNDED:u16=12;
pub const MAX_DATA_LEN:usize=4096; pub const RESPONSE_HEADER_LEN:usize=40;
pub const STATUS_BOUND_REACHED:i64=-4094;
pub struct RequestHeader {{pub opcode:u16,pub object_id:u64,pub argument:i64,pub basis:u64,pub length:u32,pub data_length:u32}}
pub struct ResponseHeader {{pub value:u64}}
}}
const SUCCESS:u64=0; const EIO:u64=(-5i64) as u64; const EINVAL:u64=(-22i64) as u64;
struct ProviderObject {{object_id:u64}}
struct State {{mode:u8,position:u64,calls:usize,copies:usize,updated:usize}}
static STATE:Mutex<State>=Mutex::new(State{{mode:0,position:0,calls:0,copies:0,updated:0}});
static LOCKED:AtomicBool=AtomicBool::new(false);
fn provider_cache_identity(_: &ProviderObject)->Result<Option<u64>,u64>{{Ok(Some(77))}}
pub mod mem {{pub mod vm_object {{
use super::super::*;
pub struct Guard;
impl Drop for Guard {{fn drop(&mut self){{assert!(LOCKED.swap(false,Ordering::SeqCst));}}}}
pub fn lock_provider_io(_: &ProviderObject,identity:u64)->Result<Guard,status::Error>{{
assert_eq!(identity,77);let s=STATE.lock().unwrap();
if s.mode==8 || (s.mode==9 && s.calls==1){{return Err(status::Error::ResourceUnavailable)}}
drop(s);assert!(!LOCKED.swap(true,Ordering::SeqCst));Ok(Guard)}}
pub fn update_provider_range(_: &Guard,_start:u64,bytes:&[u8]){{
assert!(LOCKED.load(Ordering::SeqCst));STATE.lock().unwrap().updated+=bytes.len();
}}
}}}}
pub mod syscall {{use super::*;
pub fn copy_from_user_native(address:u64,bytes:&mut[u8])->Result<(),status::Error>{{
assert!(!LOCKED.load(Ordering::SeqCst)); let mut s=STATE.lock().unwrap();s.copies+=1;
if s.mode==6 && address>=4096 {{return Err(status::Error::InvalidAddress)}}
bytes.fill(0x7a);Ok(())
}}
}}
fn provider_call(owner:&ProviderObject,request:provider::RequestHeader,data:&[u8],reply:&mut[u8])->Result<(provider::ResponseHeader,usize),u64>{{
assert_eq!(owner.object_id,17);assert_eq!(request.object_id,17);assert_eq!(request.argument,0);
assert_eq!((request.length as usize,request.data_length as usize),(data.len(),data.len()));
assert!(data.len()<=4096);if !data.is_empty(){{assert!(LOCKED.load(Ordering::SeqCst));}}
let mut s=STATE.lock().unwrap();s.calls+=1;
if s.mode==7 || (s.mode==3 && s.calls==2){{return Err(EIO)}}
let mut count=data.len();let mut start=s.position;
if !data.is_empty() && request.opcode==provider::OP_WRITE_BOUNDED {{
if start>=request.basis{{return Err(provider::STATUS_BOUND_REACHED as u64)}}
count=count.min((request.basis-start) as usize);
}}
match s.mode{{1=>start=request.basis,2=>start=u64::MAX-1,4=>count=data.len()+1,_=>{{}}}}
reply[provider::RESPONSE_HEADER_LEN..].copy_from_slice(&start.to_le_bytes());
s.position=s.position.saturating_add(count as u64);
Ok((provider::ResponseHeader{{value:count as u64}},if s.mode==5{{0}}else{{8}}))
}}
{implementation}
fn reset(mode:u8,position:u64){{assert!(!LOCKED.load(Ordering::SeqCst));*STATE.lock().unwrap()=State{{mode,position,calls:0,copies:0,updated:0}};}}
fn run(length:u64,end:Option<u64>)->u64{{provider_write_impl(&ProviderObject{{object_id:17}},0,length,end)}}
fn main(){{
reset(0,0);assert_eq!(run(8192,Some(4096)),4096);
{{let s=STATE.lock().unwrap();assert_eq!((s.calls,s.copies,s.updated),(1,1,4096));}}
assert_eq!(run(1,Some(4096)),provider::STATUS_BOUND_REACHED as u64);
reset(0,3);assert_eq!(run(7,Some(5)),2);assert_eq!(STATE.lock().unwrap().updated,2);
reset(0,99);assert_eq!(run(0,Some(0)),0);
{{let s=STATE.lock().unwrap();assert_eq!((s.calls,s.copies,s.updated),(1,0,0));}}
for mode in [1,2,4,5]{{reset(mode,0);assert_eq!(run(4,Some(5)),status::Error::BackingFailure.into_raw());assert_eq!(STATE.lock().unwrap().updated,0);}}
reset(7,0);assert_eq!(run(4,Some(5)),EIO);
for mode in [3,6]{{reset(mode,0);assert_eq!(run(8192,Some(10000)),4096);assert_eq!(STATE.lock().unwrap().updated,4096);}}
reset(0,0);assert_eq!(run(5,None),5);assert_eq!(STATE.lock().unwrap().updated,5);
reset(8,0);assert_eq!(run(8192,None),status::Error::ResourceUnavailable.into_raw());
{{let s=STATE.lock().unwrap();assert_eq!((s.calls,s.updated),(0,0));}}
reset(9,0);assert_eq!(run(8192,None),4096);
{{let s=STATE.lock().unwrap();assert_eq!((s.calls,s.updated),(1,4096));}}
for allocation in [0,1]{{
reset(0,0);ALLOCATION.store(allocation,Ordering::Relaxed);let result=run(5,None);
ALLOCATION.store(usize::MAX,Ordering::Relaxed);
assert_eq!(result,status::Error::ResourceUnavailable.into_raw());
let s=STATE.lock().unwrap();assert_eq!((s.calls,s.copies,s.updated),(0,0,0));
}}
reset(0,0);assert_eq!(run(u64::MAX,None),status::Error::LimitExceeded.into_raw());
assert_eq!(STATE.lock().unwrap().calls,0);
}}
"#
    );
    let directory =
        std::env::temp_dir().join(format!("mochios-bounded-write-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let executable = directory.join("probe");
    let mut compiler = Command::new("rustc")
        .args([
            "--edition=2021",
            "--crate-name=bounded_write_probe",
            "-",
            "-o",
        ])
        .arg(&executable)
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
    assert!(Command::new(executable).status().unwrap().success());
    std::fs::remove_dir_all(directory).unwrap();
}
