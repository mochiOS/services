#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn production_clock_adapter_validates_native_results_and_never_uses_errno_as_native_status() {
    let abi = include_str!("../../../core/crates/abi/src/lib.rs");
    let mut program = String::from("#![allow(dead_code)]\nmod mnu_abi { pub mod status {\n");
    program.push_str(include_str!("../../../core/crates/abi/src/status.rs"));
    program.push_str("}\n");
    program.push_str(probe::between(
        abi,
        "/// Kernel-provided clocks.",
        "/// Smallest representable increment of a native clock",
    ));
    program.push_str("}\nmod ext4plus { pub mod inode {\n");
    program.push_str(probe::between(
        include_str!("../../third_party/ext4plus/src/inode_timestamps.rs"),
        "/// Seconds relative to the Unix epoch",
        "/// Failure before any timestamp fields",
    ));
    program.push_str("}}\nmod mochi_user_platform { pub mod syscall {\npub use crate::mnu_abi::status::Error as NativeError;\n");
    program.push_str(probe::between(
        include_str!("../../../user/crates/syscall/src/lib.rs"),
        "#[derive(Clone, Copy, Debug, PartialEq, Eq)]\npub struct SysError",
        "#[derive(Clone, Copy, Debug, PartialEq, Eq)]\npub struct RawSyscallResult",
    ));
    program.push_str(r#"
#[derive(Debug,PartialEq)]pub enum SyscallNumber {ClockRead}
pub fn call2(number:SyscallNumber,clock:u64,output:u64)->SysResult<u64>{
assert_eq!(number,SyscallNumber::ClockRead);
assert_eq!(clock,crate::mnu_abi::ClockId::Realtime as u64);
let mut state=crate::STATE.lock().unwrap();state.2+=1;
if let Some(error)=state.1 {return Err(SysError::from_raw(error as i64));}
assert_ne!(output,0);
unsafe{(output as *mut crate::mnu_abi::ClockInstant).write(state.0);}
Ok(0)
}
}}
use mnu_abi::ClockInstant;
static STATE:std::sync::Mutex<(ClockInstant,Option<u64>,usize)>=std::sync::Mutex::new((ClockInstant{seconds:0,nanoseconds:0,reserved:0},None,0));
"#);
    program.push_str(probe::between(
        include_str!("../../filesystem/src/main.rs"),
        "fn realtime_timestamp()",
        "#[cfg(target_os = \"mochios\")]\nfn decode_single_open",
    ));
    program.push_str(r#"
fn call(instant:ClockInstant,error:Option<u64>)->Result<ext4plus::inode::InodeTimestamp,i32>{
*STATE.lock().unwrap()=(instant,error,0);
let result=realtime_timestamp();assert_eq!(STATE.lock().unwrap().2,1);result
}
fn main(){
let valid=ClockInstant{seconds:2147483648,nanoseconds:999999999,reserved:0};
assert_eq!(call(valid,None).unwrap(),ext4plus::inode::InodeTimestamp{seconds:2147483648,nanoseconds:999999999});
for (error,expected) in [
(mnu_abi::status::Error::AccessDenied.into_raw(),13),
(mnu_abi::status::Error::NotReady.into_raw(),11),
(mnu_abi::status::Error::BackingFailure.into_raw(),5),
((-13i64)as u64,5),
((-75i64)as u64,5),
]{assert_eq!(call(valid,Some(error)),Err(expected));}
assert_eq!(call(ClockInstant{reserved:1,..valid},None),Err(5));
assert_eq!(call(ClockInstant{nanoseconds:1000000000,..valid},None),Err(5));
assert_eq!(call(ClockInstant{seconds:u64::MAX,..valid},None),Err(75));
}
"#);
    probe::run(&program);
    let manifest = include_str!("../../filesystem/manifest.toml");
    assert!(manifest.contains("\"system.time.read\""));
}
