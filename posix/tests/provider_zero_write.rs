use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn empty_provider_writes_delegate_once_and_validate_the_owner_reply() {
    let source = include_str!("../../../core/src/syscall/handle.rs");
    let function = source.find("fn provider_write(").unwrap();
    let start = source[function..].find("if length == 0 {").unwrap() + function;
    let mut depth = 0;
    let mut end = None;
    for (offset, byte) in source[start..].bytes().enumerate() {
        if byte == b'{' {
            depth += 1;
        }
        if byte == b'}' {
            depth -= 1;
            if depth == 0 {
                end = Some(start + offset + 1);
                break;
            }
        }
    }
    let branch = &source[start..end.unwrap()];
    // Compile the actual kernel branch against a controlled Provider transport.
    // No socket/POSIX concepts are supplied to that branch.
    let program = format!(
        r#"
extern crate self as mnu_abi;
pub mod provider {{
pub const OP_WRITE:u16=2; pub const OP_WRITE_BOUNDED:u16=12; pub const RESPONSE_HEADER_LEN:usize=32;
pub struct RequestHeader {{pub opcode:u16,pub object_id:u64,pub argument:u64,pub basis:u64,pub length:u32,pub data_length:u32}}
pub struct ResponseHeader {{pub value:u64}}
}}
const SUCCESS:u64=0;const EIO:u64=(-5i64) as u64;
struct ProviderObject{{object_id:u64}}
thread_local!{{static MODE:std::cell::Cell<u8>=const{{std::cell::Cell::new(0)}};static CALLS:std::cell::Cell<u8>=const{{std::cell::Cell::new(0)}};}}
fn provider_call(owner:&ProviderObject,request:provider::RequestHeader,data:&[u8],reply:&mut[u8])->Result<(provider::ResponseHeader,usize),u64>{{
assert_eq!(owner.object_id,17);assert_eq!(request.object_id,17);assert_eq!(request.opcode,provider::OP_WRITE);
assert_eq!((request.argument,request.basis,request.length,request.data_length),(0,0,0,0));
assert!(data.is_empty());assert_eq!(reply.len(),provider::RESPONSE_HEADER_LEN+8);
CALLS.with(|n|n.set(n.get()+1));
match MODE.with(|m|m.get()){{
0=>Ok((provider::ResponseHeader{{value:0}},0)),1=>Ok((provider::ResponseHeader{{value:0}},8)),
2=>Ok((provider::ResponseHeader{{value:1}},0)),3=>Ok((provider::ResponseHeader{{value:0}},1)),
4=>Err((-13i64) as u64),_=>Err((-12i64) as u64)}}
}}
fn empty_write(provider:&ProviderObject,length:usize)->u64{{let byte_end:Option<u64>=None;{branch} panic!("only empty writes are tested")}}
fn main(){{for mode in 0..6{{MODE.with(|m|m.set(mode));CALLS.with(|n|n.set(0));
assert_eq!(empty_write(&ProviderObject{{object_id:17}},0),match mode{{0|1=>0,2|3=>EIO,4=>(-13i64) as u64,_=>(-12i64) as u64}});
CALLS.with(|n|assert_eq!(n.get(),1));}}}}
"#
    );
    let directory = std::env::temp_dir().join(format!(
        "mochios-provider-zero-write-{}",
        std::process::id()
    ));
    std::fs::create_dir(&directory).unwrap();
    let executable = directory.join("probe");
    let mut compile = Command::new("rustc")
        .args([
            "--edition=2021",
            "--crate-name=provider_zero_write",
            "-",
            "-o",
        ])
        .arg(&executable)
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    compile
        .stdin
        .take()
        .unwrap()
        .write_all(program.as_bytes())
        .unwrap();
    let result = compile.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(Command::new(executable).status().unwrap().success());
    std::fs::remove_dir_all(directory).unwrap();
}
