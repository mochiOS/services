#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn empty_provider_writes_delegate_once_and_validate_the_owner_reply() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
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
#[path={abi_path:?}]mod abi;
pub use abi::*;
const SUCCESS:u64=0;
struct ProviderObject{{object_id:u64}}
thread_local!{{static MODE:std::cell::Cell<u8>=const{{std::cell::Cell::new(0)}};static CALLS:std::cell::Cell<u8>=const{{std::cell::Cell::new(0)}};static BOUND:std::cell::Cell<Option<u64>>=const{{std::cell::Cell::new(None)}};}}
fn provider_call(owner:&ProviderObject,request:provider::RequestHeader,data:&[u8],reply:&mut[u8])->Result<(provider::ResponseHeader,usize),u64>{{
let bound=BOUND.get();
assert_eq!(owner.object_id,17);assert_eq!(request.object_id,17);
assert_eq!(request.opcode,if bound.is_some(){{provider::OP_WRITE_BOUNDED}}else{{provider::OP_WRITE}});
assert_eq!((request.argument,request.basis,request.length,request.data_length),(0,bound.unwrap_or(0),0,0));
assert!(data.is_empty());assert_eq!(reply.len(),provider::RESPONSE_HEADER_LEN+8);
CALLS.with(|n|n.set(n.get()+1));
let response=|value|provider::ResponseHeader{{opcode:request.opcode,status:0,object_id:17,value,data_length:0}};
match MODE.with(|m|m.get()){{
0=>Ok((response(0),0)),1=>Ok((response(0),8)),
2=>Ok((response(1),0)),3=>Ok((response(0),1)),
4=>Err(status::Error::AccessDenied.into_raw()),5=>Err(status::Error::ResourceUnavailable.into_raw()),_=>Err((-42i64)as u64)}}
}}
fn empty_write(provider:&ProviderObject,length:usize,byte_end:Option<u64>)->u64{{{branch} panic!("only empty writes are tested")}}
fn main(){{for bound in [None,Some(0),Some(17),Some(u64::MAX)]{{for mode in 0..7{{
BOUND.set(bound);MODE.with(|m|m.set(mode));CALLS.with(|n|n.set(0));
assert_eq!(empty_write(&ProviderObject{{object_id:17}},0,bound),match mode{{
0 if bound.is_none()=>0,1=>0,0|2|3=>status::Error::BackingFailure.into_raw(),
4=>status::Error::AccessDenied.into_raw(),5=>status::Error::ResourceUnavailable.into_raw(),_=>(-42i64)as u64}});
CALLS.with(|n|assert_eq!(n.get(),1));}}}}}}
"#,
        abi_path = root.join("core/crates/abi/src/lib.rs"),
    );
    probe::run(&program);
}
