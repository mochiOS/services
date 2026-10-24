use mnu_abi::{
    HANDLE_RIGHT_CONTROL as C, HANDLE_RIGHT_DUPLICATE as D, HANDLE_RIGHT_READ as R,
    HANDLE_RIGHT_TRANSFER as T, IpcObjectHandle,
};
use posix_service::{OpenedObject, filesystem_metadata::mutate_through_provider};
use std::cell::RefCell;

#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

fn source() -> IpcObjectHandle {
    IpcObjectHandle {
        handle: 40,
        reserved: 0,
        rights: R | C | D | T,
    }
}

#[test]
fn filesystem_success_and_mutation_errors_never_query_another_owner() {
    for result in [Ok(()), Err(-13), Err(-1), Err(-5), Err(-30), Err(-28)] {
        assert_eq!(
            mutate_through_provider(
                source(),
                |object| {
                    assert_eq!(
                        object,
                        IpcObjectHandle {
                            rights: C | T,
                            ..source()
                        }
                    );
                    result
                },
                |_| panic!("not an owner rejection"),
                |_| panic!("borrowed source"),
            ),
            result
        );
    }
}

#[test]
fn owner_resolution_preserves_control_without_forwarding_data_or_duplication_rights() {
    for result in [Ok(()), Err(-13), Err(-5), Err(-9)] {
        let events = RefCell::new(Vec::new());
        assert_eq!(
            mutate_through_provider(
                source(),
                |object| {
                    assert_eq!(object.rights, C | T);
                    events.borrow_mut().push(("mutate", object.handle));
                    if object.handle == 40 { Err(-9) } else { result }
                },
                |object| {
                    assert_eq!(object.rights, C | T);
                    events.borrow_mut().push(("resolve", object.handle));
                    Ok(OpenedObject {
                        handle: 92,
                        rights: C | T,
                    })
                },
                |handle| events.borrow_mut().push(("close", handle)),
            ),
            result
        );
        assert_eq!(
            *events.borrow(),
            [
                ("mutate", 40),
                ("resolve", 40),
                ("mutate", 92),
                ("close", 92),
            ]
        );
    }
}

#[test]
fn stripped_control_or_transfer_is_rejected_before_any_operation_even_for_root() {
    for rights in [0, T, C, R | D | T, C | R | D] {
        assert_eq!(
            mutate_through_provider::<()>(
                IpcObjectHandle { rights, ..source() },
                |_| panic!("missing authority reached FS"),
                |_| panic!("missing authority reached provider"),
                |_| panic!("borrowed source"),
            ),
            Err(-13)
        );
    }
    for object in [
        IpcObjectHandle {
            handle: 0,
            ..source()
        },
        IpcObjectHandle {
            reserved: 1,
            ..source()
        },
    ] {
        assert_eq!(
            mutate_through_provider::<()>(
                object,
                |_| panic!("invalid source"),
                |_| panic!("invalid source"),
                |_| panic!("invalid source")
            ),
            Err(-13)
        );
    }
}

#[test]
fn malformed_metadata_is_closed_once_and_never_used_for_mutation() {
    for (handle, rights, expected) in [
        (0, C | T, vec![]),
        (40, C | T, vec![]),
        (92, T, vec![92]),
        (92, C | D | T, vec![92]),
        (92, C | R | T, vec![92]),
    ] {
        let mut closed = Vec::new();
        let mut attempts = 0;
        assert_eq!(
            mutate_through_provider::<()>(
                source(),
                |object| {
                    assert_eq!(object.handle, 40);
                    attempts += 1;
                    Err(-9)
                },
                |_| Ok(OpenedObject { handle, rights }),
                |handle| closed.push(handle)
            ),
            Err(-5)
        );
        assert_eq!(attempts, 1);
        assert_eq!(closed, expected);
    }
}

#[test]
fn provider_failure_preserves_original_reference_and_is_not_retried() {
    for error in [-9, -13, -32, -5] {
        assert_eq!(
            mutate_through_provider::<()>(
                source(),
                |_| Err(-9),
                |_| Err(error),
                |_| panic!("no owned result")
            ),
            Err(error)
        );
    }
}

#[test]
fn native_metadata_operations_use_the_shared_resolver_and_explicit_endpoint() {
    // Wiring check, not proof of native IPC behavior.
    let source = include_str!("../src/main.rs");
    for (start, end) in [
        ("    fn futimens(", "    fn fchmod("),
        ("    fn fchmod(", "    fn fchown("),
        ("    fn fchown(", "    fn fsync("),
    ] {
        let body = source
            .split(start)
            .nth(1)
            .unwrap()
            .split(end)
            .next()
            .unwrap();
        assert!(body.contains("self.metadata_call("));
        assert!(!body.contains("self.empty_call("));
    }
    assert!(source.contains("device_endpoint: Some(provider_endpoint_handle)"));
    let helper = source
        .split("    fn metadata_call(")
        .nth(1)
        .unwrap()
        .split("    fn open_request(")
        .next()
        .unwrap();
    assert!(helper.contains("mutate_through_provider("));
    assert!(helper.contains("query_provider_metadata("));
    assert!(!helper.contains(".lock()"));
}

#[test]
fn only_native_identity_rejection_allows_fallback_to_another_provider() {
    use mnu_abi::status::Error;
    for error in [Error::InvalidArgument,Error::AccessDenied] {
        assert_eq!(posix_service::pty_metadata_ipc::identity_error(error.into_raw() as i64),9);
    }
    for error in [Error::BackingFailure,Error::NotReady,Error::ResourceUnavailable,Error::NotFound,
        Error::PeerClosed,Error::Unsupported,Error::LimitExceeded,Error::InvalidAddress,Error::AlreadyExists,Error::InvalidFormat] {
        let raw=error.into_raw() as i64;
        assert_eq!(posix_service::pty_metadata_ipc::identity_error(raw),-mochios_posix_protocol::status::normalize_failure(raw));
        assert_ne!(posix_service::pty_metadata_ipc::identity_error(raw),9);
    }
    assert_eq!(posix_service::pty_metadata_ipc::identity_error(-5),5);
}

#[test]
fn target_metadata_adapter_executes_with_owned_cleanup_and_unchanged_request_body() {
    // Compile the actual target-only adapter against controlled transport
    // boundaries. This does not emulate kernel Handle transfer or identity.
    let mut program = String::from(
        r#"
#![allow(dead_code)]
extern crate self as posix_service;
extern crate self as mnu_abi;
extern crate self as mochi_user_platform;
extern crate self as mochios_filesystem_protocol;
const HANDLE_RIGHT_CONTROL:u64=1;const HANDLE_RIGHT_TRANSFER:u64=2;
#[derive(Clone,Copy,Debug)]struct IpcObjectHandle{handle:u32,reserved:u32,rights:u64}
struct OpenedObject<H>{handle:H,rights:u64}
struct AttachedObject<H>{handle:H,rights:u64}
#[derive(Clone,Copy,Debug,PartialEq)]struct Header{opcode:u16,mode:u32}
thread_local!{
 static CLOSED:std::cell::RefCell<Vec<u32>>=const{std::cell::RefCell::new(Vec::new())};
 static QUERIES:std::cell::Cell<u32>=const{std::cell::Cell::new(0)};
 static FIRST_ERROR:std::cell::Cell<i32>=const{std::cell::Cell::new(0)};
 static SEEN:std::cell::RefCell<Vec<u32>>=const{std::cell::RefCell::new(Vec::new())};
}
mod handle{pub fn close(handle:u32)->Result<(),i32>{super::CLOSED.with_borrow_mut(|v|v.push(handle));Ok(())}}
mod pty_metadata_ipc{
 pub fn query(endpoint:u32,object:super::IpcObjectHandle,rights:u64)->Result<super::OpenedObject<u32>,i32>{
  assert!([81,82].contains(&endpoint));assert_eq!(object.handle,40);assert_eq!(object.rights,3);assert_eq!(rights,3);
  super::SEEN.with_borrow_mut(|v|v.push(endpoint));super::QUERIES.set(super::QUERIES.get()+1);
  if endpoint==81 && super::FIRST_ERROR.get()!=0{return Err(super::FIRST_ERROR.get());}
  Ok(super::OpenedObject{handle:92,rights})
 }
}
fn controlled_file_handle(file:AttachedObject<u32>)->Result<AttachedObject<u32>,i32>{assert_eq!(file.rights,3);Ok(file)}
mod filesystem_metadata{
"#,
    );
    let resolver = include_str!("../src/filesystem_metadata.rs");
    program.push_str(probe::between(
        resolver,
        "pub fn through_provider",
        "pub fn fstat_response",
    ));
    program.push_str(r#"
}
"#);
    program.push_str(probe::between(include_str!("../src/main.rs"),"fn query_provider_metadata(","#[cfg"));
    program.push_str(r#"
struct RuntimeFilesystem{device_endpoint:Option<u32>,fifo_endpoint:Option<u32>,result:Result<(),i32>,calls:Vec<u32>}
impl RuntimeFilesystem{
 fn empty_call(&mut self,header:Header,payload:&[u8],file:AttachedObject<u32>)->Result<(),i32>{
  assert_eq!(header,Header{opcode:18,mode:0o620});assert_eq!(payload,b"stored credentials");
  self.calls.push(file.handle);if file.handle==40{Err(-9)}else{assert_eq!(file.handle,92);self.result}
 }
"#);
    program.push_str(probe::between(
        include_str!("../src/main.rs"),
        "    fn metadata_call(",
        "    fn open_request(",
    ));
    program.push_str(r#"
}
fn main(){
 for result in [Ok(()),Err(-13),Err(-5)]{
  CLOSED.with_borrow_mut(Vec::clear);QUERIES.set(0);
  let mut fs=RuntimeFilesystem{device_endpoint:Some(81),fifo_endpoint:None,result,calls:Vec::new()};
  assert_eq!(fs.metadata_call(AttachedObject{handle:40,rights:7},Header{opcode:18,mode:0o620},b"stored credentials"),result);
  assert_eq!(fs.calls,[40,92]);assert_eq!(QUERIES.get(),1);CLOSED.with_borrow(|v|assert_eq!(v,&[92]));
 }
 let mut fs=RuntimeFilesystem{device_endpoint:None,fifo_endpoint:None,result:Ok(()),calls:Vec::new()};
 assert_eq!(fs.metadata_call(AttachedObject{handle:40,rights:3},Header{opcode:18,mode:0o620},b"stored credentials"),Err(-9));
 assert_eq!(fs.calls,[40]);
 for error in [-9,-13,-5] {
  CLOSED.with_borrow_mut(Vec::clear);SEEN.with_borrow_mut(Vec::clear);FIRST_ERROR.set(error);
  let mut fs=RuntimeFilesystem{device_endpoint:Some(81),fifo_endpoint:Some(82),result:Ok(()),calls:Vec::new()};
  let result=fs.metadata_call(AttachedObject{handle:40,rights:3},Header{opcode:18,mode:0o620},b"stored credentials");
  if error==-9 {
   assert_eq!(result,Ok(()));SEEN.with_borrow(|v|assert_eq!(v,&[81,82]));CLOSED.with_borrow(|v|assert_eq!(v,&[92]));
  } else {
   assert_eq!(result,Err(error));SEEN.with_borrow(|v|assert_eq!(v,&[81]));CLOSED.with_borrow(|v|assert!(v.is_empty()));
  }
 }
}
"#);
    probe::run(&program);
}
