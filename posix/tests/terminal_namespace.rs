use posix_service::{
    OpenedObject,
    terminal_namespace::{Backend, RIGHTS, prepare},
};
use std::collections::VecDeque;

fn object(handle: u32) -> OpenedObject<u32> {
    OpenedObject {
        handle,
        rights: RIGHTS,
    }
}
struct Fake {
    replies: VecDeque<Result<OpenedObject<u32>, i32>>,
    creation: Result<(), i32>,
    events: Vec<(Vec<u8>, Option<u32>)>,
    closed: Vec<u32>,
}
impl Backend for Fake {
    fn open_directory(
        &mut self,
        path: &[u8],
        parent: Option<OpenedObject<u32>>,
    ) -> Result<OpenedObject<u32>, i32> {
        self.events.push((path.to_vec(), parent.map(|p| p.handle)));
        self.replies.pop_front().unwrap()
    }
    fn create_directory(&mut self, parent: OpenedObject<u32>, name: &[u8]) -> Result<(), i32> {
        assert_eq!((parent.handle, name), (10, b"pts".as_slice()));
        self.creation
    }
    fn close(&mut self, handle: u32) {
        self.closed.push(handle);
    }
}
fn fake() -> Fake {
    Fake {
        replies: VecDeque::from([Ok(object(10)), Ok(object(11))]),
        creation: Ok(()),
        events: vec![],
        closed: vec![],
    }
}

#[test]
fn existing_or_new_namespace_returns_one_owned_scoped_directory_not_a_path() {
    for creation in [Ok(()), Err(-17)] {
        let mut fs = fake();
        fs.creation = creation;
        let directory = prepare(&mut fs).unwrap();
        assert_eq!((directory.handle, directory.rights), (11, RIGHTS));
        assert_eq!(
            fs.events,
            [(b"/dev".to_vec(), None), (b"pts".to_vec(), Some(10))]
        );
        assert_eq!(fs.closed, [10]);
    }
}

#[test]
fn creation_and_child_lookup_errors_close_parent_without_replacing_a_name() {
    for error in [-13, -5, -12] {
        let mut fs = fake();
        fs.creation = Err(error);
        assert_eq!(prepare(&mut fs).err(), Some(error));
        assert_eq!(fs.closed, [10]);
        assert_eq!(fs.events.len(), 1);
    }
    for error in [-20, -40, -5] {
        let mut fs = fake();
        fs.replies[1] = Err(error);
        assert_eq!(prepare(&mut fs).err(), Some(error));
        assert_eq!(fs.closed, [10]);
    }
}

#[test]
fn malformed_or_underprivileged_owned_results_are_reclaimed_without_double_close() {
    for (reply, closed, error) in [
        (object(0), vec![10], -13),
        (
            OpenedObject {
                handle: 11,
                rights: mnu_abi::HANDLE_RIGHT_TRANSFER,
            },
            vec![11, 10],
            -13,
        ),
        (object(10), vec![10], -5),
    ] {
        let mut fs = fake();
        fs.replies[1] = Ok(reply);
        assert_eq!(prepare(&mut fs).err(), Some(error));
        assert_eq!(fs.closed, closed);
    }
    let mut fs = fake();
    fs.replies[0] = Err(-9);
    assert_eq!(prepare(&mut fs).err(), Some(-9));
    assert!(fs.closed.is_empty());
    let mut fs = fake();
    fs.replies[0] = Ok(OpenedObject {
        handle: 10,
        rights: 0,
    });
    assert_eq!(prepare(&mut fs).err(), Some(-13));
    assert_eq!(fs.closed, [10]);
}

#[test]
fn native_bootstrap_releases_policy_state_before_namespace_ipc_and_ready_publication() {
    // Structural native wiring only, not proof of boot/runtime IPC behavior.
    let source = include_str!("../src/main.rs");
    let start = source
        .find("let mut service = service_state.lock().unwrap()")
        .unwrap();
    let body = &source[start..];
    let release = body.find("drop(service)").unwrap();
    let namespace = body
        .find("terminal_namespace_native::prepare(&filesystem)")
        .unwrap();
    let ready = body
        .find("service_ready::notify_handle(ready_target, 0")
        .unwrap();
    assert!(release < namespace && namespace < ready);
    assert!(body.contains("let _pty_namespace = match"));
}

#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn target_namespace_adapter_uses_scoped_attachments_and_owns_its_result() {
    // Execute the actual target adapter with controlled native boundaries,
    // not an emulation of kernel Handle transfer or endpoint identity.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let program = format!(
        r#"
#![allow(dead_code)]
extern crate self as mnu_abi;extern crate self as mochi_user_platform;
extern crate self as mochios_filesystem_protocol;extern crate self as posix_service;
#[path={:?}]mod abi;pub use abi::*;
#[path={:?}]mod wire;pub use wire::*;
#[derive(Clone,Copy)]pub struct OpenedObject<H>{{pub handle:H,pub rights:u64}}
#[path={:?}]pub mod terminal_namespace;
#[path={:?}]mod native;
thread_local!{{
 static CLOSED:std::cell::RefCell<Vec<u32>>=const{{std::cell::RefCell::new(Vec::new())}};
 static CREATION:std::cell::Cell<i32>=const{{std::cell::Cell::new(0)}};
 static CHILD:std::cell::Cell<i32>=const{{std::cell::Cell::new(0)}};
}}
pub mod ipc{{pub use crate::abi::IpcObjectHandles;}}
pub mod handle{{pub fn close(handle:u32)->Result<(),i32>{{super::CLOSED.with_borrow_mut(|v|v.push(handle));Ok(())}}}}
struct RuntimeFilesystem;
impl RuntimeFilesystem{{
 fn credential_payload(uid:u32,gid:u32,groups:&[u32],path:&[u8])->Result<Vec<u8>,i32>{{
  assert_eq!((uid,gid),(0,0));assert!(groups.is_empty());
  let mut bytes=vec![0;wire::CREDENTIALS_MAX_LEN+path.len()];
  let length=wire::encode_credentials_payload(uid,gid,groups,path,&mut bytes).unwrap();bytes.truncate(length);Ok(bytes)
 }}
 fn open_call(&self,header:wire::Header,payload:&[u8],handles:ipc::IpcObjectHandles)->Result<OpenedObject<u32>,i32>{{
  assert_eq!(header.opcode,wire::OP_OPEN_AT);assert_eq!(header.length as usize,payload.len());
  let (caller,path)=wire::decode_credentials_payload(payload).unwrap();assert_eq!((caller.effective_uid,caller.effective_gid),(0,0));
  let base=wire::OPEN_AT_READ|wire::OPEN_AT_DIRECTORY|wire::OPEN_AT_NOFOLLOW;
  let id=if path==b"/dev"{{assert_eq!(header.flags,base);assert_eq!(handles.count,0);10}}
   else{{assert_eq!(path,b"pts");assert_eq!(header.flags,base|wire::OPEN_AT_BASE_ATTACHED);assert_eq!(handles.count,1);
    assert_eq!(handles.handles[0].handle,10);assert_eq!(handles.handles[0].rights,HANDLE_RIGHT_READ|HANDLE_RIGHT_TRANSFER);
    if CHILD.get()!=0{{return Err(CHILD.get())}}11}};
  Ok(OpenedObject{{handle:id,rights:terminal_namespace::RIGHTS|HANDLE_RIGHT_SEEK}})
 }}
 fn status_call(&self,header:wire::Header,payload:&[u8],handles:ipc::IpcObjectHandles)->Result<wire::NodeStatus,i32>{{
  assert_eq!(header.opcode,wire::OP_DEVICE_NODE_CREATE);assert_eq!(header.length as usize,payload.len());
  assert_eq!(handles.count,1);assert_eq!(handles.handles[0].handle,10);assert_eq!(handles.handles[0].rights,HANDLE_RIGHT_CONTROL|HANDLE_RIGHT_TRANSFER);
  let request=wire::device_namespace::decode(header.opcode,payload).unwrap();
  assert_eq!((request.name,request.kind,request.mode,request.uid,request.gid),(b"pts".as_slice(),wire::device_namespace::KIND_DIRECTORY,0o755,0,0));
  if CREATION.get()!=0{{return Err(CREATION.get())}}
  Ok(wire::NodeStatus{{kind:wire::NODE_TYPE_DIRECTORY,..Default::default()}})
 }}
}}
fn main(){{
 for creation in [0,-17]{{CREATION.set(creation);CHILD.set(0);CLOSED.with_borrow_mut(Vec::clear);
  let directory=native::prepare(&RuntimeFilesystem).unwrap();assert_eq!((directory.object.handle,directory.object.rights),(11,terminal_namespace::RIGHTS));
  CLOSED.with_borrow(|v|assert_eq!(v,&[10]));drop(directory);CLOSED.with_borrow(|v|assert_eq!(v,&[10,11]));
 }}
 CREATION.set(-13);CLOSED.with_borrow_mut(Vec::clear);assert_eq!(native::prepare(&RuntimeFilesystem).err(),Some(-13));CLOSED.with_borrow(|v|assert_eq!(v,&[10]));
 CREATION.set(0);CHILD.set(-40);CLOSED.with_borrow_mut(Vec::clear);assert_eq!(native::prepare(&RuntimeFilesystem).err(),Some(-40));CLOSED.with_borrow(|v|assert_eq!(v,&[10]));
}}
"#,
        root.join("core/crates/abi/src/lib.rs"),
        root.join("user/crates/filesystem-protocol/src/lib.rs"),
        root.join("services/posix/src/terminal_namespace.rs"),
        root.join("services/posix/src/terminal_namespace_native.rs")
    );
    probe::run(&program);
}
