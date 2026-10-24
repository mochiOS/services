#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn opened_terminal_files_keep_distinct_data_and_metadata_classification_across_handoff() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let mut program = format!(
        r#"
#![allow(dead_code,non_camel_case_types)]
extern crate self as mnu_abi;
#[path={:?}]mod abi;pub use abi::*;pub use abi::status;
#[path={:?}]mod posix_protocol;pub use posix_protocol::*;
type c_int=i32;const ENOTTY:i32=25;const EIO:i32=5;
mod syscall{{pub use mnu_abi::{{HANDLE_RIGHT_READ,HANDLE_RIGHT_WRITE}};}}
#[derive(Clone,Copy)]struct ObjectHandleAttachment<H>{{handle:H,rights:u64}}
thread_local!{{
 static ERROR:std::cell::Cell<i32>=const{{std::cell::Cell::new(0)}};
 static QUERIES:std::cell::Cell<u32>=const{{std::cell::Cell::new(0)}};
}}
"#,
        root.join("core/crates/abi/src/lib.rs"),
        root.join("user/crates/posix-protocol/src/lib.rs")
    );
    program.push_str(probe::between(
        source,
        "#[derive(Clone, Copy, PartialEq, Eq)]\n#[repr(u8)]\nenum FdKind",
        "#[derive(Clone, Copy, PartialEq, Eq)]\nstruct FdObject",
    ));
    program.push_str(probe::between(
        source,
        "fn inherited_fd_kind(",
        "#[repr(C)]\n#[derive(Clone, Copy)]\nstruct NewlibTimespec",
    ));
    program.push_str(r#"
fn object_entry(handle:u64,rights:u64,kind:FdKind,flags:i32)->(u64,u64,FdKind,i32){(handle,rights,kind,flags)}
fn terminal_attributes(entry:(u64,u64,FdKind,i32))->Result<(),i32>{
 assert_eq!((entry.0,entry.1,entry.3),(41,0x1234,0));assert!(entry.2==FdKind::ObjectSpecial);
 QUERIES.set(QUERIES.get()+1);if ERROR.get()==0{Ok(())}else{Err(ERROR.get())}
}
"#);
    program.push_str(&format!(
        "#[path={:?}]mod file_kind;\n",
        root.join("user/crates/newlib-runtime/src/file_kind.rs")
    ));
    program.push_str(r#"
fn main(){
 let object=ObjectHandleAttachment{handle:41,rights:0x1234};
 for (mode,kind) in [(0o100600,FdKind::ObjectFile),(0o040700,FdKind::ObjectDirectory)]{
  QUERIES.set(0);assert!(file_kind::opened(object,mode).unwrap()==kind);assert_eq!(QUERIES.get(),0);
 }
 for rights in [HANDLE_RIGHT_READ,HANDLE_RIGHT_WRITE]{assert!(file_kind::opened(ObjectHandleAttachment{handle:41,rights},0o010600)==Ok(FdKind::ObjectFifo));}
 for rights in [0,HANDLE_RIGHT_READ|HANDLE_RIGHT_WRITE]{assert!(file_kind::opened(ObjectHandleAttachment{handle:41,rights},0o010600)==Err(EIO));}
 for (error,kind) in [(0,FdKind::ObjectTerminalFile),(25,FdKind::ObjectSpecial)]{
  ERROR.set(error);QUERIES.set(0);let result=file_kind::opened(object,0o020600).unwrap();assert!(result==kind);assert_eq!(QUERIES.get(),1);
 }
 for error in [13,5,9,32,75]{ERROR.set(error);assert!(file_kind::opened(object,0o020600)==Err(error));}
 let wire=inherited_fd_kind(FdKind::ObjectTerminalFile).unwrap();assert_eq!(wire,INHERITED_FD_KIND_TERMINAL_FILE);
 assert_eq!(inherited_fd_kind_requires_handle(wire),Some(true));
 for flags in [0,1,2,0x4000] {for descriptor_flags in [0,INHERITED_FD_DESCRIPTOR_CLOEXEC]{
  let metadata=InheritedFdMetadata{kind:wire,open_flags:flags,descriptor_flags};
  let encoded=encode_inherited_fd_metadata(metadata).unwrap();let decoded=decode_inherited_fd_metadata(encoded).unwrap();
  assert_eq!(metadata,decoded);assert!(fd_kind_from_inherited(decoded.kind)==Some(FdKind::ObjectTerminalFile));
 }}
 assert!(encode_inherited_fd_metadata(InheritedFdMetadata{kind:17,open_flags:0,descriptor_flags:0}).is_none());
}
"#);
    probe::run(&program);
}

#[test]
fn terminal_file_dispatch_uses_native_io_but_inode_metadata_and_tracked_open_ownership() {
    // Native-adapter wiring only; actual IPC/VMIN/VTIME integration requires OS tests.
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let read = probe::between(source, "fn syscall_read(", "\n#[unsafe(no_mangle)]");
    let terminal = read
        .split("FdKind::ObjectPty | FdKind::ObjectTerminalFile =>")
        .nth(1)
        .unwrap()
        .split("}")
        .next()
        .unwrap();
    assert!(terminal.contains("return terminal_read::read("));
    let write = probe::between(source, "fn syscall_write(", "fn syscall_read(");
    assert!(write.contains("FdKind::ObjectPty | FdKind::ObjectTerminalFile => loop"));
    assert!(write.contains("wait_for_handle("));
    let mutation = include_str!("../../../user/crates/newlib-runtime/src/file_mutation.rs");
    assert!(
        mutation.find("source.opened = Some(opened)").unwrap()
            < mutation.find("file_kind::opened(").unwrap()
    );
    for name in ["fchmod", "fchown", "_fstat"] {
        let marker = format!("fn {name}(");
        let body = source
            .split(&marker)
            .nth(1)
            .unwrap()
            .split("\n}\n")
            .next()
            .unwrap();
        assert!(body.contains("FdKind::ObjectTerminalFile"), "{name}");
        assert!(body.contains("posix_client()"), "{name}");
    }
    let time = include_str!("../../../user/crates/newlib-runtime/src/file_time.rs");
    assert!(time.contains("FdKind::ObjectTerminalFile"));
    assert!(time.contains(".futimens("));
}
