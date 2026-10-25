//! Execute retained process image metadata; no ELF/context-switch claim.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn native_c_probes_reserve_the_complete_status_record() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    for (name, source) in [
        ("status", include_str!("native_clone_cow.c")),
        ("status", include_str!("native_snapshot_create.c")),
        ("status", include_str!("native_snapshot_continuation.c")),
        ("status", include_str!("native_process_terminal_state.c")),
        ("process_status", include_str!("native_process_create.c")),
        ("process_status", include_str!("native_permission_prompt.c")),
        ("hc_status", include_str!("native_handle_capture.c")),
    ] {
        let start = source.find(&format!("struct {name} {{")).unwrap();
        let end = start + source[start..].find('}').unwrap() + 1;
        let input = format!(
            "#include <stdint.h>\n#include <stddef.h>\n{};\n\
             _Static_assert(sizeof(struct {name}) == {}, \"native status size\");\n\
             _Static_assert(offsetof(struct {name}, image_revision) == {}, \"image revision offset\");\n",
            &source[start..end],
            core::mem::size_of::<mnu_abi::ProcessStatus>(),
            core::mem::offset_of!(mnu_abi::ProcessStatus, image_revision),
        );
        let mut cc = Command::new("cc")
            .args(["-std=c11", "-x", "c", "-fsyntax-only", "-"])
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        cc.stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        let output = cc.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn retained_image_revisions_advance_only_on_commit_and_never_wrap() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let process = include_str!("../../../core/src/task/process.rs");
    let handle = include_str!("../../../core/src/syscall/handle.rs");
    let mut program = format!(
        r#"extern crate self as mnu_abi;
#[path={:?}]mod abi;pub use abi::*;
mod task {{
 #[derive(Debug,Clone,Copy)]pub struct ProcessId(u64);
 impl ProcessId{{pub fn as_u64(self)->u64{{self.0}}}}
 pub mod process {{
 use super::ProcessId;
 use std::sync::{{Arc,atomic::{{AtomicU8,AtomicU64,Ordering}}}};
"#,
        root.join("core/crates/abi/src/lib.rs"),
    );
    program.push_str(probe::between(
        process,
        "#[derive(Debug)]\npub struct ProcessObject",
        "#[derive(Clone, Copy, Debug, PartialEq, Eq)]",
    ));
    program.push_str(
        r#"
pub fn create(id:u64)->Arc<ProcessObject>{Arc::new(ProcessObject::new(ProcessId(id)))}
pub fn exit(object:&ProcessObject){object.mark_exited(0x123456789abcdef0)}
pub fn exhaust(object:&ProcessObject){object.image_revision.store(u64::MAX,Ordering::Release)}
}}
"#,
    );
    program.push_str(probe::between(
        handle,
        "fn process_status_of(",
        "fn write_process_status(",
    ));
    program.push_str(
        r#"
fn main(){
 use task::process::{create,exit,exhaust};
 let retained=create(17);let other=create(19);
 let initial=process_status_of(&retained);
 assert_eq!(initial.process_id,17);
 assert_eq!(initial.image_revision,0);assert_eq!(initial.reserved,0);
 assert_eq!(initial.state,PROCESS_STATE_RUNNING);
 assert_eq!(core::mem::size_of::<ProcessStatus>(),32);
 assert_eq!(core::mem::offset_of!(ProcessStatus,image_revision),24);
 // A fallible preparation may be abandoned without consuming a revision.
 for _ in 0..10{
  assert_eq!(retained.next_image_revision(),Some(1));
  assert_eq!(process_status_of(&retained).image_revision,0);
 }
 retained.commit_image_revision(retained.next_image_revision().unwrap());
 assert_eq!(process_status_of(&retained).image_revision,1);
 assert_eq!(process_status_of(&other).image_revision,0);
 // Same-byte replacement still constitutes a new image. No digest/path
 // equality test or client acknowledgement controls the native generation.
 retained.commit_image_revision(retained.next_image_revision().unwrap());
 assert_eq!(process_status_of(&retained).image_revision,2);
 let observer=std::sync::Arc::clone(&retained);
 let barrier=std::sync::Arc::new(std::sync::Barrier::new(2));
 let reader_barrier=barrier.clone();
 let reader=std::thread::spawn(move||{
  reader_barrier.wait();let mut previous=2;
  for _ in 0..10000{
   let current=process_status_of(&observer).image_revision;
   assert!(current>=previous);assert!(current<=10002);previous=current;
  }
 });
 barrier.wait();
 // Actual image-transition admission serializes writers; concurrent readers
 // observe only completely published scalar generations.
 for _ in 0..10000{
  let next=retained.next_image_revision().unwrap();
  retained.commit_image_revision(next);
 }
 reader.join().unwrap();assert_eq!(retained.image_revision(),10002);
 exit(&retained);let terminal=process_status_of(&retained);
 assert_eq!(terminal.image_revision,10002);
 assert_eq!(terminal.exit_code,0x123456789abcdef0);
 assert_eq!(terminal.state,PROCESS_STATE_EXITED);
 exhaust(&other);
 for _ in 0..2{
  assert_eq!(other.next_image_revision(),None);
  assert_eq!(process_status_of(&other).image_revision,u64::MAX);
 }
}
"#,
    );
    program.insert_str(0, include_str!("support/unmeasured_memory.inc"));
    probe::run(&program);
}

#[test]
fn image_revision_is_checked_before_destruction_and_published_at_commit() {
    let exec = include_str!("../../../core/src/syscall/exec.rs");
    let replacement = probe::between(
        exec,
        "fn replace_current_process_image(",
        "pub fn process_image_replace_syscall(",
    );
    let transition = replacement.find("begin_image_transition(").unwrap();
    let check = replacement.find("next_image_revision()").unwrap();
    let revoke = replacement
        .find("release_process_borrowed_mappings(pid)?")
        .unwrap();
    let root = replacement
        .find("process.set_page_table(new_pt_phys)")
        .unwrap();
    let context = replacement
        .find("process.retain_launch_context_handles_for_exec()")
        .unwrap();
    let publish = replacement
        .find(".commit_image_revision(next_image_revision)")
        .unwrap();
    let release = replacement.find("drop(transition)").unwrap();
    assert!(transition < check && check < revoke && revoke < root);
    assert!(root < context && context < publish && publish < release);
    assert_eq!(exec.matches(".commit_image_revision(").count(), 1);
    assert!(replacement[check..revoke].contains("Error::LimitExceeded.into_raw()"));
    // Native queries still resolve caller-held WAIT references; revision is
    // not a path/PID lookup or a service-specific syscall.
    let handles = include_str!("../../../core/src/syscall/handle.rs");
    let status = probe::between(handles, "fn process_status_for(", "fn process_status_of(");
    assert!(status.contains("object_native(raw, HandleRights::WAIT)"));
    assert!(status.contains("KernelObject::Process(process)"));
}
