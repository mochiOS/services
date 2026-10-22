#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn production_panel_preflight_uses_only_already_held_authority_of_the_original_endpoint() {
    let mut program = probe::program();
    program.push_str("const STATUS_EIO:i32=-5;const STATUS_EAGAIN:i32=-11;mod wire {\n");
    program.push_str(
        &include_str!("../../../user/crates/posix-protocol/src/status.rs")
            .replace("mnu_abi::", "crate::mnu_abi::"),
    );
    program.push_str("}\nmod error {\n");
    program.push_str(
        &probe::between(
            include_str!("../../workspace/src/error.rs"),
            "pub(crate) fn status_errno(",
            "pub(crate) fn io_errno(",
        )
        .replace(
            "mochios_posix_protocol::status::normalize_failure",
            "crate::wire::normalize_failure",
        )
        .replace("syscall::SysError", "crate::mochi_user_syscall::SysError"),
    );
    program.push_str("}\nmod protocol {\n");
    probe::constants(
        &mut program,
        include_str!("../../../user/crates/workspace-protocol/src/lib.rs"),
        &["FILE_PANEL_MODE_OPEN", "FILE_PANEL_MODE_SAVE"],
    );
    program.push_str(
        r#"
}
use std::cell::RefCell;
use std::collections::VecDeque;
thread_local! {
static ANSWERS:RefCell<VecDeque<Result<u64,SysError>>>=const{RefCell::new(VecDeque::new())};
static QUERIES:RefCell<Vec<String>>=const{RefCell::new(Vec::new())};
}
struct PendingFilePanel{mode:u16,grant_endpoint:u64,requester_process:u64}
mod platform {pub mod capability {
pub fn check_thread(endpoint:u64,capability:&str)->Result<u64,crate::SysError>{
 assert_eq!(endpoint,51,"must inspect the authenticated endpoint, not the claimed PID");
 crate::QUERIES.with_borrow_mut(|queries|queries.push(capability.to_owned()));
 crate::ANSWERS.with_borrow_mut(|answers|answers.pop_front().expect("unexpected authority query"))
}}}
"#,
    );
    program.push_str(probe::between(
        include_str!("../../workspace/src/main.rs"),
        "fn require_file_panel_authority(",
        "fn set_process_modal(",
    ));
    program.push_str(r#"
fn check(mode:u16,answers:&[Result<u64,SysError>],expected:Result<(),u64>,queries:&[&str]) {
 ANSWERS.with_borrow_mut(|queue|*queue=answers.iter().copied().collect());
 QUERIES.with_borrow_mut(Vec::clear);
 let panel=PendingFilePanel{mode,grant_endpoint:51,requester_process:999};
 assert_eq!(require_file_panel_authority(&panel),expected);
 QUERIES.with_borrow(|actual|assert_eq!(actual.iter().map(String::as_str).collect::<Vec<_>>(),queries));
 ANSWERS.with_borrow(|queue|assert!(queue.is_empty()));
}
fn main(){
 for (mode,scoped,broad) in [
  (protocol::FILE_PANEL_MODE_OPEN,"fs.read.user","fs.read.all"),
  (protocol::FILE_PANEL_MODE_SAVE,"fs.write.user","fs.write.all")
 ] {
  check(mode,&[Ok(1)],Ok(()),&[scoped]);
  check(mode,&[Ok(0),Ok(1)],Ok(()),&[scoped,broad]);
  check(mode,&[Ok(0),Ok(0)],Err(95),&[scoped,broad]);
  check(mode,&[Ok(2)],Err(5),&[scoped]);
  check(mode,&[Err(SysError::from_raw(NativeError::AccessDenied.into_raw()as i64))],Err(13),&[scoped]);
  check(mode,&[Err(SysError::from_raw(NativeError::NotFound.into_raw()as i64))],Err(2),&[scoped]);
 }
 check(0,&[],Err(22),&[]);
}
"#);
    probe::run(&program);
}

#[test]
fn selection_validation_precedes_authority_check_and_failed_checks_do_not_deliver_selection() {
    let source = include_str!("../../workspace/src/main.rs");
    assert!(!source.contains("fn grant_selected_path("));
    let complete = probe::between(
        source,
        "    fn file_panel_complete(",
        "    fn file_panel_finish(",
    );
    assert!(
        complete
            .find("sender_process == Some(pending.picker_process)")
            .unwrap()
            < complete
                .find("require_file_panel_authority(pending)?")
                .unwrap()
    );
    assert!(
        complete
            .find("validate_panel_selection(pending, result.path)")
            .unwrap()
            < complete
                .find("require_file_panel_authority(pending)?")
                .unwrap()
    );
    assert!(
        complete
            .find("require_file_panel_authority(pending)?")
            .unwrap()
            < complete.find("pending.selection_delivered = true").unwrap()
    );
    let preflight = probe::between(
        source,
        "fn require_file_panel_authority(",
        "fn set_process_modal(",
    );
    for forbidden in [
        "find_by_name",
        "CapabilityDecisionRequest",
        "new_prompt",
        "CapTransfer",
        "ipc::call",
    ] {
        assert!(!preflight.contains(forbidden));
    }
}
