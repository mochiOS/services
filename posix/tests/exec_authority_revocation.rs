//! Production permit consumption and late validation with controlled native
//! authority storage; this does not replace a real scheduler/IPC test.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn one_shot_replacement_permits_cannot_restore_revoked_native_authority() {
    let process = include_str!("../../../core/src/task/process.rs");
    let exec = include_str!("../../../core/src/syscall/exec.rs");
    let mut program = String::from(
        r#"
extern crate self as mnu_abi;
#[derive(Debug,PartialEq,Eq)]pub enum Error{NotReady,AccessDenied,LimitExceeded}
pub mod status{pub use super::Error;}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]struct Grants(u8);
impl Grants{fn is_empty(&self)->bool{self.0==0}fn is_subset_of(&self,held:&Self)->bool{(0..8).all(|bit|self.0&(1<<bit)==0 || held.0&(1<<bit)!=0)}}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]enum PendingExecKind{ImageReplace,ImageInstall{image_revision:u64},Spawn,SpawnInherit}
#[derive(Clone,Debug)]struct PendingExecSecurity{identity:u8,executable_digest:[u8;32],path:String,authorized_thread:u64,capabilities:Grants,kernel_authorities:Grants,kind:PendingExecKind,authority_revision:u64}
#[derive(Clone)]struct Process{application_identity:Option<u8>,image_digest:Option<[u8;32]>,pending_exec_security:Option<PendingExecSecurity>,capabilities:Grants,kernel_authorities:Grants,exec_authority_revision:u64,image_revision:u64}
struct ProcessObject(u64);impl ProcessObject{fn image_revision(&self)->u64{self.0}}
type CapabilitySet=Grants;type KernelAuthoritySet=Grants;
mod task{
 pub type ThreadId=u64;pub type ProcessId=u64;
 pub mod process{pub(crate) use crate::PendingExecSecurity;}
 thread_local!{pub static CURRENT:std::cell::RefCell<Option<crate::Process>>=const{std::cell::RefCell::new(None)};}
 pub fn with_process<T>(pid:u64,operation:impl FnOnce(&crate::Process)->T)->Option<T>{assert_eq!(pid,7);CURRENT.with_borrow(|p|p.as_ref().map(operation))}
}
impl Process{
 fn process_object(&self)->ProcessObject{ProcessObject(self.image_revision)}
"#,
    );
    program.push_str(probe::between(
        process,
        "    pub(crate) fn authorize_next_exec(",
        "    /// A replacement may attenuate",
    ));
    program.push_str(probe::between(
        process,
        "    pub(crate) fn capabilities_mut(",
        "    /// プロセス名を取得",
    ));
    program.push_str(probe::between(
        process,
        "    pub(crate) fn permits_image_authorization(",
        "    /// サービスID",
    ));
    program.push_str("}\n");
    program.push_str(probe::between(
        exec,
        "fn check_image_authorization(",
        "fn replace_current_process_image(",
    ));
    program.push_str(r#"
fn permit(caps:u8,authority:u8,kind:PendingExecKind)->PendingExecSecurity{PendingExecSecurity{identity:9,executable_digest:[7;32],path:"opaque-image-key".into(),authorized_thread:11,capabilities:Grants(caps),kernel_authorities:Grants(authority),kind,authority_revision:1}}
fn process(caps:u8,authority:u8,permit:PendingExecSecurity)->Process{Process{application_identity:Some(9),image_digest:Some([7;32]),capabilities:Grants(caps),kernel_authorities:Grants(authority),pending_exec_security:Some(permit),exec_authority_revision:1,image_revision:1}}
fn mutate(p:&mut Process, operation:u8) {match operation {
  0 => { *p.capabilities_mut()=Grants(0); *p.capabilities_mut()=Grants(7); }
  1 => { *p.kernel_authorities_mut()=Grants(0); *p.kernel_authorities_mut()=Grants(7); }
  2 => p.set_capabilities_for_exec(Grants(7)),
  _ => p.set_kernel_authorities_for_exec(Grants(7)),
 }}
fn main(){
 for measured in [false,true] {
  let mut p=process(0,0,permit(7,0,PendingExecKind::ImageInstall{image_revision:0}));
  p.image_revision=0;if !measured {p.image_digest=None;}
  assert_eq!(p.take_exec_authorization("opaque-image-key",11).is_some(),measured);
  assert_eq!(p.capabilities,Grants(0));assert_eq!(p.kernel_authorities,Grants(0));
 }
 for held in 0..8 {for desired in 0..8 {for revision in [0,1,2] {for native_desired in 0..8 {
  let mut p=process(held,7,permit(desired,native_desired,PendingExecKind::ImageInstall{image_revision:revision}));
  let expected=revision==1 && native_desired==0;
  assert_eq!(p.permits_image_authorization(p.pending_exec_security.as_ref().unwrap()),expected);
  assert_eq!(p.take_exec_authorization("opaque-image-key",11).is_some(),expected);
  assert!(p.pending_exec_security.is_none());
  assert_eq!(p.capabilities,Grants(held));assert_eq!(p.kernel_authorities,Grants(7));
 }}}}
 for kind in [PendingExecKind::ImageReplace,PendingExecKind::SpawnInherit] {
 for held in 0..8 {for desired in 0..8 {for native_held in 0..8 {for native_desired in 0..8 {
  let expected=(desired&!held)==0 && (native_desired&!native_held)==0;
  let mut p=process(held,native_held,permit(desired,native_desired,kind));
  assert_eq!(if kind==PendingExecKind::SpawnInherit {p.permits_inherited_spawn_authorization(p.pending_exec_security.as_ref().unwrap())}else{p.permits_image_authorization(p.pending_exec_security.as_ref().unwrap())},expected);
  assert_eq!(p.take_exec_authorization("opaque-image-key",11).is_some(),expected);
  assert!(p.pending_exec_security.is_none());
 }}}}}
 for (caps,authority) in [(0,1),(1,0)]{
  let mut p=process(1,1,permit(1,1,PendingExecKind::ImageReplace));
  assert!(p.take_exec_authorization("different",11).is_none());assert!(p.pending_exec_security.is_some());
  assert!(p.take_exec_authorization("opaque-image-key",12).is_none());assert!(p.pending_exec_security.is_some());
  p.capabilities=Grants(caps);p.kernel_authorities=Grants(authority);
  assert!(p.take_exec_authorization("opaque-image-key",11).is_none());
  p.capabilities=Grants(1);p.kernel_authorities=Grants(1);
  assert!(p.take_exec_authorization("opaque-image-key",11).is_none());
 }
 // Explicit installation has the same revocation and late-image checks;
 // consuming the permit grants nothing to the currently running image.
 for operation in 0..4 {
  let kind=PendingExecKind::ImageInstall{image_revision:1};
  let mut p=process(0,0,permit(7,0,kind));
  p.authorize_next_exec(permit(7,0,kind)).unwrap();
  let authorization=p.take_exec_authorization("opaque-image-key",11).unwrap();
  assert_eq!(p.capabilities,Grants(0));assert_eq!(p.kernel_authorities,Grants(0));
  mutate(&mut p,operation);
  assert!(!p.permits_image_authorization(&authorization));
 }
 for current_revision in [0,2,u64::MAX] {
  let mut p=process(0,0,permit(7,0,PendingExecKind::ImageInstall{image_revision:1}));
  let authorization=p.take_exec_authorization("opaque-image-key",11).unwrap();
  p.image_revision=current_revision;
  task::CURRENT.with_borrow_mut(|slot|*slot=Some(p));
  assert_eq!(check_image_authorization(7,&authorization),Err(Error::AccessDenied));
 }
 // Successful consumption is not the last check: a sibling can revoke while
 // image bytes/VM are prepared. The late check uses the then-current state.
 for (caps,authority,expected) in [(1,1,Ok(())),(0,1,Err(Error::AccessDenied)),(1,0,Err(Error::AccessDenied))]{
  let mut p=process(1,1,permit(1,1,PendingExecKind::ImageReplace));
  let authorization=p.take_exec_authorization("opaque-image-key",11).unwrap();
  p.capabilities=Grants(caps);p.kernel_authorities=Grants(authority);
  task::CURRENT.with_borrow_mut(|slot|*slot=Some(p));
  assert_eq!(check_image_authorization(7,&authorization),expected);
 }
 task::CURRENT.with_borrow_mut(|slot|*slot=None);
 assert_eq!(check_image_authorization(7,&permit(0,0,PendingExecKind::ImageReplace)),Err(Error::NotReady));
 let mut p=process(0,0,permit(7,7,PendingExecKind::Spawn));
 assert!(!p.permits_image_authorization(p.pending_exec_security.as_ref().unwrap()));
 for (identity,digest) in [(Some(8),Some([7;32])),(Some(9),Some([6;32])),(None,Some([7;32])),(Some(9),None)] {
  let mut p=process(7,7,permit(7,7,PendingExecKind::SpawnInherit));
  p.application_identity=identity;p.image_digest=digest;
  assert!(p.take_exec_authorization("opaque-image-key",11).is_none());
  assert!(p.pending_exec_security.is_none());
 }
 // Spawn keeps its existing trusted-broker policy; it cannot pass the image
 // replacement predicate or be mistaken for a replacement permit.
 assert!(p.take_exec_authorization("opaque-image-key",11).is_some());

 // Every mutation API invalidates stored permits, including a no-op access
 // or a revoke/restore cycle. Publication always stamps the native revision.
 for kind in [PendingExecKind::ImageReplace,PendingExecKind::SpawnInherit,PendingExecKind::Spawn] {
  for operation in 0..4 {
   let mut p=process(7,7,permit(7,7,kind));
   let mut request=permit(7,7,kind); request.authority_revision=12345;
   p.authorize_next_exec(request).unwrap();
   assert_eq!(p.pending_exec_security.as_ref().unwrap().authority_revision,1);
   mutate(&mut p,operation);
   assert_eq!(p.capabilities,Grants(7)); assert_eq!(p.kernel_authorities,Grants(7));
   assert!(p.pending_exec_security.is_none());
   assert!(p.take_exec_authorization("opaque-image-key",11).is_none());
   p.authorize_next_exec(permit(7,7,kind)).unwrap();
   assert!(p.take_exec_authorization("opaque-image-key",11).is_some());
  }
 }
 // After consumption a sibling can revoke and restore exactly the same
 // grants during image preparation. The detached permit must still fail.
 for kind in [PendingExecKind::ImageReplace,PendingExecKind::SpawnInherit] {
  for operation in 0..4 {
   let mut p=process(7,7,permit(7,7,kind));
   p.authorize_next_exec(permit(7,7,kind)).unwrap();
   let old=p.take_exec_authorization("opaque-image-key",11).unwrap();
   mutate(&mut p,operation);
   assert!(!p.permits_image_authorization(&old));
   assert!(!p.permits_inherited_spawn_authorization(&old));
   if kind==PendingExecKind::ImageReplace {
    task::CURRENT.with_borrow_mut(|slot|*slot=Some(p));
    assert_eq!(check_image_authorization(7,&old),Err(Error::AccessDenied));
   }
  }
 }
 let mut p=process(7,7,permit(7,7,PendingExecKind::ImageReplace));
 p.exec_authority_revision=u64::MAX-1;
 p.authorize_next_exec(permit(7,7,PendingExecKind::ImageReplace)).unwrap();
 p.capabilities_mut();
 assert_eq!(p.exec_authority_revision,u64::MAX);
 p.kernel_authorities_mut();
 assert_eq!(p.exec_authority_revision,u64::MAX);
 assert!(p.pending_exec_security.is_none());
 assert_eq!(p.authorize_next_exec(permit(7,7,PendingExecKind::ImageReplace)),Err(Error::LimitExceeded));
 assert!(p.pending_exec_security.is_none());
}
"#);
    probe::run(&program);
}

#[test]
fn late_authority_validation_is_after_quiescence_and_before_old_image_mutation() {
    let source = include_str!("../../../core/src/syscall/exec.rs");
    let source = probe::between(
        source,
        "fn replace_current_process_image(",
        "/// Replaces the current process image",
    );
    let quiesce = source
        .find("let quiescence = crate::task::scheduler::quiesce_image_siblings")
        .unwrap();
    let validation = source
        .find("check_image_authorization(pid, &authorization).map_err(Error::into_raw)?;")
        .unwrap();
    let freeze = source
        .find("crate::task::authority_transition::begin_commit(pid)")
        .unwrap();
    assert!(quiesce < freeze && freeze < validation);
    assert!(quiesce < validation);
    for mutation in [
        "process\n                    .launch_context()",
        "crate::task::release_process_borrowed_mappings(pid)?;",
        "retire_image_siblings(pid, current_tid)",
        "stack_mapping.commit();",
        "process.set_page_table(new_pt_phys);",
        "process.set_capabilities_for_exec(authorization.capabilities);",
    ] {
        assert!(
            validation < source.find(mutation).unwrap(),
            "mutation precedes validation: {mutation}"
        );
    }
    assert!(validation < source.find("drop(quiescence);").unwrap());
}
