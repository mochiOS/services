#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn presenters_and_dictionary_start_only_after_authenticated_session_publication() {
    let mut program = probe::program();
    program.push_str(r#"
use std::cell::{Cell,RefCell};
#[macro_export] macro_rules! logln {($($args:tt)*)=>{let _=format_args!($($args)*);};}
mod platform {pub use crate::logln;}
thread_local! {
    static CALLS:RefCell<Vec<&'static str>>=RefCell::default();
    static PUBLISHED:Cell<bool>=const {Cell::new(false)};
    static FAIL_PREPARE:Cell<bool>=const {Cell::new(false)};
    static FAIL_PUBLISH:Cell<bool>=const {Cell::new(false)};
    static PERMISSION_PREPARED:Cell<bool>=const {Cell::new(false)};
}
#[derive(Clone,Copy)] struct Session {id:u64}
struct Input;
impl Input {
    fn warmup_ime(&self)->Result<(),SysError>{
        assert!(PUBLISHED.get());assert!(PERMISSION_PREPARED.get());CALLS.with_borrow_mut(|v|v.push("warm"));Ok(())
    }
}
struct Execution;
impl Execution {fn maintain(&mut self,logger:u64){assert_eq!(logger,17);assert!(PUBLISHED.get());CALLS.with_borrow_mut(|v|v.push("execution"));}}
struct Runtime {permission_prompt:(),execution_prompt:Execution,logger_endpoint:u64,raw_input:Option<Input>}
impl Runtime {
    fn prepare_consent_session(&self,_:&mut consent_session::Epoch,session:Session)->Result<(),SysError>{
        assert_eq!(session.id,7);CALLS.with_borrow_mut(|v|v.push("prepare"));
        if FAIL_PREPARE.get(){Err(NativeError::AccessDenied.into_raw().into())}else{Ok(())}
    }
}
mod consent_session {
    #[derive(Default)] pub struct Epoch;
    impl Epoch {
        pub fn native(&mut self,id:u64,active:bool)->Result<(),crate::SysError>{
            assert_eq!(id,if active{7}else{1});
            crate::CALLS.with_borrow_mut(|v|v.push("publish"));
            if crate::FAIL_PUBLISH.get(){return Err(crate::NativeError::PeerClosed.into_raw().into());}
            crate::PUBLISHED.set(active);Ok(())
        }
    }
}
mod portal {
    pub fn prewarm(_: &mut (),logger:u64)->bool {
        assert_eq!(logger,17);assert!(crate::PUBLISHED.get());
        crate::CALLS.with_borrow_mut(|v|v.push("presenter"));
        crate::PERMISSION_PREPARED.get()
    }
}
fn initialize(mut runtime:Option<Runtime>,active_session:Option<Session>) {
"#);
    program.push_str(probe::between(
        include_str!("../../service-manager/src/bootstrap.rs"),
        "    let mut consent_session = crate::consent_session::Epoch::default();",
        "    #[cfg(mochios_process_domain_probe_308)]",
    ));
    program.push_str("let pending_logout:Option<()>=None;\nfor ready in [false,true,true] {PERMISSION_PREPARED.set(ready);if let Some(runtime)=runtime.as_mut(){\n");
    program.push_str(probe::between(
        include_str!("../../service-manager/src/bootstrap.rs"),
        "            if presenter_prewarm_allowed && active_session.is_some() && pending_logout.is_none() {",
        "        }\n        if let (Some(logout)",
    ));
    program.push_str("}}\n");
    program.push_str(r#"
}
fn run(active:bool,prepare_failure:bool,publish_failure:bool,has_input:bool)->Vec<&'static str>{
    CALLS.with_borrow_mut(Vec::clear);PUBLISHED.set(false);PERMISSION_PREPARED.set(false);
    FAIL_PREPARE.set(prepare_failure);FAIL_PUBLISH.set(publish_failure);
    initialize(Some(Runtime{permission_prompt:(),execution_prompt:Execution,logger_endpoint:17,raw_input:has_input.then_some(Input)}),
        active.then_some(Session{id:7}));
    CALLS.with_borrow(Clone::clone)
}
fn main(){
    assert_eq!(run(true,false,false,true),["prepare","publish","presenter","presenter","execution","presenter","execution","warm","presenter","execution"]);
    assert_eq!(run(true,false,false,false),["prepare","publish","presenter","presenter","execution","presenter","execution","presenter","execution"]);
    assert_eq!(run(true,true,false,true),["prepare"]);
    assert_eq!(run(true,false,true,true),["prepare","publish"]);
    assert_eq!(run(false,false,false,true),["publish"]);
    assert_eq!(run(false,false,true,true),["publish"]);
}
"#);
    probe::run(&program);
}
