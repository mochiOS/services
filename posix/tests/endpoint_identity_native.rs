//! Run production endpoint record validation and identity lookup against a
//! controlled live-thread registry. No raw TID fallback is supplied.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn endpoint_identity_requires_inspection_and_a_live_matching_generation() {
    let source = include_str!("../../../core/src/syscall/ipc.rs");
    let mut program = probe::program();
    program.push_str("#[repr(C)]\n#[derive(Debug,Clone,Copy,PartialEq,Eq)]\n");
    program.push_str(probe::between(
        include_str!("../../../core/crates/abi/src/lib.rs"),
        "pub struct ExecutionIdentity {",
        "/// Native execution domains",
    ));
    program.push_str(probe::between(
        source,
        "#[derive(Debug, Clone, Copy, PartialEq, Eq)]\npub struct IpcEndpoint",
        "// Endpoint handles and legacy",
    ));
    program.push_str(
        r#"
use std::collections::BTreeMap;
use std::cell::RefCell;
use mnu_abi::status::Error;
struct State {
    authorized:bool,live:Option<(usize,u64)>,process:bool,
    lookups:usize,thread_checks:usize,process_checks:usize,
    endpoints:BTreeMap<u64,EndpointRecord>,
}
impl Default for State {
    fn default()->Self {
        Self {authorized:true,live:Some((2,3)),process:true,lookups:0,
            thread_checks:0,process_checks:0,
            endpoints:BTreeMap::from([(0x40000005,EndpointRecord{
                thread_id:9,slot:2,generation:3,rights:EndpointRights::SEND})])}
    }
}
thread_local!{static STATE:RefCell<State>=RefCell::new(State::default());}
mod capability {#[derive(PartialEq,Eq,Debug)]pub enum Capability{ProcessInspect}}
mod syscall {pub mod security {
    pub fn caller_has_any_capability(caps:&[crate::capability::Capability])->bool {
        assert_eq!(caps,[crate::capability::Capability::ProcessInspect]);
        crate::STATE.with_borrow(|s|s.authorized)
    }
}}
mod task {
    pub struct Id(u64);impl Id{pub fn as_u64(self)->u64{self.0}}
    pub fn thread_to_process_id(thread:u64)->Option<Id>{
        assert_eq!(thread,9);
        crate::STATE.with_borrow_mut(|s|{s.process_checks+=1;s.process.then_some(Id(90))})
    }
    pub mod thread {
        pub fn live_thread_slot_index_and_generation_by_u64(thread:u64)->Option<(usize,u64)> {
            assert_eq!(thread,9);
            crate::STATE.with_borrow_mut(|s|{s.thread_checks+=1;s.live})
        }
    }
}
fn with_endpoints_mut<T>(operation:impl FnOnce(&mut BTreeMap<u64,EndpointRecord>)->T)->T {
    STATE.with_borrow_mut(|s|{s.lookups+=1;operation(&mut s.endpoints)})
}
"#,
    );
    program.push_str(probe::between(
        source,
        "pub fn endpoint_is_valid(",
        "pub fn endpoint_rights_for_process(",
    ));
    program.push_str(probe::between(
        source,
        "fn endpoint_record_is_valid(",
        "pub fn endpoint_alive(",
    ));
    program.push_str(
        &probe::between(
            source,
            "pub fn endpoint_execution_identity(",
            "pub fn endpoint_is_owned_by(",
        )
        .replace("mnu_abi::ExecutionIdentity", "ExecutionIdentity"),
    );
    program.push_str(
        r#"
fn main(){
    STATE.set(State::default());
    assert_eq!(endpoint_execution_identity(0x40000005),
        Ok(ExecutionIdentity{process_id:90,thread_id:9}));
    STATE.with_borrow(|s|{
        assert_eq!((s.lookups,s.thread_checks,s.process_checks),(1,1,1));
        assert_eq!(s.endpoints.len(),1);
        assert_eq!(s.endpoints[&0x40000005].rights,EndpointRights::SEND);
    });
    // No raw thread number, null selector or unregistered endpoint resolves.
    for endpoint in [0,9,u64::MAX,0x40000006] {
        STATE.set(State::default());
        assert_eq!(endpoint_execution_identity(endpoint),Err(Error::NotFound));
        STATE.with_borrow(|s|assert_eq!((s.lookups,s.thread_checks,s.process_checks),(1,0,0)));
    }
    // Lack of inspection permission prevents even lookup of attacker input.
    for endpoint in [0x40000005,9,u64::MAX] {
        STATE.set(State{authorized:false,..State::default()});
        assert_eq!(endpoint_execution_identity(endpoint),Err(Error::AccessDenied));
        STATE.with_borrow(|s|assert_eq!((s.lookups,s.thread_checks,s.process_checks),(0,0,0)));
    }
    for live in [None,Some((2,4)),Some((3,3))] {
        STATE.set(State{live,..State::default()});
        assert_eq!(endpoint_execution_identity(0x40000005),Err(Error::NotFound));
        STATE.with_borrow(|s|assert_eq!((s.lookups,s.thread_checks,s.process_checks),(1,1,0)));
    }
    STATE.set(State{process:false,..State::default()});
    assert_eq!(endpoint_execution_identity(0x40000005),Err(Error::NotFound));
    STATE.with_borrow(|s|assert_eq!((s.lookups,s.thread_checks,s.process_checks),(1,1,1)));
}
"#,
    );
    probe::run(&program);
}
