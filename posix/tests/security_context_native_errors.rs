//! Execute the complete production security query with controlled task/IPC
//! lookup and native usercopy boundaries, without weakening its inspect gate.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn native_security_query_preserves_authenticated_identity_and_failure_categories() {
    let mut program = probe::program();
    program.push_str("mod record {\n");
    program.push_str(probe::between(
        include_str!("../../../core/crates/abi/src/lib.rs"),
        "pub const APPLICATION_ID_FIELD_LEN:",
        "#[cfg(test)]",
    ));
    program.push_str(r#"
}
use mnu_abi::status::Error;
use std::cell::RefCell;
const SUCCESS:u64=0;
struct State {
    authorized:bool,current:bool,thread:bool,process:bool,identity:Option<Identity>,
    checks:usize,resolutions:usize,copies:usize,copy_error:Option<Error>,bytes:Vec<u8>,
}
impl Default for State {
    fn default()->Self{Self{authorized:true,current:true,thread:true,process:true,
        identity:Some(Identity{package:"org.example.app".into(),developer:"example".into(),
            provenance:task::process::ApplicationProvenance::VerifiedPackage}),
        checks:0,resolutions:0,copies:0,copy_error:None,bytes:Vec::new()}}
}
thread_local!{static STATE:RefCell<State>=RefCell::new(State::default());}
struct Identity {package:String,developer:String,provenance:task::process::ApplicationProvenance}
impl Identity {
    fn package_id(&self)->&str{&self.package}
    fn developer_id(&self)->&str{&self.developer}
    fn provenance(&self)->task::process::ApplicationProvenance{self.provenance}
    fn subject_key_id(&self)->&[u8;32]{&[0xab;32]}
}
mod task {
    #[derive(Clone,Copy)] pub struct Id(pub u64);
    impl Id{pub fn as_u64(self)->u64{self.0}}
    pub fn current_thread_id()->Option<Id>{crate::STATE.with_borrow(|s|s.current.then_some(Id(7)))}
    pub fn thread_to_process_id(thread:u64)->Option<Id>{
        assert!([7,9].contains(&thread));
        crate::STATE.with_borrow(|s|s.thread.then_some(Id(thread*10)))
    }
    pub struct Process<'a>(pub &'a crate::State);
    impl Process<'_>{pub fn application_identity(&self)->Option<&crate::Identity>{self.0.identity.as_ref()}}
    pub fn with_process<T>(pid:Id,operation:impl FnOnce(&Process<'_>)->T)->Option<T>{
        assert!([70,90].contains(&pid.0));
        crate::STATE.with_borrow(|s|s.process.then(||operation(&Process(s))))
    }
    pub mod process {
        #[derive(Clone,Copy)] pub enum ApplicationProvenance{BuiltIn,VerifiedPackage,Development}
    }
}
mod capability {
    #[derive(Debug,PartialEq,Eq)] pub enum Capability{CapabilitiesManage,ProcessInspect}
}
mod syscall {
    pub mod security {
        pub fn caller_has_any_capability(caps:&[crate::capability::Capability])->bool{
            use crate::capability::Capability;
            assert_eq!(caps,[Capability::CapabilitiesManage,Capability::ProcessInspect]);
            crate::STATE.with_borrow_mut(|s|{s.checks+=1;s.authorized})
        }
    }
    pub mod ipc {
        pub fn resolve_sender_thread_id(endpoint:u64)->Option<u64>{
            crate::STATE.with_borrow_mut(|s|s.resolutions+=1);
            (endpoint==0x40000005).then_some(9)
        }
    }
    pub fn copy_to_user_native(pointer:u64,bytes:&[u8])->Result<(),crate::Error>{
        assert_eq!(bytes.len(),320);
        crate::STATE.with_borrow_mut(|s|{
            s.copies+=1;
            if let Some(error)=s.copy_error{return Err(error);}
            if pointer==0{return Err(crate::Error::InvalidAddress);}
            assert_eq!(pointer,0x1000);s.bytes=bytes.to_vec();Ok(())
        })
    }
}
"#);
    program.push_str(
        &probe::between(
            include_str!("../../../core/src/syscall/process.rs"),
            "pub fn get_thread_security_context(",
            "/// ユーザー空間の上限アドレス",
        )
        .replace(
            "mnu_abi::ThreadSecurityContext",
            "record::ThreadSecurityContext",
        )
        .replace(
            "mnu_abi::APPLICATION_ID_FIELD_LEN",
            "record::APPLICATION_ID_FIELD_LEN",
        ),
    );
    program.push_str(r#"
fn query(endpoint:u64)->u64{get_thread_security_context(endpoint,0x1000,320)}
fn unchanged(){STATE.with_borrow(|s|{assert_eq!(s.copies,0);assert!(s.bytes.is_empty());});}
fn main(){
    for endpoint in [0,0x40000005] {
        STATE.set(State::default());assert_eq!(query(endpoint),0);
        STATE.with_borrow(|s|{
            assert_eq!((s.checks,s.resolutions,s.copies),
                (usize::from(endpoint!=0),usize::from(endpoint!=0),1));
            let thread=if endpoint==0{7}else{9};
            assert_eq!(u64::from_ne_bytes(s.bytes[..8].try_into().unwrap()),thread*10);
            assert_eq!(u64::from_ne_bytes(s.bytes[8..16].try_into().unwrap()),thread);
            assert_eq!(s.bytes[16],2);assert_eq!(s.bytes[17..24],[0;7]);
            assert_eq!(s.bytes[24..56],[0xab;32]);assert_eq!(s.bytes[60..64],[0;4]);
            assert_eq!(u16::from_ne_bytes(s.bytes[56..58].try_into().unwrap()),15);
            assert_eq!(u16::from_ne_bytes(s.bytes[58..60].try_into().unwrap()),7);
            assert_eq!(&s.bytes[64..79],b"org.example.app");assert_eq!(s.bytes[79..192],[0;113]);
            assert_eq!(&s.bytes[192..199],b"example");assert_eq!(s.bytes[199..],[0;121]);
        });
    }
    // No inspection authority is acquired by asking about the caller itself.
    STATE.set(State{authorized:false,..State::default()});
    assert_eq!(query(0),0);STATE.with_borrow(|s|assert_eq!(s.checks,0));
    // Denial must precede foreign endpoint resolution and any output access.
    STATE.set(State{authorized:false,..State::default()});
    assert_eq!(get_thread_security_context(u64::MAX,0,320),Error::AccessDenied.into_raw());
    unchanged();STATE.with_borrow(|s|assert_eq!((s.checks,s.resolutions),(1,0)));
    STATE.set(State::default());
    for length in [0,319] {
        assert_eq!(get_thread_security_context(0x40000005,0x1000,length),Error::InvalidArgument.into_raw());
        unchanged();STATE.with_borrow(|s|assert_eq!((s.checks,s.resolutions),(0,0)));
    }
    assert_eq!(query(u64::MAX),Error::NotFound.into_raw());unchanged();
    for endpoint in [0,0x40000005] {
        for missing in 0..3 {
            if endpoint!=0 && missing==0{continue;}
            STATE.set(State::default());
            STATE.with_borrow_mut(|s|match missing{0=>s.current=false,1=>s.thread=false,_=>s.process=false});
            let error=if endpoint==0{Error::NotReady}else{Error::NotFound};
            assert_eq!(query(endpoint),error.into_raw());unchanged();
        }
    }
    for error in [Error::InvalidAddress,Error::ResourceUnavailable,Error::BackingFailure] {
        STATE.set(State{copy_error:Some(error),..State::default()});
        assert_eq!(query(0x40000005),error.into_raw());
        STATE.with_borrow(|s|{assert_eq!(s.copies,1);assert!(s.bytes.is_empty());});
    }
    STATE.set(State::default());
    assert_eq!(get_thread_security_context(0,0,320),Error::InvalidAddress.into_raw());
    // A larger capacity is accepted but exactly the current record is copied.
    STATE.set(State::default());assert_eq!(get_thread_security_context(0,0x1000,u64::MAX),0);
    STATE.with_borrow(|s|assert_eq!(s.bytes.len(),320));
    for provenance in [task::process::ApplicationProvenance::BuiltIn,
        task::process::ApplicationProvenance::Development] {
        STATE.set(State::default());
        STATE.with_borrow_mut(|s|s.identity.as_mut().unwrap().provenance=provenance);
        assert_eq!(query(0),0);
        STATE.with_borrow(|s|assert_eq!(s.bytes[16],match provenance{
            task::process::ApplicationProvenance::BuiltIn=>1,_=>3}));
    }
    STATE.set(State{identity:None,..State::default()});assert_eq!(query(0),0);
    STATE.with_borrow(|s|assert!(s.bytes[16..].iter().all(|byte|*byte==0)));
    for length in [128,129] {
        STATE.set(State::default());
        STATE.with_borrow_mut(|s|s.identity.as_mut().unwrap().package="x".repeat(length));
        assert_eq!(query(0),0);
        STATE.with_borrow(|s|if length==128{
            assert_eq!(u16::from_ne_bytes(s.bytes[56..58].try_into().unwrap()),128);
            assert_eq!(s.bytes[64..192],[b'x';128]);
        }else{assert!(s.bytes[16..].iter().all(|byte|*byte==0));});
    }
}
"#);
    probe::run(&program);
}
