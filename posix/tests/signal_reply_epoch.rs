use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn actual_delivery_loops_discard_only_replies_copied_into_another_fork_image() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let fault = include_str!("../../../user/crates/newlib-runtime/src/fault_signal.rs");
    let mut program = String::from(
        r#"
use std::sync::atomic::{AtomicU32,AtomicU64,Ordering};
#[allow(non_camel_case_types)] type c_int=i32;
const EAGAIN:i32=11;const EINVAL:i32=22;const EIO:i32=5;
static FORK_EPOCH:AtomicU64=AtomicU64::new(0);
static OWNER:AtomicU64=AtomicU64::new(11);
static MODE:AtomicU32=AtomicU32::new(0);
static REQUESTS:AtomicU32=AtomicU32::new(0);
static DISPATCHES:AtomicU32=AtomicU32::new(0);
static COMPLETIONS:AtomicU32=AtomicU32::new(0);
static DEFAULTS:AtomicU32=AtomicU32::new(0);
static CLIENTS:AtomicU32=AtomicU32::new(0);
static FAULT:AtomicU32=AtomicU32::new(0);
static DEFERRED:AtomicU32=AtomicU32::new(0);
static NOTIFICATION:AtomicU32=AtomicU32::new(0);
mod posix_protocol {
    #[derive(Clone,Copy)] pub struct SignalDelivery{pub signal:u32,pub token:u64}
    pub const SIGNAL_DISPOSITION_CAUGHT:u32=2;
}
#[derive(Clone,Copy)] struct SigInfo{si_signo:i32}
impl SigInfo{fn memory_fault(_:u64,_:usize)->Result<Self,()>{Ok(Self{si_signo:11})}}
mod mochios_posix_client {pub mod signal_context{pub type SigInfo=crate::SigInfo;}}
struct UContext;
struct CallbackResources;
impl CallbackResources {
    fn is_deferred(&self)->bool{DEFERRED.load(Ordering::Acquire)!=0}
    fn take_notification(&self)->bool{
        assert!(!self.is_deferred());NOTIFICATION.swap(0,Ordering::AcqRel)!=0
    }
}
struct ThreadControl{callback_resources:CallbackResources}
static CONTROL:ThreadControl=ThreadControl{callback_resources:CallbackResources};
struct Preparation{epoch:u64,started:bool}
mod signal_scope {
    use super::*;
    pub struct Scope {delivery:posix_protocol::SignalDelivery,epoch:u64}
    impl Scope {
        pub fn new(_:&'static ThreadControl,delivery:posix_protocol::SignalDelivery,epoch:u64)->Result<Self,i32>{Ok(Self{delivery,epoch})}
        pub fn complete(self:core::pin::Pin<&mut Self>)->Result<(),i32>{
            if FORK_EPOCH.load(Ordering::Acquire)!=self.epoch{return Ok(())}
            CLIENT.complete_signal_delivery(self.delivery)
        }
    }
}
impl Preparation{
    fn new(_:&'static ThreadControl)->Result<Self,i32>{Ok(Self{epoch:FORK_EPOCH.load(Ordering::Acquire),started:false})}
    fn started(&self)->bool{self.started}
}
struct FaultDelivery {signal:posix_protocol::SignalDelivery,disposition:u32}
struct Client;static CLIENT:Client=Client;
fn copied_child(){OWNER.fetch_add(1,Ordering::AcqRel);FORK_EPOCH.fetch_add(1,Ordering::AcqRel);}
fn native_process_id()->Result<u64,NativeError>{Ok(OWNER.load(Ordering::Acquire))}
struct NativeError;impl NativeError{fn raw(self)->i64{-5}}
fn map_kernel_errno(_:i64)->i32{5}
fn map_posix_client_error(error:i32)->i32{error}
fn register_current_thread()->Option<((),&'static ThreadControl)>{Some(((),&CONTROL))}
fn process_exit(_:i32)->!{panic!("unexpected process exit")}
fn posix_client()->Result<&'static Client,i32>{
    if MODE.load(Ordering::Acquire)==12 && CLIENTS.fetch_add(1,Ordering::AcqRel)==0{
        copied_child();return Err(5)
    }
    Ok(&CLIENT)
}
impl Client{
    fn thread_dequeue_signal_delivery(&self)->Result<posix_protocol::SignalDelivery,i32>{
        let call=REQUESTS.fetch_add(1,Ordering::AcqRel);
        let mode=MODE.load(Ordering::Acquire);
        let token=OWNER.load(Ordering::Acquire);
        if call==0 && matches!(mode,1|2|3){copied_child()}
        if (call==0&&mode==2)||mode==6 {return Err(5)}
        let empty=(call==0&&matches!(mode,3|7))
            || COMPLETIONS.load(Ordering::Acquire)>0 || DEFAULTS.load(Ordering::Acquire)>0;
        Ok(posix_protocol::SignalDelivery{signal:if empty{0}else{11},token})
    }
    fn fault_signal_delivery(&self,_:u32)->Result<FaultDelivery,i32>{
        let mut signal=self.thread_dequeue_signal_delivery()?;
        if MODE.load(Ordering::Acquire)==11 {signal.signal=20}
        Ok(FaultDelivery{signal,disposition:posix_protocol::SIGNAL_DISPOSITION_CAUGHT})
    }
    fn complete_signal_delivery(&self,delivery:posix_protocol::SignalDelivery)->Result<(),i32>{
        assert_eq!(delivery.token,OWNER.load(Ordering::Acquire),"completed another image's token");
        COMPLETIONS.fetch_add(1,Ordering::AcqRel);
        if MODE.load(Ordering::Acquire)==13{copied_child();return Err(5)}
        if MODE.load(Ordering::Acquire)==16{copied_child()}
        if MODE.load(Ordering::Acquire)==15{return Err(5)}
        Ok(())
    }
    fn report_process_signaled(&self,_:posix_protocol::SignalDelivery)->Result<(),i32>{panic!("unexpected fatal report")}
}
fn dispatch_signal(delivery:posix_protocol::SignalDelivery,info:Option<SigInfo>,_:&mut UContext,_:bool,preparation:&mut Preparation,_:core::pin::Pin<&mut signal_scope::Scope>)->Result<i32,i32>{
    assert_eq!(delivery.token,OWNER.load(Ordering::Acquire),"dispatched another image's token");
    assert_eq!(info.is_some(),FAULT.load(Ordering::Acquire)!=0);
    let call=DISPATCHES.fetch_add(1,Ordering::AcqRel);
    if MODE.load(Ordering::Acquire)==18 && call==0{copied_child();return Err(5)}
    if MODE.load(Ordering::Acquire)==19{return Err(5)}
    preparation.started=!matches!(MODE.load(Ordering::Acquire),8|9|10|14|17);
    match MODE.load(Ordering::Acquire){
        4|5 if call==0=>{copied_child();if MODE.load(Ordering::Acquire)==5{Err(22)}else{Ok(0)}}
        8|14|17=>Ok(1),9=>Ok(3),10=>Ok(2),_=>Ok(0)
    }
}
fn apply_default_signal_action(delivery:posix_protocol::SignalDelivery)->Result<(),i32>{
    assert_eq!(delivery.token,OWNER.load(Ordering::Acquire));DEFAULTS.fetch_add(1,Ordering::AcqRel);
    if MODE.load(Ordering::Acquire)==14{copied_child();return Err(5)}
    if MODE.load(Ordering::Acquire)==17{return Err(5)}
    Ok(())
}
"#,
    );
    for (source, name) in [
        (runtime, "drain_pending_signals_with_context"),
        (fault, "deliver"),
    ] {
        let start = source.find(&format!("fn {name}(")).unwrap();
        let end = start + source[start..].find("\n}\n").unwrap() + 3;
        program.push_str(&source[start..end]);
    }
    program.push_str(r#"
fn reset(mode:u32,fault:bool){
    MODE.store(mode,Ordering::Release);FAULT.store(fault as u32,Ordering::Release);
    OWNER.store(11,Ordering::Release);FORK_EPOCH.store(0,Ordering::Release);
    DEFERRED.store(0,Ordering::Release);NOTIFICATION.store(1,Ordering::Release);
    for value in [&REQUESTS,&DISPATCHES,&COMPLETIONS,&DEFAULTS,&CLIENTS]{value.store(0,Ordering::Release)}
}
fn main(){
    reset(0,false);DEFERRED.store(1,Ordering::Release);
    assert_eq!(drain_pending_signals_with_context(&mut UContext,false),Ok(()));
    assert_eq!(REQUESTS.load(Ordering::Acquire),0);
    assert_eq!(DISPATCHES.load(Ordering::Acquire),0);
    assert_eq!(COMPLETIONS.load(Ordering::Acquire),0);
    assert_eq!(NOTIFICATION.load(Ordering::Acquire),1);
    DEFERRED.store(0,Ordering::Release);
    assert_eq!(drain_pending_signals_with_context(&mut UContext,false),Ok(()));
    assert_eq!(COMPLETIONS.load(Ordering::Acquire),1);
    assert_eq!(NOTIFICATION.load(Ordering::Acquire),0);
    for mode in [0,1,2,3,4,5,6,7,8,9,10,12,13,14,15,16,17,18,19] {
        reset(mode,false);
        let result=drain_pending_signals_with_context(&mut UContext,false);
        assert_eq!(result,match mode{5|10=>Err(22),6|15|17|19=>Err(5),_=>Ok(())},"queued mode {mode}");
        let completed=match mode{5|6|7|8|14|17=>0,_=>1};
        assert_eq!(COMPLETIONS.load(Ordering::Acquire),completed,"queued mode {mode}");
        assert_eq!(DEFAULTS.load(Ordering::Acquire),if matches!(mode,8|14|17){1}else{0});
        if matches!(mode,1|2|3) {assert_eq!(DISPATCHES.load(Ordering::Acquire),1)}
    }
    for mode in [0,1,2,4,5,6,11,13,15,16,18,19] {
        reset(mode,true);
        let result=deliver(1,0,&mut UContext);
        assert_eq!(result,match mode{5=>Err(22),6|11|15|19=>Err(5),_=>Ok(())},"fault mode {mode}");
        assert_eq!(COMPLETIONS.load(Ordering::Acquire),if matches!(mode,0|1|2|13|15|16|18|19){1}else{0},"fault mode {mode}");
        if matches!(mode,1|2) {assert_eq!(REQUESTS.load(Ordering::Acquire),2)}
    }
}
"#);
    let directory =
        std::env::temp_dir().join(format!("mochios-signal-reply-epoch-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let binary = directory.join("probe");
    let mut compiler = Command::new("rustc")
        .args(["--edition=2024", "-Awarnings", "-", "-o"])
        .arg(&binary)
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    compiler
        .stdin
        .take()
        .unwrap()
        .write_all(program.as_bytes())
        .unwrap();
    let output = compiler.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = Command::new(binary).output().unwrap();
    std::fs::remove_dir_all(directory).unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
