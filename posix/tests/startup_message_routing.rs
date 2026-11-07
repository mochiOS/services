#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn startup_waits_recover_queued_replies_without_stealing_calls_or_endpoint_publications() {
    let source = include_str!("../../service-manager/src/readiness.rs");
    let mut program = probe::program();
    program.push_str(r#"
use std::cell::{Cell,RefCell};
use std::collections::VecDeque;
#[derive(Debug,PartialEq,Eq)] struct DeferredMessage {sender:u64,bytes:Vec<u8>}
#[derive(Debug,PartialEq,Eq)] enum ReadyError {Ipc(u64),Clock(u64),ProcessStatus(i32),ProcessExited(i32),TimedOut}
#[derive(Clone,Copy)] struct ProcessWatchTarget(u32);
struct ProcessWatch;
impl ProcessWatch {
    fn open(target:ProcessWatchTarget)->Result<Self,i32>{assert_eq!(target.0,77);Ok(Self)}
    fn process_id(&self)->Result<u64,i32>{Ok(611)}
    fn exit_status(&self)->Result<Option<i32>,i32>{Ok(EXIT.get())}
}
enum ReceivedNotification {Deferred(DeferredMessage),Endpoint(u32),Other}
thread_local! {
    static INCOMING:RefCell<VecDeque<ReceivedNotification>>=RefCell::default();
    static RECEIVES:Cell<usize>=const {Cell::new(0)};
    static YIELDS:Cell<usize>=const {Cell::new(0)};
    static CLOCK:Cell<u64>=const {Cell::new(0)};
    static EXIT:Cell<Option<i32>>=const {Cell::new(None)};
    static RECEIVE_ERROR:Cell<Option<u64>>=const {Cell::new(None)};
}
mod platform {
    pub mod ipc {
        pub fn endpoint_owner_process(sender:u64)->Result<u64,crate::SysError>{
            match sender {701|702=>Ok(611),801=>Ok(612),_=>Err(crate::NativeError::PeerClosed.into_raw().into())}
        }
    }
    pub mod thread {pub fn yield_now(){crate::YIELDS.set(crate::YIELDS.get()+1);}}
}
fn current_ticks()->Result<u64,ReadyError>{let value=CLOCK.get();CLOCK.set(value+1);Ok(value)}
fn receive_notification()->Result<Option<ReceivedNotification>,ReadyError>{
    RECEIVES.set(RECEIVES.get()+1);
    if let Some(error)=RECEIVE_ERROR.get(){return Err(ReadyError::Ipc(error));}
    Ok(INCOMING.with_borrow_mut(VecDeque::pop_front))
}
struct ReadyHandshake {deferred:VecDeque<DeferredMessage>,network:Option<u32>}
impl ReadyHandshake {
    // Wire validation and restricted endpoint ownership are exercised by the
    // production readiness unit tests; this transport supplies decoded events.
    fn record_non_session_notification(&mut self,event:ReceivedNotification)->Result<(),ReadyError>{
        match event {
            ReceivedNotification::Deferred(message)=>self.deferred.push_back(message),
            ReceivedNotification::Endpoint(endpoint)=>{assert!(self.network.replace(endpoint).is_none());}
            ReceivedNotification::Other=>{}
        }
        Ok(())
    }
"#);
    program.push_str(probe::between(
        source,
        "    pub(crate) fn wait_for_process_message(",
        "    fn record_non_session_notification(",
    ));
    program.push_str("}\n");
    program.push_str(probe::between(
        source,
        "fn take_process_message(",
        "\nenum ReceivedNotification {",
    ));
    program.push_str(r#"
fn message(sender:u64,value:u8)->DeferredMessage {DeferredMessage{sender,bytes:vec![value]}}
fn reset()->ReadyHandshake {
    INCOMING.with_borrow_mut(VecDeque::clear);RECEIVES.set(0);YIELDS.set(0);CLOCK.set(0);EXIT.set(None);RECEIVE_ERROR.set(None);
    ReadyHandshake{deferred:VecDeque::new(),network:None}
}
fn main() {
    // A completion consumed by an earlier Ready wait must not incur a timeout
    // or another transport receive. Neither payload claims nor stale endpoints
    // may authenticate an unrelated queued caller.
    let mut ready=reset();
    let mut external=VecDeque::from([message(801,611u16 as u8),message(999,2),message(701,3),message(801,4)]);
    assert_eq!(ready.wait_for_process_message(ProcessWatchTarget(77),4,&mut external),Ok(message(701,3)));
    assert_eq!(RECEIVES.get(),0);assert_eq!(YIELDS.get(),0);
    assert_eq!(external,VecDeque::from([message(801,611u16 as u8),message(999,2),message(801,4)]));
    let mut ready=reset();ready.deferred.push_back(message(702,8));
    assert_eq!(ready.wait_for_process_message(ProcessWatchTarget(77),4,&mut VecDeque::new()),Ok(message(702,8)));
    assert_eq!(RECEIVES.get(),0);
    // Network publication and a regular caller can arrive ahead of the
    // completion. Keep their ownership/order while returning the exact reply.
    let mut ready=reset();let mut external=VecDeque::from([message(801,1)]);
    INCOMING.with_borrow_mut(|events|events.extend([
        ReceivedNotification::Endpoint(91),ReceivedNotification::Deferred(message(801,2)),
        ReceivedNotification::Deferred(message(701,3))]));
    assert_eq!(ready.wait_for_process_message(ProcessWatchTarget(77),4,&mut external),Ok(message(701,3)));
    assert_eq!(ready.network,Some(91));assert_eq!(external,VecDeque::from([message(801,1)]));
    assert_eq!(ready.deferred,VecDeque::from([message(801,2)]));
    assert_eq!(RECEIVES.get(),3);
    // Unrelated traffic must not reset or evade the original deadline.
    let mut ready=reset();INCOMING.with_borrow_mut(|events|for _ in 0..10{events.push_back(ReceivedNotification::Other);});
    assert_eq!(ready.wait_for_process_message(ProcessWatchTarget(77),4,&mut VecDeque::new()),Err(ReadyError::TimedOut));
    assert_eq!(RECEIVES.get(),4);
    let mut ready=reset();EXIT.set(Some(-37));
    assert_eq!(ready.wait_for_process_message(ProcessWatchTarget(77),4,&mut VecDeque::new()),Err(ReadyError::ProcessExited(-37)));
    for error in [NativeError::PeerClosed.into_raw(),NativeError::AccessDenied.into_raw()] {
        let mut ready=reset();RECEIVE_ERROR.set(Some(error));
        assert_eq!(ready.wait_for_process_message(ProcessWatchTarget(77),4,&mut VecDeque::new()),Err(ReadyError::Ipc(error)));
        assert_eq!(YIELDS.get(),0);
    }
}
"#);
    probe::run(&program);
}
