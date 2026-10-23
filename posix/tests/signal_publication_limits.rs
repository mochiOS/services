//! Exercise the unchanged publication guard and fault-delivery constructor at
//! their real u64 limits. Only the surrounding state/transport is controlled.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn actual_token_and_epoch_exhaustion_never_reuses_authority_or_leaves_a_partial_delivery() {
    let source = include_str!("../src/signal_dequeue.rs");
    let fault = include_str!("../src/fault_signal.rs");
    let runtime = include_str!("../src/lib.rs");
    let mut program = String::from(
        r#"
#![allow(dead_code)]
use std::collections::BTreeMap;
const STATUS_EOVERFLOW:i32=-75;const MAX_OUTSTANDING_SIGNAL_DELIVERIES:usize=64;
mod protocol {
 pub const STATUS_EAGAIN:i32=-11;pub const STATUS_ESRCH:i32=-3;
 #[derive(Clone,Copy,Debug,PartialEq,Eq)]pub struct SignalDelivery{pub signal:u32,pub token:u64}
 pub mod signal_origin {#[derive(Clone,Copy,Debug,PartialEq,Eq)]pub struct Origin(pub u64);}
}
mod mnu_abi {#[derive(Clone,Copy)]pub struct ExecutionIdentity{pub process_id:u64,pub thread_id:u64}}
#[derive(Clone,Copy)]struct SignalDeliveryOwner{signal:u32,origin:protocol::signal_origin::Origin,thread_id:u64}
#[derive(Default)]struct ProcessWaitState{deliveries:BTreeMap<u64,SignalDeliveryOwner>}
impl ProcessWaitState {
"#,
    );
    program.push_str(probe::between(
        runtime,
        "    fn begin_delivery(",
        "    fn cancel_stop_deliveries(",
    ));
    program.push_str(
        r#"
}
struct PosixService<H:Copy>{
 process_wait_states:BTreeMap<u64,ProcessWaitState>,signal_delivery_epochs:BTreeMap<(u64,u64),u64>,
 next_signal_delivery_token:u64,_handle:std::marker::PhantomData<H>,
}
mod signal_dequeue {
use super::*;
"#,
    );
    program.push_str(probe::between(
        source,
        "pub(super) fn allocate_token(",
        "#[derive(Clone, Copy)]\nenum Candidate",
    ));
    program.push_str(r#"
pub fn run(){
 let own=mnu_abi::ExecutionIdentity{process_id:1,thread_id:2};
 let origin=protocol::signal_origin::Origin(37);
 let mut state=ProcessWaitState::default();let mut epoch=0;let mut next=u64::MAX-1;
 let rejected;
 {
  let mut pending=Publication::new(&mut state,&mut epoch,&mut next,own,10,origin).unwrap();
  rejected=pending.delivery.token;assert_eq!(rejected,u64::MAX-1);
  assert!(!pending.publish(|_|false));
 }
 assert_eq!(next,u64::MAX);assert_eq!(epoch,0);assert!(state.deliveries.is_empty());
 assert!(matches!(Publication::new(&mut state,&mut epoch,&mut next,own,10,origin),Err(STATUS_EOVERFLOW)));
 assert_eq!(next,u64::MAX);assert_eq!(epoch,0);assert!(state.deliveries.is_empty());
 next=1;epoch=u64::MAX;
 assert!(matches!(Publication::new(&mut state,&mut epoch,&mut next,own,10,origin),Err(STATUS_EOVERFLOW)));
 assert_eq!(next,1);assert_eq!(epoch,u64::MAX);assert!(state.deliveries.is_empty());
 epoch=u64::MAX-1;
 {
  let mut pending=Publication::new(&mut state,&mut epoch,&mut next,own,10,origin).unwrap();
  assert!(pending.publish(|_|true));
 }
 assert_eq!(epoch,u64::MAX);assert_eq!(state.deliveries.len(),1);
 assert_eq!(state.deliveries[&1].origin,origin);
 assert!(matches!(Publication::new(&mut state,&mut epoch,&mut next,own,10,origin),Err(STATUS_EOVERFLOW)));
 assert_eq!(next,2);assert_eq!(state.deliveries.len(),1);
}
}
mod fault_signal { use super::*; impl<H:Copy> PosixService<H>{
"#);
    let start = fault
        .find("    pub(super) fn begin_signal_delivery(")
        .unwrap();
    let end = start + fault[start..].find("\n    }\n").unwrap() + "\n    }\n".len();
    program.push_str(&fault[start..end]);
    program.push_str(r#"
}}
fn main(){
 signal_dequeue::run();
 let own=mnu_abi::ExecutionIdentity{process_id:1,thread_id:2};let origin=protocol::signal_origin::Origin(37);
 let mut service=PosixService::<u32>{process_wait_states:BTreeMap::from([(1,ProcessWaitState::default())]),
 signal_delivery_epochs:BTreeMap::from([((1,2),u64::MAX)]),next_signal_delivery_token:1,_handle:std::marker::PhantomData};
 assert_eq!(service.begin_signal_delivery(own,10,origin),Err(STATUS_EOVERFLOW));
 assert_eq!(service.next_signal_delivery_token,1);assert!(service.process_wait_states[&1].deliveries.is_empty());
 service.signal_delivery_epochs.insert((1,2),0);service.next_signal_delivery_token=u64::MAX;
 assert_eq!(service.begin_signal_delivery(own,10,origin),Err(STATUS_EOVERFLOW));
 assert_eq!(service.signal_delivery_epochs[&(1,2)],0);assert!(service.process_wait_states[&1].deliveries.is_empty());
}
"#);
    probe::run(&program);
}
