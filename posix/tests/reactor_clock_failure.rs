#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn real_reactor_clock_failures_reach_ipc_planning_and_recover_without_discarding_deadlines() {
    let main = include_str!("../src/main.rs");
    let planning = probe::between(
        main,
        "        if let Err(error) = service.expire_alarms()",
        "        drop(service);",
    );
    let mut program = String::from(
        r#"
extern crate self as platform;
use std::cell::Cell;
thread_local! {
static FAIL:Cell<u32>=const{Cell::new(0)};
static CLOCK_CALLS:Cell<u32>=const{Cell::new(0)};
static LOGS:Cell<u32>=const{Cell::new(0)};
static NOTIFICATIONS:Cell<u32>=const{Cell::new(0)};
}
#[macro_export]macro_rules! logln{($($argument:tt)*)=>{crate::LOGS.set(crate::LOGS.get()+1)}}
pub mod syscall{pub const HANDLE_WAIT_INFINITE:u64=u64::MAX;}
struct Error;impl Error{fn raw(&self)->i64{-5}}
mod time{
pub fn monotonic_milliseconds()->Result<u64,crate::Error>{
let call=crate::CLOCK_CALLS.get()+1;crate::CLOCK_CALLS.set(call);
if crate::FAIL.get()&(1<<call)!=0{Err(crate::Error)}else{Ok(2000)}
}}
mod posix_service{pub mod cpu_limit{pub const SWEEP_INTERVAL_MS:u64=100;}}
struct Service {deadline:u64,cpu_sweeps:u32}
impl Service {
fn expire_alarms(&mut self)->Result<usize,i32>{if FAIL.get()&1!=0{Err(-5)}else{Ok(0)}}
fn has_finite_cpu_limits(&self)->bool{true}
fn enforce_cpu_limits(&mut self,_:&mut())->Result<(),i32>{self.cpu_sweeps+=1;Ok(())}
fn next_alarm_deadline(&self)->Option<u64>{Some(self.deadline)}
fn child_lifecycle_handles(&self)->Vec<u32>{vec![7]}
}
struct PendingSignalWait{deadline:Option<u64>}
fn reap_signal_threads(_:&mut Service,_:&mut Vec<()>){ }
fn deliver_process_resume_notifications(_:&mut Service){NOTIFICATIONS.set(NOTIFICATIONS.get()+1);}
fn complete_pending_signal_waits(_:&mut Vec<PendingSignalWait>,_:&mut Service){}
fn complete_pending_waits(_:&mut Vec<()>,_:&mut Service,_:&mut(),_:&mut()){}
fn deliver_signal_notifications(_:&mut Service,_:&mut Vec<()>){}
fn plan(mut service:&mut Service,reported:&mut bool)->(u64,bool) {
let mut clock_failure_reported=*reported;
let mut clock_failed=false;
let mut processes=();let mut filesystem=();
let mut cpu_sweep_deadline_ms=0;let mut thread_sweep_deadline_ms=0;
let mut signal_threads=vec![()];let mut pending_waits=Vec::new();
let mut pending_signal_waits=vec![PendingSignalWait{deadline:Some(9_000_000_000)}];
"#,
    );
    program.push_str(planning);
    program.push_str(
        r#"
*reported=clock_failure_reported;(deadline,clock_failed)
}
fn main(){
for failure in [1,2,4,7] {
 let mut service=Service{deadline:5_000_000_000,cpu_sweeps:0};let mut reported=false;
 LOGS.set(0);NOTIFICATIONS.set(0);FAIL.set(failure);
 for _ in 0..2 {
  CLOCK_CALLS.set(0);assert!(plan(&mut service,&mut reported).1);assert!(reported);
  assert_eq!(service.deadline,5_000_000_000);
 }
 assert_eq!(LOGS.get(),1);assert_eq!(NOTIFICATIONS.get(),2);
 FAIL.set(0);CLOCK_CALLS.set(0);
 assert_eq!(plan(&mut service,&mut reported),(2_100_000_000,false));assert!(!reported);
 assert_eq!(NOTIFICATIONS.get(),3);assert_eq!(service.deadline,5_000_000_000);
 FAIL.set(failure);CLOCK_CALLS.set(0);assert!(plan(&mut service,&mut reported).1);
 assert_eq!(LOGS.get(),2);
}
}
"#,
    );
    probe::run(&program);
}
