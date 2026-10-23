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
static CALLBACK_SWEEPS:Cell<u32>=const{Cell::new(0)};
static CPU_ONLY:Cell<bool>=const{Cell::new(false)};
static TIMER_SWEEPS:Cell<u32>=const{Cell::new(0)};
static PROCESS_TIMERS:Cell<bool>=const{Cell::new(false)};
static PROCESS_TIMER_FAILURE:Cell<bool>=const{Cell::new(false)};
static PROCESS_TIMER_SWEEPS:Cell<u32>=const{Cell::new(0)};
static CPU_SLEEPS:Cell<bool>=const{Cell::new(false)};
static CPU_SLEEP_FAILURE:Cell<bool>=const{Cell::new(false)};
static CPU_SLEEP_SWEEPS:Cell<u32>=const{Cell::new(0)};
static DEFERRED:Cell<bool>=const{Cell::new(false)};
static DEFERRED_FAILURE:Cell<bool>=const{Cell::new(false)};
static RESUME:Cell<bool>=const{Cell::new(false)};
static RESUME_FAILURE:Cell<bool>=const{Cell::new(false)};
static EXEC_LOCKS:Cell<bool>=const{Cell::new(false)};
}
#[macro_export]macro_rules! logln{($($argument:tt)*)=>{crate::LOGS.set(crate::LOGS.get()+1)}}
pub mod syscall{pub const HANDLE_WAIT_INFINITE:u64=u64::MAX;}
struct Error;impl Error{fn raw(&self)->i64{-5}}
mod time{
pub fn monotonic_milliseconds()->Result<u64,crate::Error>{
let call=crate::CLOCK_CALLS.get()+1;crate::CLOCK_CALLS.set(call);
if crate::FAIL.get()&(1<<call)!=0{Err(crate::Error)}else{Ok(2000)}
}
pub fn monotonic_nanoseconds()->Result<u64,crate::Error>{monotonic_milliseconds().map(|ms|ms*1_000_000)}
}
mod posix_service{
pub mod cpu_limit{pub const SWEEP_INTERVAL_MS:u64=100;}
pub mod process_timer_reactor{pub const OBSERVATION_INTERVAL_MS:u64=10;}
}
struct Service {deadline:u64,cpu_sweeps:u32}
struct Processes {signal_threads:Vec<()>}
impl Service {
fn expire_alarms(&mut self)->Result<usize,i32>{if FAIL.get()&1!=0{Err(-5)}else{Ok(0)}}
fn has_finite_cpu_limits(&self)->bool{!CPU_ONLY.get()&&!PROCESS_TIMERS.get()&&!CPU_SLEEPS.get()&&!EXEC_LOCKS.get()}
fn has_record_lock_execs(&self)->bool{EXEC_LOCKS.get()}
fn has_cpu_timers(&self)->bool{CPU_ONLY.get()}
fn has_observable_process_timers(&self)->bool{PROCESS_TIMERS.get()}
fn observe_process_timers(&mut self,_:&mut Processes)->Result<usize,i32>{
 if !PROCESS_TIMERS.get(){return Ok(0)}
 PROCESS_TIMER_SWEEPS.set(PROCESS_TIMER_SWEEPS.get()+1);
 if PROCESS_TIMER_FAILURE.get(){Err(-5)}else{Ok(1)}
}
fn expire_cpu_timers(&mut self,_:&mut Processes)->Result<usize,i32>{TIMER_SWEEPS.set(TIMER_SWEEPS.get()+1);Ok(0)}
fn enforce_cpu_limits(&mut self,_:&mut Processes)->Result<(),i32>{self.cpu_sweeps+=1;Ok(())}
fn next_alarm_deadline(&self)->Option<u64>{Some(self.deadline)}
fn child_lifecycle_handles(&self)->Vec<u32>{vec![7]}
fn has_deferred_child_notifications(&self)->bool{DEFERRED.get()}
fn process_resume_notification_processes(&self)->impl Iterator<Item=u64>{
 RESUME.get().then_some(7).into_iter()
}
fn refresh_child_notifications(&mut self,_:&mut Processes)->Result<usize,i32>{
 if DEFERRED.get()&&DEFERRED_FAILURE.get(){return Err(-5)}
 let count=usize::from(DEFERRED.get());DEFERRED.set(false);Ok(count)
}
}
struct PendingSignalWait{deadline:Option<u64>}
struct CpuSleeps;
struct CallbackWaits;
impl CallbackWaits {
fn observe(&mut self,_:&mut Service,_:&mut Processes){CALLBACK_SWEEPS.set(CALLBACK_SWEEPS.get()+1);}
}
impl CpuSleeps {
fn is_empty(&self)->bool{!CPU_SLEEPS.get()}
fn observe(&mut self,_:&mut Service,_:&mut Processes)->Result<usize,i32>{
 if !CPU_SLEEPS.get(){return Ok(0)}
 CPU_SLEEP_SWEEPS.set(CPU_SLEEP_SWEEPS.get()+1);
 if CPU_SLEEP_FAILURE.get(){Err(-5)}else{Ok(1)}
}
}
fn reap_signal_threads(_:&mut Service,_:&mut Vec<()>){ }
fn deliver_process_resume_notifications(_:&mut Service,_:&mut Processes){
 NOTIFICATIONS.set(NOTIFICATIONS.get()+1);
 if RESUME.get()&&!RESUME_FAILURE.get(){RESUME.set(false);}
}
fn complete_pending_signal_waits(_:&mut Vec<PendingSignalWait>,_:&mut Service,_:&mut Processes){}
fn complete_pending_waits(_:&mut Vec<()>,_:&mut Service,_:&mut(),_:&mut Processes){}
fn deliver_signal_notifications(_:&mut Service,_:&mut Vec<()>){}
fn plan(mut service:&mut Service,reported:&mut bool)->(u64,bool) {
let mut clock_failure_reported=*reported;
let mut clock_failed=false;
let mut processes=Processes{signal_threads:vec![()]};let mut filesystem=();
let mut cpu_sweep_deadline_ms=0;let mut thread_sweep_deadline_ms=0;
let mut pending_waits=Vec::new();
let mut cpu_sleeps=CpuSleeps;
let mut callback_waits=CallbackWaits;
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
 LOGS.set(0);NOTIFICATIONS.set(0);CALLBACK_SWEEPS.set(0);FAIL.set(failure);
 for _ in 0..2 {
  CLOCK_CALLS.set(0);assert!(plan(&mut service,&mut reported).1);assert!(reported);
  assert_eq!(service.deadline,5_000_000_000);
 }
 assert_eq!(LOGS.get(),1);assert_eq!(NOTIFICATIONS.get(),2);assert_eq!(CALLBACK_SWEEPS.get(),2);
 FAIL.set(0);CLOCK_CALLS.set(0);
 assert_eq!(plan(&mut service,&mut reported),(2_100_000_000,false));assert!(!reported);
 assert_eq!(NOTIFICATIONS.get(),3);assert_eq!(service.deadline,5_000_000_000);
 FAIL.set(failure);CLOCK_CALLS.set(0);assert!(plan(&mut service,&mut reported).1);
 assert_eq!(LOGS.get(),2);
}
// CPU timers alone must keep the idle reactor's native wait deadline finite.
CPU_ONLY.set(true);FAIL.set(0);CLOCK_CALLS.set(0);TIMER_SWEEPS.set(0);
let mut service=Service{deadline:5_000_000_000,cpu_sweeps:0};let mut reported=false;
assert_eq!(plan(&mut service,&mut reported),(2_010_000_000,false));
assert_eq!(TIMER_SWEEPS.get(),1);
// Process timers alone keep the same finite cadence, without CPU timers or
// budgets. Native observation errors preserve that cadence, reach fallback
// wait planning, and report only once until recovery.
CPU_ONLY.set(false);PROCESS_TIMERS.set(true);PROCESS_TIMER_FAILURE.set(true);
PROCESS_TIMER_SWEEPS.set(0);LOGS.set(0);reported=false;
for _ in 0..2 {
 CLOCK_CALLS.set(0);
 assert_eq!(plan(&mut service,&mut reported),(2_010_000_000,true));
 assert!(reported);
}
assert_eq!(PROCESS_TIMER_SWEEPS.get(),2);assert_eq!(LOGS.get(),1);
PROCESS_TIMER_FAILURE.set(false);CLOCK_CALLS.set(0);
assert_eq!(plan(&mut service,&mut reported),(2_010_000_000,false));
assert!(!reported);assert_eq!(LOGS.get(),1);
PROCESS_TIMERS.set(false);
// CPU sleepers alone also keep the reactor live. Completion observation
// failures must reach IPC fallback planning and recover without a client RPC.
CPU_SLEEPS.set(true);CPU_SLEEP_FAILURE.set(true);CPU_SLEEP_SWEEPS.set(0);
LOGS.set(0);reported=false;
for _ in 0..2 {
 CLOCK_CALLS.set(0);
 assert_eq!(plan(&mut service,&mut reported),(2_010_000_000,true));
 assert!(reported);
}
assert_eq!(CPU_SLEEP_SWEEPS.get(),2);assert_eq!(LOGS.get(),1);
CPU_SLEEP_FAILURE.set(false);CLOCK_CALLS.set(0);
assert_eq!(plan(&mut service,&mut reported),(2_010_000_000,false));
assert!(!reported);assert_eq!(LOGS.get(),1);
CPU_SLEEPS.set(false);
// Failed parent-image observation keeps a retry deadline without another RPC
// or child exit. Failure of that deadline's ClockRead must still reach polling.
CPU_ONLY.set(false);DEFERRED.set(true);DEFERRED_FAILURE.set(true);
FAIL.set(0);CLOCK_CALLS.set(0);
assert_eq!(plan(&mut service,&mut reported),(2_010_000_000,false));
assert!(DEFERRED.get());
FAIL.set(8);CLOCK_CALLS.set(0);
assert!(plan(&mut service,&mut reported).1);assert!(DEFERRED.get());
FAIL.set(0);CLOCK_CALLS.set(0);
assert_eq!(plan(&mut service,&mut reported),(2_010_000_000,false));
assert!(DEFERRED.get());
DEFERRED_FAILURE.set(false);CLOCK_CALLS.set(0);
assert_eq!(plan(&mut service,&mut reported),(2_100_000_000,false));
assert!(!DEFERRED.get());
// A failed native resume, including SIGKILL with no continued notification,
// independently keeps the retry deadline finite and survives clock failures.
RESUME.set(true);RESUME_FAILURE.set(true);FAIL.set(0);CLOCK_CALLS.set(0);
assert_eq!(plan(&mut service,&mut reported),(2_010_000_000,false));
assert!(RESUME.get());assert!(!DEFERRED.get());
FAIL.set(8);CLOCK_CALLS.set(0);
assert!(plan(&mut service,&mut reported).1);assert!(RESUME.get());
FAIL.set(0);RESUME_FAILURE.set(false);CLOCK_CALLS.set(0);
assert_eq!(plan(&mut service,&mut reported),(2_100_000_000,false));
assert!(!RESUME.get());assert!(!DEFERRED.get());
// Prepared exec cleanup alone must keep observation live after a native image
// replacement, even with no timers, CPU budget, continuation or further RPC.
EXEC_LOCKS.set(true);FAIL.set(0);CLOCK_CALLS.set(0);
assert_eq!(plan(&mut service,&mut reported),(2_010_000_000,false));
FAIL.set(4);CLOCK_CALLS.set(0);
assert!(plan(&mut service,&mut reported).1);assert!(EXEC_LOCKS.get());
FAIL.set(0);CLOCK_CALLS.set(0);
assert_eq!(plan(&mut service,&mut reported),(2_010_000_000,false));
EXEC_LOCKS.set(false);CLOCK_CALLS.set(0);
assert_eq!(plan(&mut service,&mut reported),(2_100_000_000,false));
}
"#,
    );
    probe::run(&program);
}
