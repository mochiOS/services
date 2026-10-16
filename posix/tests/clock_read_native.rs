#[path = "support/native_error_probe.rs"]
#[allow(dead_code)]
mod probe;

#[test]
fn clock_sampling_keeps_native_selectors_authority_and_typed_failures() {
    assert_eq!(core::mem::size_of::<mnu_abi::ClockInstant>(), 16);
    let abi = include_str!("../../../core/crates/abi/src/lib.rs");
    let source = include_str!("../../../core/src/syscall/time.rs");
    let mut program =
        String::from("#![allow(dead_code)]\nextern crate self as mnu_abi;\nmod status {\n");
    program.push_str(include_str!("../../../core/crates/abi/src/status.rs"));
    program.push_str("}\nuse status::Error;\n#[derive(Clone,Copy,PartialEq,Eq)]\n");
    program.push_str(probe::between(abi, "pub enum ClockId {", "\n#[repr(C)]"));
    program.push_str(r#"
use std::cell::RefCell;
#[repr(C)] struct ClockInstant {seconds:u64,nanoseconds:u32,reserved:u32}
const SUCCESS:u64=0;
struct State {authorized:bool,ready:bool,frequency:u64,thread:bool,present:bool,process:bool,copies:usize,copy_error:Option<Error>}
impl Default for State {fn default()->Self{Self{authorized:true,ready:true,frequency:10,thread:true,present:true,process:true,copies:0,copy_error:None}}}
thread_local!{static STATE:RefCell<State>=RefCell::new(State::default());}
fn realtime()->Result<(u64,u64),()>{STATE.with_borrow(|s|if s.ready{Ok((1700000000,123))}else{Err(())})}
fn get_ticks()->u64{23}
mod capability {#[derive(PartialEq,Eq,Debug)] pub enum Capability {SystemTimeRead}}
mod syscall {
    pub fn validate_user_ptr(pointer:u64,length:u64)->bool{assert_eq!(length,16);pointer>1}
    pub fn copy_to_user_native(pointer:u64,bytes:&[u8])->Result<(),crate::Error>{
        assert_eq!(bytes.len(),16);
        crate::STATE.with_borrow_mut(|s|{s.copies+=1;if let Some(error)=s.copy_error{return Err(error);}
            unsafe{std::ptr::copy_nonoverlapping(bytes.as_ptr(),pointer as *mut u8,16)};Ok(())
        })
    }
    pub mod security {
        pub fn caller_has_any_capability(caps:&[crate::capability::Capability])->bool{
            assert_eq!(caps,[crate::capability::Capability::SystemTimeRead]);crate::STATE.with_borrow(|s|s.authorized)
        }
    }
}
mod interrupt {pub mod timer {
    pub fn ticks_per_second()->u64{crate::STATE.with_borrow(|s|s.frequency)}
    pub fn tick_ms()->u64{100}
}}
mod task {
    pub struct Thread;
    impl Thread {pub fn cpu_ticks(&self)->u64{42} pub fn process_cpu_ticks(&self)->Option<u64>{crate::STATE.with_borrow(|s|s.process.then_some(55))}}
    pub fn current_thread_id()->Option<u64>{crate::STATE.with_borrow(|s|s.thread.then_some(7))}
    pub fn with_thread<T>(id:u64,operation:impl FnOnce(&Thread)->T)->Option<T>{assert_eq!(id,7);if crate::STATE.with_borrow(|s|s.present){Some(operation(&Thread))}else{None}}
}
"#);
    program.push_str(probe::between(
        source,
        "pub fn clock_read(",
        "/// SleepUntil",
    ));
    program.push_str(r#"
fn main(){
    let mut bytes=[0x71_u8;16];let pointer=bytes.as_mut_ptr() as u64;
    for (clock,seconds,nanos) in [(ClockId::Realtime,1700000000,123),(ClockId::Monotonic,2,300000000),(ClockId::ThreadCpu,4,200000000),(ClockId::ProcessCpu,5,500000000)] {
        STATE.set(State::default());assert_eq!(clock_read(clock as u64,pointer),0);
        assert_eq!(u64::from_le_bytes(bytes[..8].try_into().unwrap()),seconds);
        assert_eq!(u32::from_le_bytes(bytes[8..12].try_into().unwrap()),nanos);assert_eq!(bytes[12..],[0;4]);
    }
    for invalid in [0,1,2,3,4,u64::MAX] {
        STATE.set(State::default());bytes.fill(0x71);
        assert_eq!(clock_read(invalid,pointer),Error::InvalidArgument.into_raw());assert_eq!(bytes,[0x71;16]);
        STATE.with_borrow(|s|assert_eq!(s.copies,0));
    }
    for output in [0,1] {assert_eq!(clock_read(ClockId::Monotonic as u64,output),Error::InvalidAddress.into_raw());}
    STATE.set(State{authorized:false,..State::default()});
    assert_eq!(clock_read(ClockId::Realtime as u64,pointer),Error::AccessDenied.into_raw());
    STATE.with_borrow(|s|assert_eq!(s.copies,0));
    // Unprivileged clocks do not acquire realtime authority accidentally.
    assert_eq!(clock_read(ClockId::Monotonic as u64,pointer),0);
    for state in [State{frequency:0,..State::default()},State{ready:false,..State::default()}] {
        STATE.set(state);assert_eq!(clock_read(ClockId::Realtime as u64,pointer),Error::NotReady.into_raw());
        STATE.with_borrow(|s|assert_eq!(s.copies,0));
    }
    for clock in [ClockId::ThreadCpu,ClockId::ProcessCpu] {
        for state in [State{thread:false,..State::default()},State{present:false,..State::default()}] {
            STATE.set(state);assert_eq!(clock_read(clock as u64,pointer),Error::NotReady.into_raw());
            STATE.with_borrow(|s|assert_eq!(s.copies,0));
        }
    }
    STATE.set(State{process:false,..State::default()});
    assert_eq!(clock_read(ClockId::ProcessCpu as u64,pointer),Error::NotReady.into_raw());
    for error in [Error::InvalidAddress,Error::ResourceUnavailable,Error::BackingFailure] {
        STATE.set(State{copy_error:Some(error),..State::default()});bytes.fill(0x71);
        assert_eq!(clock_read(ClockId::Monotonic as u64,pointer),error.into_raw());assert_eq!(bytes,[0x71;16]);
    }
}
"#);
    probe::run(&program);
}

#[test]
fn native_probe_matches_the_published_clock_and_error_encoding() {
    let source = include_str!("native_clock_status.c");
    let describe = include_str!("native_clock_getres.c");
    assert!(source.contains(&format!(
        "CLOCK_READ = {}",
        mnu_abi::SyscallNumber::ClockRead as u64
    )));
    for (source, name, error) in [
        (
            source,
            "NATIVE_ACCESS_DENIED",
            mnu_abi::status::Error::AccessDenied,
        ),
        (
            describe,
            "NATIVE_INVALID_ARGUMENT",
            mnu_abi::status::Error::InvalidArgument,
        ),
        (
            describe,
            "NATIVE_INVALID_ADDRESS",
            mnu_abi::status::Error::InvalidAddress,
        ),
    ] {
        assert!(source.contains(&format!("{name} INT64_C({})", error.into_raw() as i64)));
    }
}
