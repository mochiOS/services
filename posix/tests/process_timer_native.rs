//! Execute the production native adapter; only primitive observations are
//! controlled. Use the actual ABI types, clock IDs and status translation.
extern crate mnu_abi as real_abi;
extern crate mochios_posix_protocol as real_protocol;
extern crate posix_service as real_service;
extern crate self as mnu_abi;
extern crate self as mochi_user_platform;
extern crate self as mochios_posix_protocol;
extern crate self as posix_service;
pub use real_abi::{
    ClockId, ClockInstant, ProcessExecutionUsage, THREAD_STATE_READY, THREAD_STATE_TERMINATED,
    ThreadStatus,
};
pub use real_protocol::{STATUS_EIO, STATUS_EPERM, STATUS_ESRCH};
pub use real_service::STATUS_EINVAL;
pub mod process_timer {
    pub use real_protocol::process_timer::Clock;
}
pub mod process_timer_request {
    pub use real_service::process_timer_request::{Reading, cpu_nanoseconds};
}
pub mod status {
    pub use real_abi::status::Error;
    pub use real_protocol::status::*;
}
use std::cell::RefCell;
#[path = "../src/process_timer_native.rs"]
mod native;
#[derive(Clone, Copy, Debug)]
pub struct Failure(i64);
impl Failure {
    pub fn raw(self) -> i64 {
        self.0
    }
}
struct State {
    clock: Result<ClockInstant, Failure>,
    usage: Result<ProcessExecutionUsage, Failure>,
    owners: Vec<Option<u32>>,
    clocks: Vec<u64>,
    thread_status: Result<ThreadStatus, Failure>,
    thread_clocks: Vec<u32>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            clock: Ok(ClockInstant {
                seconds: 7,
                nanoseconds: 13,
                reserved: 0,
            }),
            usage: Ok(ProcessExecutionUsage {
                user_ticks: 11,
                kernel_ticks: 4,
                ticks_per_second: 10,
                reserved: 0,
            }),
            owners: Vec::new(),
            clocks: Vec::new(),
            thread_status: Ok(ThreadStatus {
                thread_id: 7,
                process_id: 41,
                state: real_abi::THREAD_STATE_RUNNING,
                reserved: 0,
            }),
            thread_clocks: Vec::new(),
        }
    }
}
thread_local! { static STATE: RefCell<State> = RefCell::new(State::default()); }
pub mod syscall {
    use super::*;
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SyscallNumber {
        ClockRead,
    }
    pub fn call2(number: SyscallNumber, clock: u64, output: u64) -> Result<u64, Failure> {
        assert_eq!(number, SyscallNumber::ClockRead);
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            state.clocks.push(clock);
            let value = state.clock?;
            // Only production's own stack-local ClockInstant reaches this
            // controlled primitive; this is not a C application pointer.
            unsafe {
                (output as *mut ClockInstant).write(value);
            }
            Ok(0)
        })
    }
}
pub mod process {
    use super::*;
    pub fn execution_usage(owner: Option<u32>) -> Result<ProcessExecutionUsage, Failure> {
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            state.owners.push(owner);
            state.usage
        })
    }
}
pub mod thread {
    use super::*;
    pub fn handle_status(handle: u32) -> Result<ThreadStatus, Failure> {
        assert_eq!(handle, 81);
        STATE.with(|state| state.borrow().thread_status)
    }
    pub fn cpu_clock(handle: u32) -> Result<ClockInstant, Failure> {
        assert_eq!(handle, 81);
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            state.thread_clocks.push(handle);
            state.clock
        })
    }
}
use process_timer::Clock;
use process_timer_request::Reading;

#[test]
fn thread_clock_adapter_authenticates_retained_target_and_never_uses_service_cpu() {
    STATE.with(|state| *state.borrow_mut() = State::default());
    assert_eq!(native::thread_target(41, 81), Ok(7));
    assert_eq!(native::thread_target(99, 81), Err(STATUS_EPERM));
    assert_eq!(native::thread_target(0, 81), Err(STATUS_EPERM));
    for (owner, target) in [(0, 7), (41, 0), (99, 7), (41, 8)] {
        assert_eq!(
            native::read_thread(owner, target, 81).err(),
            Some(STATUS_EPERM)
        );
    }
    STATE.with(|state| assert!(state.borrow().thread_clocks.is_empty()));
    for (state, reserved, error) in [
        (0, 0, STATUS_EIO),
        (99, 0, STATUS_EIO),
        (2, 1, STATUS_EIO),
        (5, 0, STATUS_ESRCH),
    ] {
        STATE.with(|control| {
            control.borrow_mut().thread_status = Ok(ThreadStatus {
                thread_id: 7,
                process_id: 41,
                state,
                reserved,
            })
        });
        assert_eq!(native::read_thread(41, 7, 81).err(), Some(error));
        assert_eq!(native::thread_target(41, 81), Err(error));
    }
    STATE.with(|state| *state.borrow_mut() = State::default());
    assert!(matches!(
        native::read_thread(41, 7, 81),
        Ok(Reading::Counter(7_000_000_013))
    ));
    STATE.with(|state| {
        let state = state.borrow();
        assert_eq!(state.thread_clocks, [81]);
        assert!(state.clocks.is_empty());
        assert!(state.owners.is_empty());
    });
    STATE.with(|state| {
        state.borrow_mut().thread_status =
            Err(Failure(real_abi::status::Error::NotFound.into_raw() as i64))
    });
    assert_eq!(native::read_thread(41, 7, 81).err(), Some(STATUS_ESRCH));
    assert_eq!(native::thread_target(41, 81), Err(STATUS_ESRCH));
    STATE.with(|state| *state.borrow_mut() = State::default());
    STATE.with(|state| {
        state.borrow_mut().clock = Ok(ClockInstant {
            seconds: 0,
            nanoseconds: 1_000_000_000,
            reserved: 0,
        })
    });
    assert_eq!(native::read_thread(41, 7, 81).err(), Some(STATUS_EIO));
}

#[test]
fn cpu_timer_reads_retained_owner_not_current_service_cpu_clock() {
    STATE.with(|s| *s.borrow_mut() = State::default());
    assert!(matches!(
        native::read(41, Clock::ProcessCpu),
        Ok(Reading::Counter(1_500_000_000))
    ));
    STATE.with(|s| {
        assert_eq!(s.borrow().owners, vec![Some(41)]);
        assert!(s.borrow().clocks.is_empty());
        s.borrow_mut().usage = Ok(ProcessExecutionUsage {
            user_ticks: u64::MAX,
            kernel_ticks: u64::MAX,
            ticks_per_second: 1,
            reserved: 0,
        });
    });
    let expected = 2 * u128::from(u64::MAX) * 1_000_000_000;
    assert!(
        matches!(native::read(71, Clock::ProcessCpu), Ok(Reading::Counter(value)) if value == expected)
    );
}

#[test]
fn elapsed_and_civil_clocks_use_actual_native_ids_without_losing_nanoseconds() {
    STATE.with(|s| *s.borrow_mut() = State::default());
    assert!(matches!(
        native::read(41, Clock::Realtime),
        Ok(Reading::Realtime(7_000_000_013))
    ));
    assert!(matches!(
        native::read(41, Clock::Monotonic),
        Ok(Reading::Counter(7_000_000_013))
    ));
    STATE.with(|s| {
        assert_eq!(
            s.borrow().clocks,
            vec![ClockId::Realtime as u64, ClockId::Monotonic as u64]
        );
        assert!(s.borrow().owners.is_empty());
    });
}

#[test]
fn invalid_samples_and_native_failures_are_not_replaced_by_clock_zero_or_another_clock() {
    STATE.with(|s| *s.borrow_mut() = State::default());
    for (nanoseconds, reserved) in [(1_000_000_000, 0), (0, 1)] {
        STATE.with(|s| {
            s.borrow_mut().clock = Ok(ClockInstant {
                seconds: 0,
                nanoseconds,
                reserved,
            })
        });
        assert_eq!(native::read(41, Clock::Realtime).err(), Some(STATUS_EIO));
    }
    for (ticks_per_second, reserved) in [(0, 0), (1, 1)] {
        STATE.with(|s| {
            s.borrow_mut().usage = Ok(ProcessExecutionUsage {
                user_ticks: 0,
                kernel_ticks: 0,
                ticks_per_second,
                reserved,
            })
        });
        assert_eq!(native::read(41, Clock::ProcessCpu).err(), Some(STATUS_EIO));
    }
    let error = real_abi::status::Error::AccessDenied.into_raw() as i64;
    STATE.with(|s| {
        s.borrow_mut().clock = Err(Failure(error));
        s.borrow_mut().usage = Err(Failure(error));
    });
    assert_eq!(native::read(41, Clock::Realtime).err(), Some(-13));
    assert_eq!(native::read(41, Clock::ProcessCpu).err(), Some(-13));
}
