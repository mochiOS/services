extern crate alloc;
extern crate self as mochi_user_platform;
extern crate self as mochi_user_syscall;
extern crate self as mochios_posix_client;

use std::sync::Mutex;

pub const EIO: u64 = mnu_abi::EIO;
pub mod syscall {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct SysError(pub i64);
    impl SysError {
        pub fn from_raw(raw: i64) -> Self {
            Self(raw)
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub enum ClientError {
    Transport(syscall::SysError),
    Remote(i32),
    Malformed,
}
pub struct ObjectHandleAttachment<H = u32> {
    pub handle: H,
    pub rights: u64,
}
pub struct SyscallEndpointTransport(u32);
impl SyscallEndpointTransport {
    pub fn new(endpoint: u32) -> Self {
        Self(endpoint)
    }
}
pub struct Client<T>(T);
impl Client<SyscallEndpointTransport> {
    pub fn new(transport: SyscallEndpointTransport) -> Self {
        Self(transport)
    }
    pub fn abort_launched_child(
        &self,
        attachment: ObjectHandleAttachment,
    ) -> Result<(), ClientError> {
        assert_eq!(self.0.0, 41);
        assert_eq!(attachment.handle, 7);
        assert_eq!(attachment.rights, mnu_abi::HANDLE_RIGHT_WAIT);
        // Exercise the production queue's lock discipline during its RPC.
        assert!(!production::has_failed_launch_cleanup());
        let mut state = STATE.lock().unwrap();
        state.events.push("abort-registration");
        state.reply
    }
}
struct State {
    exited: bool,
    status_error: bool,
    termination_pending: bool,
    reply: Result<(), ClientError>,
    events: Vec<&'static str>,
    log_count: usize,
}
static STATE: Mutex<State> = Mutex::new(State {
    exited: false,
    status_error: false,
    termination_pending: true,
    reply: Ok(()),
    events: Vec::new(),
    log_count: 0,
});
#[macro_export]
macro_rules! logln {
    ($($argument:tt)*) => {{
        let _ = format!($($argument)*);
        $crate::STATE.lock().unwrap().log_count += 1;
    }};
}
pub mod handle {
    pub type Handle = u32;
    pub use mnu_abi::{HANDLE_RIGHT_SIGNAL, HANDLE_RIGHT_WAIT};
    pub fn close(handle: u32) -> Result<(), crate::syscall::SysError> {
        assert_eq!(handle, 7);
        crate::STATE.lock().unwrap().events.push("close");
        Ok(())
    }
}
pub mod process {
    pub struct Status {
        pub process_id: u64,
        pub state: u32,
    }
    pub fn create_stopped(_: u32, _: &[u8]) -> Result<u32, crate::syscall::SysError> {
        Ok(7)
    }
    pub fn handle_status(handle: u32) -> Result<Status, crate::syscall::SysError> {
        assert_eq!(handle, 7);
        let state = crate::STATE.lock().unwrap();
        if state.status_error {
            return Err(crate::syscall::SysError(-5));
        }
        Ok(Status {
            process_id: 70,
            state: if state.exited {
                mnu_abi::PROCESS_STATE_EXITED
            } else {
                mnu_abi::PROCESS_STATE_RUNNING
            },
        })
    }
    pub fn terminate_handle(handle: u32, code: u64) -> Result<(), crate::syscall::SysError> {
        assert_eq!((handle, code), (7, 127));
        let mut state = crate::STATE.lock().unwrap();
        state.events.push("terminate");
        if !state.termination_pending {
            state.exited = true;
        }
        Ok(())
    }
    pub fn resume_handle(_: u32) -> Result<(), crate::syscall::SysError> {
        panic!("failed registration must not resume")
    }
}
pub mod process_watch {
    pub enum ProcessWatchTarget {
        RetainedHandle(u32),
    }
}
pub mod thread {
    pub fn sleep_milliseconds(milliseconds: u64) -> Result<(), crate::syscall::SysError> {
        assert_eq!(milliseconds, 10);
        assert!(crate::production::has_failed_launch_cleanup());
        crate::STATE.lock().unwrap().events.push("throttle");
        Ok(())
    }
}
mod spawn_support {
    pub fn sys_error(errno: u64) -> crate::syscall::SysError {
        crate::syscall::SysError(-((errno as i64).unsigned_abs() as i64))
    }
    pub fn errno(error: crate::syscall::SysError) -> u64 {
        error.0.unsigned_abs()
    }
}
#[allow(dead_code)]
#[path = "../../service-manager/src/native_process.rs"]
mod native_process;
#[path = "../../service-manager/src/launch_rollback.rs"]
mod production;

#[test]
fn real_rollback_queue_retains_owner_across_native_and_ipc_failures() {
    assert!(!production::has_failed_launch_cleanup());
    let result = native_process::NativeProcess::create_with_rollback(
        9,
        b"metadata",
        |_| Err(syscall::SysError(-13)),
        |owner| production::retain_failed_launch(owner, 41),
    );
    assert_eq!(result.unwrap_err(), syscall::SysError(-13));
    assert!(production::has_failed_launch_cleanup());
    assert_eq!(STATE.lock().unwrap().events, ["terminate"]);

    STATE.lock().unwrap().status_error = true;
    production::retry_failed_launch_cleanup();
    assert!(production::has_failed_launch_cleanup());
    assert_eq!(STATE.lock().unwrap().events, ["terminate", "throttle"]);

    STATE.lock().unwrap().status_error = false;
    // Even an ESRCH response cannot close a process whose exit is unconfirmed.
    STATE.lock().unwrap().reply = Err(ClientError::Remote(-3));
    production::retry_failed_launch_cleanup();
    assert!(!STATE.lock().unwrap().events.contains(&"abort-registration"));
    assert!(!STATE.lock().unwrap().events.contains(&"close"));

    STATE.lock().unwrap().exited = true;
    for reply in [
        Err(ClientError::Transport(syscall::SysError(-5))),
        Err(ClientError::Remote(-1)),
        Err(ClientError::Malformed),
    ] {
        STATE.lock().unwrap().reply = reply;
        production::retry_failed_launch_cleanup();
        assert!(production::has_failed_launch_cleanup());
        assert!(!STATE.lock().unwrap().events.contains(&"close"));
    }
    // A server-side reclaim with a lost response is retried with the same
    // retained Handle. Its authenticated absence is accepted only after exit.
    STATE.lock().unwrap().reply = Err(ClientError::Transport(syscall::SysError(-5)));
    production::retry_failed_launch_cleanup();
    assert_eq!(STATE.lock().unwrap().log_count, 5);
    let before = STATE.lock().unwrap().events.len();
    STATE.lock().unwrap().reply = Err(ClientError::Remote(-3));
    production::retry_failed_launch_cleanup();
    assert!(!production::has_failed_launch_cleanup());
    assert_eq!(
        &STATE.lock().unwrap().events[before..],
        ["abort-registration", "close"]
    );
    production::retry_failed_launch_cleanup();
    assert_eq!(
        STATE
            .lock()
            .unwrap()
            .events
            .iter()
            .filter(|event| **event == "close")
            .count(),
        1
    );
    assert_eq!(
        STATE
            .lock()
            .unwrap()
            .events
            .iter()
            .filter(|event| **event == "terminate")
            .count(),
        2
    );

    // The ordinary acknowledged-success path likewise closes once.
    let result = native_process::NativeProcess::create_with_rollback(
        9,
        b"metadata",
        |_| Err(syscall::SysError(-13)),
        |owner| production::retain_failed_launch(owner, 41),
    );
    assert!(result.is_err());
    STATE.lock().unwrap().reply = Ok(());
    production::retry_failed_launch_cleanup();
    assert!(!production::has_failed_launch_cleanup());
    assert_eq!(
        STATE
            .lock()
            .unwrap()
            .events
            .iter()
            .filter(|event| **event == "close")
            .count(),
        2
    );
}
