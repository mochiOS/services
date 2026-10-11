extern crate self as mochi_user_platform;
extern crate self as mochi_user_syscall;

use std::sync::Mutex;

#[derive(Debug, PartialEq, Eq)]
pub struct SysError;

impl SysError {
    pub fn raw(&self) -> i64 {
        -22
    }
}

#[derive(Default)]
struct State {
    inspected_thread: Option<u64>,
    requested: Option<(u64, u64)>,
    closed: Vec<u32>,
    exited: bool,
    fail_stage: u8,
}

static STATE: Mutex<State> = Mutex::new(State {
    inspected_thread: None,
    requested: None,
    closed: Vec::new(),
    exited: false,
    fail_stage: 0,
});

pub mod handle {
    pub type Handle = u32;
    pub const HANDLE_RIGHT_WAIT: u64 = mnu_abi::HANDLE_RIGHT_WAIT;

    pub fn close(handle: Handle) -> Result<(), super::SysError> {
        super::STATE.lock().unwrap().closed.push(handle);
        Ok(())
    }
}

pub mod process {
    pub const PROCESS_STATE_EXITED: u32 = mnu_abi::PROCESS_STATE_EXITED;

    pub fn thread_security_context(
        thread: u64,
    ) -> Result<mnu_abi::ThreadSecurityContext, super::SysError> {
        if thread != 42 {
            return Err(super::SysError);
        }
        super::STATE.lock().unwrap().inspected_thread = Some(thread);
        if super::STATE.lock().unwrap().fail_stage == 1 {
            return Err(super::SysError);
        }
        Ok(mnu_abi::ThreadSecurityContext {
            process_id: 19,
            thread_id: thread,
            ..Default::default()
        })
    }

    pub fn open_handle_for_process_id(
        process_id: u64,
        rights: u64,
    ) -> Result<u32, super::SysError> {
        if process_id != 19 {
            return Err(super::SysError);
        }
        super::STATE.lock().unwrap().requested = Some((process_id, rights));
        if super::STATE.lock().unwrap().fail_stage == 2 {
            return Err(super::SysError);
        }
        Ok(7)
    }

    pub fn handle_status(handle: u32) -> Result<mnu_abi::ProcessStatus, super::SysError> {
        assert_eq!(handle, 7);
        if super::STATE.lock().unwrap().fail_stage == 3 {
            return Err(super::SysError);
        }
        Ok(mnu_abi::ProcessStatus {
            // An extra worker thread makes thread 42 belong to process 19.
            process_id: 19,
            state: if super::STATE.lock().unwrap().exited {
                PROCESS_STATE_EXITED
            } else {
                mnu_abi::PROCESS_STATE_RUNNING
            },
            exit_code: 127,
            reserved: 0,
        })
    }
}

#[path = "../../service-manager/src/process_watch.rs"]
mod production;

#[test]
fn readiness_resolves_the_launch_thread_before_watching_its_process() {
    let watch = production::ProcessWatch::open(42).unwrap();
    assert_eq!(
        STATE.lock().unwrap().requested,
        Some((19, handle::HANDLE_RIGHT_WAIT))
    );
    assert_eq!(STATE.lock().unwrap().inspected_thread, Some(42));
    assert_eq!(watch.exit_status(), Ok(None));
    STATE.lock().unwrap().exited = true;
    assert_eq!(watch.exit_status(), Ok(Some(127)));
    drop(watch);
    assert_eq!(STATE.lock().unwrap().closed, [7]);

    // A vanished launch thread is not proof of successful process exit.
    STATE.lock().unwrap().fail_stage = 1;
    assert!(matches!(
        production::ProcessWatch::open(42),
        Err(production::ProcessWatchError::ResolveLaunchThread(22))
    ));
    assert_eq!(STATE.lock().unwrap().closed, [7]);

    STATE.lock().unwrap().fail_stage = 2;
    assert!(matches!(
        production::ProcessWatch::open(42),
        Err(production::ProcessWatchError::OpenProcess(22))
    ));
    assert_eq!(STATE.lock().unwrap().closed, [7]);

    STATE.lock().unwrap().fail_stage = 0;
    let watch = production::ProcessWatch::open(42).unwrap();
    STATE.lock().unwrap().fail_stage = 3;
    assert_eq!(
        watch.exit_status(),
        Err(production::ProcessWatchError::ReadStatus(22))
    );
    assert_eq!(production::ProcessWatchError::ReadStatus(22).errno(), 22);
    drop(watch);
    assert_eq!(STATE.lock().unwrap().closed, [7, 7]);
}
