extern crate self as mochi_user_platform;
extern crate self as mochi_user_syscall;

use std::sync::Mutex;

#[derive(Debug, PartialEq, Eq)]
pub struct SysError;

#[derive(Default)]
struct State {
    requested: Option<(u64, u64)>,
    closed: Vec<u32>,
    exited: bool,
}

static STATE: Mutex<State> = Mutex::new(State {
    requested: None,
    closed: Vec::new(),
    exited: false,
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

    pub fn open_handle_for_endpoint(endpoint: u64, rights: u64) -> Result<u32, super::SysError> {
        if endpoint != 42 {
            return Err(super::SysError);
        }
        super::STATE.lock().unwrap().requested = Some((endpoint, rights));
        Ok(7)
    }

    pub fn handle_status(handle: u32) -> Result<mnu_abi::ProcessStatus, super::SysError> {
        assert_eq!(handle, 7);
        Ok(mnu_abi::ProcessStatus {
            // An extra worker thread makes endpoint 42 belong to process 19.
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
fn readiness_watches_the_launched_endpoint_owner_not_a_same_numbered_process() {
    let watch = production::ProcessWatch::open(42).unwrap();
    assert_eq!(
        STATE.lock().unwrap().requested,
        Some((42, handle::HANDLE_RIGHT_WAIT))
    );
    assert_eq!(watch.exit_status(), Ok(None));
    STATE.lock().unwrap().exited = true;
    assert_eq!(watch.exit_status(), Ok(Some(127)));
    drop(watch);
    assert_eq!(STATE.lock().unwrap().closed, [7]);
}
