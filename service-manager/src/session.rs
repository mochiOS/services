use alloc::vec::Vec;

use mochi_user_platform as platform;

const MAX_PROCESS_RECORDS: usize = 512;
// Native process teardown is deliberately independent of POSIX signals.
const FORCED_TERMINATION_EXIT_CODE: u64 = 1;
const PROCESS_STATE_TERMINATED: u64 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ActiveSession {
    pub(crate) id: u64,
    pub(crate) identity: platform::service_ready::SessionIdentity,
    pub(crate) linux_pid: Option<u64>,
    pub(crate) workspace_pid: u64,
    pub(crate) binder_pid: u64,
}

impl ActiveSession {
    pub(crate) fn next_id(self) -> u64 {
        self.id.wrapping_add(1).max(1)
    }
}

pub(crate) fn terminate_process_tree(root_pid: u64) -> Result<(), mochi_user_syscall::SysError> {
    let records = platform::process::list(MAX_PROCESS_RECORDS)?;
    let mut processes = descendant_processes(&records, root_pid);
    processes.retain(|pid| *pid != root_pid);
    for pid in processes.into_iter().rev() {
        let _ = terminate_process(pid);
    }
    terminate_process(root_pid)
}

fn terminate_process(process_id: u64) -> Result<(), mochi_user_syscall::SysError> {
    let handle = platform::process::open_handle_for_process_id(
        process_id,
        platform::handle::HANDLE_RIGHT_SIGNAL,
    )?;
    let result = platform::process::terminate_handle(handle, FORCED_TERMINATION_EXIT_CODE);
    let _ = platform::handle::close(handle);
    result
}

fn descendant_processes(records: &[platform::process::Record], root_pid: u64) -> Vec<u64> {
    let mut result = Vec::new();
    result.push(root_pid);
    loop {
        let mut changed = false;
        for record in records {
            if record.pid == 0
                || record.state == PROCESS_STATE_TERMINATED
                || result.contains(&record.pid)
                || !result.contains(&record.parent_pid)
            {
                continue;
            }
            result.push(record.pid);
            changed = true;
        }
        if !changed {
            break;
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(pid: u64, parent_pid: u64) -> platform::process::Record {
        platform::process::Record {
            pid,
            state: 1,
            parent_pid,
            cpu_ticks: 0,
            memory_bytes: 0,
            thread_count: 0,
        }
    }

    #[test]
    fn finds_only_the_active_session_process_tree() {
        let records = [
            record(2, 1),
            record(10, 2),
            record(11, 10),
            record(12, 11),
            record(20, 2),
        ];
        assert_eq!(descendant_processes(&records, 10), [10, 11, 12]);
    }

    #[test]
    fn session_ids_never_become_zero() {
        let session = ActiveSession {
            id: u64::MAX,
            identity: platform::service_ready::SessionIdentity { uid: 1, gid: 1 },
            linux_pid: Some(3),
            workspace_pid: 4,
            binder_pid: 2,
        };
        assert_eq!(session.next_id(), 1);
    }
}
