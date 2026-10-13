use crate::driver_spawn::DriverProcess;
use alloc::string::String;
use alloc::vec::Vec;

pub(crate) struct StartedDrivers {
    package_ids: Vec<(String, DriverProcess)>,
    failed: Vec<DriverProcess>,
}

impl StartedDrivers {
    pub(crate) const fn new() -> Self {
        Self {
            package_ids: Vec::new(),
            failed: Vec::new(),
        }
    }

    pub(crate) fn contains(&self, package_id: &str) -> bool {
        self.package_ids
            .iter()
            .any(|(started, _)| started == package_id)
    }

    pub(crate) fn record(&mut self, package_id: String, process: DriverProcess) {
        self.package_ids.push((package_id, process));
    }

    pub(crate) fn retain_failed(&mut self, process: DriverProcess) {
        self.failed.push(process);
    }
    pub(crate) fn has_failed_cleanup(&self) -> bool {
        !self.failed.is_empty()
    }
    pub(crate) fn retry_failed(&mut self, endpoint: mochi_user_platform::handle::Handle) {
        let mut index = 0;
        while index < self.failed.len() {
            if self.failed[index].retry_rollback(endpoint).is_ok() {
                self.failed.swap_remove(index);
            } else {
                index += 1;
            }
        }
    }
}
