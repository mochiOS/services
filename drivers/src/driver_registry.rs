use alloc::string::String;
use alloc::vec::Vec;

pub(crate) struct StartedDrivers {
    package_ids: Vec<String>,
}

impl StartedDrivers {
    pub(crate) const fn new() -> Self {
        Self {
            package_ids: Vec::new(),
        }
    }

    pub(crate) fn contains(&self, package_id: &str) -> bool {
        self.package_ids.iter().any(|started| started == package_id)
    }

    pub(crate) fn record(&mut self, package_id: String) {
        self.package_ids.push(package_id);
    }
}
