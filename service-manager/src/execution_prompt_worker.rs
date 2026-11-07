//! Keep one measured execution presenter prepared without blocking dispatch.
use crate::presenter::{Kind, Slot};

#[derive(Default)]
pub(crate) struct Presenter {
    slot: Slot,
}

impl Presenter {
    pub(crate) fn maintain(&mut self, logger: u64) {
        self.slot.maintain(Kind::Execution, logger);
    }
}
