//! SIGCONT can originate in backend-free policy paths (including terminal and
//! orphan handling). Keep its notification until native parent image policy is
//! observed; never decide SA_NOCLDSTOP using a stale cached disposition.
use super::*;

#[derive(Clone, Copy, Debug)]
pub(super) struct Deferred {
    parent_id: u64,
    parent_image_revision: u64,
    suppress: bool,
    origin: protocol::signal_origin::Origin,
}

impl<H: Copy> PosixService<H> {
    pub(super) fn defer_parent_of_child_change(
        &mut self,
        child_id: u64,
        child: protocol::signal_origin::ChildStatus,
    ) -> Result<(), i32> {
        let Some(parent_id) = self.parents.get(&child_id).copied() else {
            return Ok(());
        };
        let parent_image_revision = self
            .process_wait_states
            .get(&parent_id)
            .ok_or(protocol::STATUS_ESRCH)?
            .observed_image_revision;
        let suppress = *self
            .signal_child_options
            .get(&parent_id)
            .ok_or(protocol::STATUS_ESRCH)?
            & protocol::SIGNAL_CHILD_OPTION_NOCLDSTOP
            != 0;
        let real_uid = self
            .sessions
            .get(&child_id)
            .ok_or(protocol::STATUS_ESRCH)?
            .real_uid;
        // Capture the event's original relationship and identity. Reparenting
        // or later credential changes must not rewrite an already generated event.
        self.deferred_child_notifications.push_back(Deferred {
            parent_id,
            parent_image_revision,
            suppress,
            origin: protocol::signal_origin::Origin {
                source: protocol::signal_origin::CHILD,
                real_uid,
                process_id: child_id,
                child,
            },
        });
        Ok(())
    }

    pub fn has_deferred_child_notifications(&self) -> bool {
        !self.deferred_child_notifications.is_empty()
    }

    /// Drain independent parents even if another parent's observation fails.
    /// Failed events remain queued, in generation order for each parent.
    pub fn refresh_child_notifications<P: ProcessBackend<H>>(
        &mut self,
        processes: &mut P,
    ) -> Result<usize, i32> {
        let parents: BTreeSet<u64> = self
            .deferred_child_notifications
            .iter()
            .map(|event| event.parent_id)
            .collect();
        let mut completed = 0;
        let mut failure = None;
        for parent in parents {
            match self.refresh_child_notifications_for_parent(parent, processes) {
                Ok(count) => completed += count,
                Err(error) => {
                    failure.get_or_insert(error);
                }
            }
        }
        failure.map_or(Ok(completed), Err)
    }

    pub(super) fn refresh_child_notifications_for_child<P: ProcessBackend<H>>(
        &mut self,
        child: u64,
        processes: &mut P,
    ) -> Result<(), i32> {
        if let Some(parent) = self.parents.get(&child).copied() {
            self.refresh_child_notifications_for_parent(parent, processes)?;
        }
        Ok(())
    }

    fn refresh_child_notifications_for_parent<P: ProcessBackend<H>>(
        &mut self,
        parent: u64,
        processes: &mut P,
    ) -> Result<usize, i32> {
        if !self
            .deferred_child_notifications
            .iter()
            .any(|event| event.parent_id == parent)
        {
            return Ok(0);
        }
        self.refresh_process_image_state(parent, true, processes)?;
        let revision = self.process_wait_states[&parent].observed_image_revision;
        let mut completed = 0;
        while let Some(index) = self
            .deferred_child_notifications
            .iter()
            .position(|event| event.parent_id == parent)
        {
            let event = self.deferred_child_notifications[index];
            // Same-image action changes after generation cannot rewrite the
            // event. Across an unobserved exec, the old NOCLDSTOP is reset.
            let suppress = event.parent_image_revision == revision && event.suppress;
            if !suppress {
                self.enqueue_signal_with_origin(parent, protocol::SIGNAL_CHLD, event.origin)?;
            }
            self.deferred_child_notifications.remove(index);
            completed += 1;
        }
        Ok(completed)
    }

    pub(super) fn discard_child_notifications_to(&mut self, parent: u64) {
        self.deferred_child_notifications
            .retain(|event| event.parent_id != parent);
    }
}
