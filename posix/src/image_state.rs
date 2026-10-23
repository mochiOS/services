//! POSIX image-local policy follows native commits, never startup claims.
use super::*;

/// Service-local request provenance, never decoded from client request bytes.
#[derive(Clone, Copy, Debug)]
pub struct RequestImage {
    process_id: u64,
    revision: u64,
}

impl<H: Copy> PosixService<H> {
    /// Capture immediately after authenticated admission observes native state.
    pub fn capture_request_image(&self, peer: PeerIdentity) -> Result<RequestImage, i32> {
        self.processes
            .get(&peer.process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        let state = self
            .process_wait_states
            .get(&peer.process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        Ok(RequestImage {
            process_id: peer.process_id,
            revision: state.observed_image_revision,
        })
    }

    /// A deferred request from an old image must not consume a new image's
    /// child status or pending signals, even if its native thread ID survives.
    pub fn validate_request_image<P: ProcessBackend<H>>(
        &mut self,
        peer: PeerIdentity,
        image: RequestImage,
        processes: &mut P,
    ) -> Result<(), i32> {
        if image.process_id != peer.process_id {
            return Err(protocol::STATUS_EPERM);
        }
        self.refresh_image_state(peer, processes)?;
        if self.process_wait_states[&peer.process_id].observed_image_revision != image.revision {
            return Err(protocol::STATUS_ESRCH);
        }
        Ok(())
    }

    /// Call at authenticated request admission, before executing POSIX policy.
    /// Frequent native I/O paths do not enter this service or need this check.
    pub fn refresh_image_state<P: ProcessBackend<H>>(
        &mut self,
        peer: PeerIdentity,
        processes: &mut P,
    ) -> Result<(), i32> {
        self.refresh_process_image_state(peer.process_id, false, processes)
    }

    /// Lifecycle observers may still need the last image policy of an exited
    /// parent whose retained native object and POSIX environment remain owned.
    pub(super) fn refresh_process_image_state<P: ProcessBackend<H>>(
        &mut self,
        owner: u64,
        allow_exited: bool,
        processes: &mut P,
    ) -> Result<(), i32> {
        let handle = self
            .processes
            .get(&owner)
            .copied()
            .ok_or(protocol::STATUS_ESRCH)?;
        let image = processes.image_status(handle)?;
        if image.process_id != owner || image.reserved != 0 {
            return Err(protocol::STATUS_EIO);
        }
        match image.state {
            mnu_abi::PROCESS_STATE_RUNNING => {}
            mnu_abi::PROCESS_STATE_EXITED if allow_exited => {}
            mnu_abi::PROCESS_STATE_EXITED => return Err(protocol::STATUS_ESRCH),
            _ => return Err(protocol::STATUS_EIO),
        }
        let previous = self
            .process_wait_states
            .get(&owner)
            .ok_or(protocol::STATUS_ESRCH)?
            .observed_image_revision;
        if image.image_revision < previous {
            return Err(protocol::STATUS_EIO);
        }
        if image.image_revision == previous {
            return Ok(());
        }
        self.signals.get(&owner).ok_or(protocol::STATUS_ESRCH)?;
        self.signal_child_options
            .get(&owner)
            .ok_or(protocol::STATUS_ESRCH)?;
        // No fallible operation follows validation. Re-observing this image
        // must not overwrite saved IDs after a later effective-ID change.
        let session = self
            .sessions
            .get_mut(&owner)
            .ok_or(protocol::STATUS_ESRCH)?;
        session.saved_uid = session.effective_uid;
        session.saved_gid = session.effective_gid;
        self.record_lock_execs.commit_observed(
            owner,
            image.image_revision,
            &mut self.record_locks,
        );
        self.publish_record_lock_state(owner);
        self.reset_image_signals(owner);
        self.process_wait_states
            .get_mut(&owner)
            .unwrap()
            .observed_image_revision = image.image_revision;
        Ok(())
    }

    // All maps are validated before native-image observation commits; fresh
    // launch paths call this only after their complete environment is installed.
    pub(super) fn reset_image_signals(&mut self, owner: u64) {
        // POSIX per-process timers are image-local. Unlike alarm/setitimer,
        // they do not survive exec; a startup claim alone cannot reach here.
        self.process_timers.retire_owner(owner);
        self.signals.get_mut(&owner).unwrap().caught = 0;
        *self.signal_child_options.get_mut(&owner).unwrap() = 0;
        // The native replacement retires siblings as well as the caller's
        // old upcall frames. No old handler in this process can complete.
        self.process_wait_states
            .get_mut(&owner)
            .unwrap()
            .deliveries
            .clear();
        // Preserve SIG_IGN, process/thread pending sets, origins, and masks.
    }
}
