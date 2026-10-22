//! Saved identities follow committed native images, never a startup claim.
use super::*;

impl<H: Copy> PosixService<H> {
    /// Call at authenticated request admission, before executing POSIX policy.
    /// Frequent native I/O paths do not enter this service or need this check.
    pub fn refresh_image_credentials<P: ProcessBackend<H>>(
        &mut self,
        peer: PeerIdentity,
        processes: &mut P,
    ) -> Result<(), i32> {
        let owner = peer.process_id;
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
            mnu_abi::PROCESS_STATE_EXITED => return Err(protocol::STATUS_ESRCH),
            _ => return Err(protocol::STATUS_EIO),
        }
        let previous = self
            .process_wait_states
            .get(&owner)
            .ok_or(protocol::STATUS_ESRCH)?
            .credential_image_revision;
        if image.image_revision < previous {
            return Err(protocol::STATUS_EIO);
        }
        if image.image_revision == previous {
            return Ok(());
        }
        // No fallible operation follows validation. Re-observing this image
        // must not overwrite saved IDs after a later effective-ID change.
        let session = self
            .sessions
            .get_mut(&owner)
            .ok_or(protocol::STATUS_ESRCH)?;
        session.saved_uid = session.effective_uid;
        session.saved_gid = session.effective_gid;
        self.process_wait_states
            .get_mut(&owner)
            .unwrap()
            .credential_image_revision = image.image_revision;
        Ok(())
    }
}
