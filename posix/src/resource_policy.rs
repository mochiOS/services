//! Authenticated, process-owned resource policy publishers. A reader gets no
//! writer/extent authority and may not select another process with PID bytes.
use super::*;

pub trait Published<H>: core::fmt::Debug + Send {
    /// Called under service state synchronization: no IPC, user callback or
    /// re-entry is allowed. A failure must leave the published value unchanged.
    fn publish(&self, resource: u32, limit: protocol::ResourceLimit) -> Result<(), i32>;
    /// Return one independently owned temporary reference. Its actual native
    /// rights must permit IPC transfer; requested reply rights are READ|MAP
    /// only. The transport closes this temporary reference after reply.
    fn delegate(&self) -> Result<OpenedObject<H>, i32>;
}

pub trait Factory<H> {
    fn create(
        &mut self,
        limits: [protocol::ResourceLimit; protocol::RLIMIT_COUNT as usize],
    ) -> Result<Box<dyn Published<H>>, i32>;
}

impl<H: Copy> PosixService<H> {
    pub fn handle_resource_policy<B: Factory<H>>(
        &mut self,
        peer: PeerIdentity,
        header: protocol::Header,
        payload: &[u8],
        attached: &[AttachedObject<H>],
        backend: &mut B,
    ) -> ObjectResponse<H> {
        if header.opcode != protocol::OP_RESOURCE_POLICY
            || header.flags != 0
            || header.status != 0
            || !payload.is_empty()
            || !attached.is_empty()
        {
            return object_error(header.request_id, STATUS_EINVAL);
        }
        let mut handles = Vec::new();
        if handles.try_reserve_exact(1).is_err() {
            return object_error(header.request_id, -12);
        }
        let page = match self.resource_policy_handle(peer.process_id, backend) {
            Ok(page) => page,
            Err(error) => return object_error(header.request_id, error),
        };
        handles.push(page);
        ObjectResponse {
            response: status_response(header.request_id, 0),
            handles,
        }
    }

    fn resource_policy_handle<B: Factory<H>>(
        &mut self,
        owner: u64,
        backend: &mut B,
    ) -> Result<OpenedObject<H>, i32> {
        if !self.sessions.contains_key(&owner)
            || !self.processes.contains_key(&owner)
            || self
                .process_wait_states
                .get(&owner)
                .is_some_and(|state| state.exit_observed)
        {
            return Err(protocol::STATUS_ESRCH);
        }
        if let Some((_, page)) = self
            .resource_policies
            .iter()
            .find(|(process, _)| *process == owner)
        {
            return page.delegate();
        }
        self.resource_policies.try_reserve(1).map_err(|_| -12)?;
        let limits = core::array::from_fn(|resource| {
            self.resource_limits
                .get(&(owner, resource as u32))
                .copied()
                .unwrap_or_default()
        });
        let page = backend.create(limits)?;
        let offered = page.delegate()?;
        self.resource_policies.push((owner, page));
        Ok(offered)
    }
}
