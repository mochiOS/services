//! Bounded, native-object-backed launch membership. The service owns registry
//! entries; processes carry weak markers, not chains of dead ancestor records.
use super::*;
use protocol::process_domain as wire;
use std::sync::{Arc, Weak};
pub const ID_BASE: u64 = 1 << 62;
const MAX_DOMAINS: usize = 256;
const MAX_PER_OWNER: usize = 16;
#[derive(Debug)]
pub(crate) struct Marker;
pub(crate) type Membership = Vec<Weak<Marker>>;
#[derive(Default)]
pub struct Registry {
    next: u64,
    entries: Vec<(u64, u64, Arc<Marker>)>,
}
impl Registry {
    pub fn create<H: Copy>(
        &mut self,
        service: &mut PosixService<H>,
        peer: PeerIdentity,
        roots: &[AuthenticatedProcess<H>],
        mut same: impl FnMut(H, H) -> Result<bool, i32>,
        create: impl FnOnce(u64) -> Result<H, i32>,
    ) -> Result<OpenedObject<H>, i32> {
        if roots.len() > wire::MAX_ROOTS {
            return Err(STATUS_EINVAL);
        }
        if service.registered_peer(peer.process_id).is_none() {
            return Err(protocol::STATUS_ESRCH);
        }
        if self.entries.len() >= MAX_DOMAINS
            || self
                .entries
                .iter()
                .filter(|(_, owner, _)| *owner == peer.process_id)
                .count()
                >= MAX_PER_OWNER
        {
            return Err(protocol::STATUS_EAGAIN);
        }
        let mut members = BTreeSet::new();
        for root in roots {
            if root.process_id != peer.process_id
                && service.launch_creators.get(&root.process_id) != Some(&peer.process_id)
            {
                return Err(protocol::STATUS_EPERM);
            }
            authenticate(service, *root, &mut same)?;
            let mut pending = vec![root.process_id];
            while let Some(process) = pending.pop() {
                if members.insert(process) {
                    if service.tree_teardown_owns(process) {
                        return Err(protocol::STATUS_EAGAIN);
                    }
                    if let Some(children) = service.children.get(&process) {
                        pending.extend(children.iter().copied());
                    }
                }
            }
        }
        self.entries
            .try_reserve(1)
            .map_err(|_| protocol::STATUS_ENOMEM)?;
        for member in &members {
            let memberships = service.process_domains.entry(*member).or_default();
            memberships.retain(|marker| marker.strong_count() != 0);
            memberships
                .try_reserve(1)
                .map_err(|_| protocol::STATUS_ENOMEM)?;
        }
        let next = self
            .next
            .checked_add(1)
            .filter(|value| *value < ID_BASE)
            .ok_or(protocol::STATUS_EOVERFLOW)?;
        self.next = next; // Never reuse even when publication fails.
        let marker = Arc::new(Marker);
        let object = create(ID_BASE + next)?;
        for member in members {
            service
                .process_domains
                .get_mut(&member)
                .unwrap()
                .push(Arc::downgrade(&marker));
        }
        self.entries.push((ID_BASE + next, peer.process_id, marker));
        Ok(OpenedObject {
            handle: object,
            rights: wire::TOKEN_RIGHTS,
        })
    }
    pub fn adopt_spawned_child<H: Copy>(
        &self,
        service: &mut PosixService<H>,
        peer: PeerIdentity,
        id: u64,
        process: AuthenticatedProcess<H>,
        uid: u32,
        gid: u32,
        groups: &[u32],
        filesystem: &mut impl FilesystemBackend<H>,
    ) -> Result<(), i32> {
        let (_, owner, marker) = self
            .entries
            .iter()
            .find(|(key, _, _)| *key == id)
            .ok_or(-9)?;
        if *owner != peer.process_id {
            return Err(protocol::STATUS_EPERM);
        }
        // Reserve all new membership storage before adopting anything.
        let mut memberships = inherit(service.process_domains.get(&peer.process_id))?;
        memberships
            .try_reserve(1)
            .map_err(|_| protocol::STATUS_ENOMEM)?;
        if !memberships
            .iter()
            .any(|value| value.ptr_eq(&Arc::downgrade(marker)))
        {
            memberships.push(Arc::downgrade(marker));
        }
        service.adopt_spawned_child(peer, process, uid, gid, groups, filesystem)?;
        service
            .process_domains
            .insert(process.process_id, memberships);
        Ok(())
    }
    pub fn contains<H: Copy>(
        &self,
        service: &PosixService<H>,
        peer: PeerIdentity,
        id: u64,
        process: AuthenticatedProcess<H>,
        mut same: impl FnMut(H, H) -> Result<bool, i32>,
    ) -> Result<bool, i32> {
        let caller = service
            .sessions
            .get(&peer.process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        let target = service
            .sessions
            .get(&process.process_id)
            .ok_or(protocol::STATUS_ESRCH)?;
        if caller.effective_uid != 0
            && caller.effective_uid != target.effective_uid
            && peer.process_id != process.process_id
        {
            return Err(protocol::STATUS_EPERM);
        }
        authenticate(service, process, &mut same)?;
        let marker = &self
            .entries
            .iter()
            .find(|(key, _, _)| *key == id)
            .ok_or(-9)?
            .2;
        Ok(service
            .process_domains
            .get(&process.process_id)
            .is_some_and(|memberships| {
                memberships.iter().any(|member| {
                    member
                        .upgrade()
                        .is_some_and(|value| Arc::ptr_eq(&value, marker))
                })
            }))
    }
    /// Only the native final-reference notification may retire a domain.
    pub fn release_native(
        &mut self,
        bytes: &[u8],
        flags: u32,
        attachments: usize,
    ) -> Result<(), i32> {
        let (header, _) =
            mnu_abi::provider::RequestHeader::decode(bytes).map_err(|_| STATUS_EINVAL)?;
        if flags != mnu_abi::IPC_DELIVERY_NATIVE_OBJECT
            || attachments != 0
            || header.opcode != mnu_abi::provider::OP_RELEASE
            || header.object_id < ID_BASE
        {
            return Err(protocol::STATUS_EPERM);
        }
        if let Some(at) = self
            .entries
            .iter()
            .position(|(key, _, _)| *key == header.object_id)
        {
            self.entries.swap_remove(at);
        }
        Ok(())
    }
}
fn authenticate<H: Copy>(
    service: &PosixService<H>,
    process: AuthenticatedProcess<H>,
    same: &mut impl FnMut(H, H) -> Result<bool, i32>,
) -> Result<(), i32> {
    let retained = *service
        .processes
        .get(&process.process_id)
        .ok_or(protocol::STATUS_ESRCH)?;
    if process.process_id == 0 || !same(retained, process.handle)? {
        return Err(protocol::STATUS_EPERM);
    }
    if service
        .process_wait_states
        .get(&process.process_id)
        .is_none_or(|state| state.exit_observed)
    {
        return Err(protocol::STATUS_ESRCH);
    }
    Ok(())
}
pub(crate) fn inherit(source: Option<&Membership>) -> Result<Membership, i32> {
    let mut output = Vec::new();
    if let Some(source) = source {
        output
            .try_reserve(source.len())
            .map_err(|_| protocol::STATUS_ENOMEM)?;
        output.extend(
            source
                .iter()
                .filter(|marker| marker.strong_count() != 0)
                .cloned(),
        );
    }
    Ok(output)
}
