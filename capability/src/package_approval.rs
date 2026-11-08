//! Common administrator approval for one native package transaction object.
//! package.service consumes it before mutation, while this broker is free to
//! receive package-index refreshes. No recursive service call or ambient token.
use crate::{
    consent::{Binding, Session},
    consent_peer::{self, Peer},
};
use alloc::{rc::Rc, string::String, vec::Vec};
use core::cell::RefCell;
use mochi_user_platform as p;
use mochios_package_protocol::{self as protocol, transaction as wire};
use p::syscall::{NativeError, SysError};

pub(crate) struct Reference(pub u32);
impl Drop for Reference {
    fn drop(&mut self) {
        let _ = p::handle::close(self.0);
    }
}
pub(crate) type Shared = Rc<RefCell<Registry>>;
fn denied() -> SysError {
    SysError::from(NativeError::AccessDenied.into_raw())
}
fn invalid() -> SysError {
    SysError::from(NativeError::InvalidArgument.into_raw())
}
pub(crate) fn service(sender: u64) -> Result<p::execution_peer::MeasuredPeer, SysError> {
    let peer = p::execution_peer::capture(sender)?;
    let c = &peer.context;
    if c.provenance != 1
        || c.subject_key_id != [0; 32]
        || c.package_id.get(..c.package_id_len as usize) != Some(b"org.mochios.package")
        || c.developer_id.get(..c.developer_id_len as usize) != Some(b"org.mochios.system")
        || p::capability::check_thread(sender, "package.install") != Ok(1)
    {
        return Err(denied());
    }
    Ok(peer)
}
pub(crate) struct Prepared {
    plan: Reference,
    pub bytes: Vec<u8>,
}
impl Prepared {
    pub(crate) fn capture(
        peer: &Peer,
        bytes: &[u8],
        objects: &mut p::ipc::IpcObjectHandles,
    ) -> Result<Self, SysError> {
        if bytes != p::capability::administrator::PACKAGE_OPCODE.to_le_bytes()
            || !objects.is_user_delivery()
            || objects.count != 1
            || objects.handles[0].handle == 0
            || objects.handles[0].reserved != 0
            || objects.handles[0].rights != p::handle::HANDLE_RIGHT_TRANSFER
        {
            return Err(invalid());
        }
        let package = service(p::process::find_by_name("package.service")?)?;
        let requester = Reference(p::process::open_handle_for_endpoint(
            peer.instance.endpoint,
            p::handle::HANDLE_RIGHT_WAIT | p::handle::HANDLE_RIGHT_TRANSFER,
        )?);
        if !p::handle::same_object(requester.0, peer.process.0)? {
            return Err(denied());
        }
        let mut request = [0; protocol::HEADER_LEN];
        let id = p::time::monotonic_nanoseconds()?;
        let n = wire::encode_command(id, false, &mut request).map_err(|_| invalid())?;
        let mut response = [0; wire::MAX_PLAN_BYTES];
        let mut attachments = p::ipc::IpcObjectHandles::default();
        attachments.count = 2;
        attachments.handles[0] = objects.handles[0];
        attachments.handles[1] = p::ipc::IpcObjectHandle {
            handle: requester.0,
            reserved: 0,
            rights: p::handle::HANDLE_RIGHT_WAIT,
        };
        let borrowed = [objects.handles[0].handle, requester.0];
        let result = p::ipc::call_object_handles(
            package.endpoint.try_into().map_err(|_| invalid())?,
            &request[..n],
            &mut response,
            &mut attachments,
        );
        let unexpected = attachments.count != 0 || attachments.delivery_flags != 0;
        for object in attachments
            .handles
            .iter()
            .take((attachments.count as usize).min(attachments.handles.len()))
        {
            if object.handle != 0 && !borrowed.contains(&object.handle) {
                let _ = p::handle::close(object.handle);
            }
        }
        let message = result?;
        let current = service(package.endpoint)?;
        if unexpected
            || message >> 32 != package.endpoint
            || message as u32 as usize > response.len()
            || current.image != package.image
            || !p::handle::same_object(current.process.0, package.process.0)?
        {
            return Err(denied());
        }
        let bytes = &response[..message as u32 as usize];
        if let Ok(status) = protocol::decode_status(bytes, id) {
            return Err(SysError::from_raw(if status < 0 {
                i64::from(status)
            } else {
                -5
            }));
        }
        let info = wire::decode_plan(bytes, id).map_err(|_| invalid())?;
        if p::capability::check_thread(peer.instance.endpoint, info.mutation.capability()) != Ok(1)
        {
            return Err(denied());
        }
        let plan = Reference(objects.handles[0].handle);
        objects.handles[0].handle = 0;
        // Canonical request ID keeps operation metadata independent of RPCs.
        let mut bytes = bytes.to_vec();
        bytes[8..16].fill(0);
        Ok(Self { plan, bytes })
    }
    pub fn capability(&self) -> &'static str {
        wire::decode_plan(&self.bytes, 0)
            .unwrap()
            .mutation
            .capability()
    }
    pub fn description(&self) -> String {
        let plan = wire::decode_plan(&self.bytes, 0).unwrap();
        alloc::format!(
            "{} {} ({}) version {} — Publisher: {}",
            plan.mutation.label(),
            plan.name,
            plan.package_id,
            plan.version,
            plan.developer
        )
    }
    pub fn approve(
        self,
        registry: &Shared,
        peer: &Peer,
        binding: Binding,
        deadline: u64,
    ) -> Result<(), SysError> {
        let owner = consent_peer::capture(peer.instance.endpoint)?;
        if owner.instance != binding.requester
            || !p::handle::same_object(owner.process.0, peer.process.0)?
        {
            return Err(denied());
        }
        let uid = crate::execution_grant::requester_uid(&owner)?;
        let mut registry = registry.borrow_mut();
        if registry.entries.len() >= wire::MAX_PENDING {
            return Err(SysError::from(NativeError::NotReady.into_raw()));
        }
        for entry in &registry.entries {
            if p::handle::same_object(entry.prepared.plan.0, self.plan.0)? {
                return Err(denied());
            }
        }
        registry.entries.push(Grant {
            prepared: self,
            owner,
            uid,
            binding,
            deadline,
        });
        Ok(())
    }
}
struct Grant {
    prepared: Prepared,
    owner: Peer,
    uid: u32,
    binding: Binding,
    deadline: u64,
}
#[derive(Default)]
pub(crate) struct Registry {
    entries: Vec<Grant>,
}
impl Registry {
    pub fn maintain(&mut self, now: u64, generation: u64) {
        self.entries.retain(|entry| {
            entry.deadline > now
                && entry.binding.policy_generation == generation
                && p::process::handle_status(entry.owner.process.0)
                    .is_ok_and(|s| s.state != p::process::PROCESS_STATE_EXITED)
        });
    }
    pub fn deadline(&self) -> u64 {
        self.entries
            .iter()
            .map(|entry| entry.deadline)
            .min()
            .unwrap_or(mnu_abi::HANDLE_WAIT_INFINITE)
    }
    pub fn processes(&self, mut emit: impl FnMut(u32)) {
        for entry in &self.entries {
            emit(entry.owner.process.0);
        }
    }
    pub fn consume(
        &mut self,
        sender: u64,
        bytes: &[u8],
        objects: &p::ipc::IpcObjectHandles,
        generation: u64,
        now: u64,
        session: impl FnOnce(&Peer) -> Result<Session, SysError>,
    ) -> Result<(), SysError> {
        let _package = service(sender)?;
        if bytes != p::capability::administrator::PACKAGE_CONSUME_OPCODE.to_le_bytes()
            || !objects.is_user_delivery()
            || objects.count != 2
            || objects.handles[0].reserved != 0
            || objects.handles[0].rights != p::handle::HANDLE_RIGHT_TRANSFER
            || objects.handles[1].reserved != 0
            || objects.handles[1].rights != p::handle::HANDLE_RIGHT_WAIT
        {
            return Err(invalid());
        }
        let mut matched = None;
        for (i, entry) in self.entries.iter().enumerate() {
            if p::handle::same_object(entry.prepared.plan.0, objects.handles[0].handle)? {
                matched = Some(i);
                break;
            }
        }
        let entry = self.entries.swap_remove(matched.ok_or_else(denied)?);
        let current = consent_peer::capture(entry.owner.instance.endpoint)?;
        if now >= entry.deadline
            || generation != entry.binding.policy_generation
            || current.instance != entry.binding.requester
            || !p::handle::same_object(current.process.0, objects.handles[1].handle)?
            || !p::handle::same_object(current.process.0, entry.owner.process.0)?
            || crate::execution_grant::requester_uid(&current)? != entry.uid
            || session(&current)? != entry.binding.session
            || p::capability::check_thread(current.instance.endpoint, entry.prepared.capability())
                != Ok(1)
        {
            return Err(denied());
        }
        Ok(())
    }
}

/// Resolve once through the measured system broker. Ordinary clients receive
/// a SEND-only endpoint object and need no process.inspect permission.
pub(crate) fn connect() -> Result<(Reference, u64), SysError> {
    let peer = service(p::process::find_by_name("package.service")?)?;
    let mut request = [0; protocol::HEADER_LEN];
    let id = p::time::monotonic_nanoseconds()?;
    let length = wire::encode_connect(id, &mut request).map_err(|_| invalid())?;
    let mut reply = [0; protocol::HEADER_LEN];
    let mut objects = p::ipc::IpcObjectHandles::default();
    let result = p::ipc::call_object_handles(
        peer.endpoint.try_into().map_err(|_| invalid())?,
        &request[..length],
        &mut reply,
        &mut objects,
    );
    let valid = result
        .as_ref()
        .is_ok_and(|m| m >> 32 == peer.endpoint && *m as u32 as usize == reply.len())
        && objects.delivery_flags == 0
        && objects.count == 1
        && objects.handles[0].reserved == 0
        && objects.handles[0].handle != 0
        && objects.handles[0].rights
            == p::handle::HANDLE_RIGHT_SEND | p::handle::HANDLE_RIGHT_TRANSFER;
    let handle = if valid {
        let handle = Reference(objects.handles[0].handle);
        objects.handles[0].handle = 0;
        Some(handle)
    } else {
        None
    };
    for object in objects
        .handles
        .iter()
        .take((objects.count as usize).min(objects.handles.len()))
    {
        if object.handle != 0 {
            let _ = p::handle::close(object.handle);
        }
    }
    result?;
    if protocol::decode_status(&reply, id).map_err(|_| invalid())? != 0 {
        return Err(denied());
    }
    let current = service(peer.endpoint)?;
    if current.image != peer.image || !p::handle::same_object(current.process.0, peer.process.0)? {
        return Err(denied());
    }
    Ok((handle.ok_or_else(denied)?, peer.endpoint))
}
