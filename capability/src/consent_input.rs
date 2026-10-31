//! Input evidence is received directly from the measured input authority.
//! No renderer, ordinary InputEvent or request-supplied identity can replace it.
use crate::{
    consent_peer::{self, Peer},
    trusted_images::{Role, TrustedImages},
};
use mochi_user_platform as p;
use p::capability::{consent::Correlation, input_authority as wire};

fn denied() -> p::syscall::SysError {
    p::syscall::SysError::from_raw(p::syscall::NativeError::AccessDenied.into_raw() as i64)
}
struct ReplyHandles(p::ipc::IpcObjectHandles);
impl Drop for ReplyHandles {
    fn drop(&mut self) {
        let entries = &self.0.handles[..(self.0.count as usize).min(self.0.handles.len())];
        for (index, entry) in entries.iter().enumerate() {
            if entry.handle != 0
                && !entries[..index]
                    .iter()
                    .any(|old| old.handle == entry.handle)
            {
                let _ = p::handle::close(entry.handle);
            }
        }
    }
}
pub(crate) struct Channel {
    peer: Peer,
    generation: u64,
    active: Option<Correlation>,
    last_serial: u64,
}
impl Channel {
    pub fn connect(trusted: &TrustedImages) -> Result<Self, p::syscall::SysError> {
        let peer = consent_peer::capture(p::process::find_by_name("input.service")?)?;
        if trusted.role(&peer)? != Some(Role::Input) {
            return Err(denied());
        }
        let mut channel = Self {
            peer,
            generation: 0,
            active: None,
            last_serial: 0,
        };
        let reply = channel.transact(wire::Command::Register)?;
        channel.generation = reply.generation;
        channel.last_serial = reply.serial;
        Ok(channel)
    }
    pub fn current(&self) -> Result<(), p::syscall::SysError> {
        let current = consent_peer::capture(self.peer.instance.endpoint)?;
        if current.instance != self.peer.instance
            || !p::handle::same_object(current.process.0, self.peer.process.0)?
        {
            return Err(denied());
        }
        Ok(())
    }
    pub fn route(&self) -> crate::consent::InputRoute {
        crate::consent::InputRoute {
            source: self.peer.instance,
            seat: 0,
            generation: self.generation,
        }
    }
    fn transact(&self, command: wire::Command) -> Result<wire::Reply, p::syscall::SysError> {
        self.current()?;
        let bytes = wire::encode_command(command).map_err(|_| denied())?;
        let mut reply = [0; wire::REPLY_BYTES];
        let mut handles = ReplyHandles(p::ipc::IpcObjectHandles::default());
        let destination = u32::try_from(self.peer.instance.endpoint).map_err(|_| denied())?;
        let message = p::ipc::call_object_handles(destination, &bytes, &mut reply, &mut handles.0)?;
        if message >> 32 != self.peer.instance.endpoint
            || message as u32 as usize != reply.len()
            || handles.0.count != 0
            || handles.0.delivery_flags != 0
        {
            return Err(denied());
        }
        self.current()?;
        let reply = wire::decode_reply(&reply).map_err(|_| denied())?;
        if reply.status != 0 {
            return Err(p::syscall::SysError::from_raw(-i64::from(reply.status)));
        }
        if !matches!(command, wire::Command::Register)
            && (reply.generation != self.generation || reply.serial < self.last_serial)
        {
            return Err(denied());
        }
        Ok(reply)
    }
    /// Call only after the presenter acknowledged this exact display. This
    /// reply is the authority's live snapshot, never a frontend-supplied one.
    pub fn arm(&mut self, correlation: Correlation) -> Result<wire::Reply, p::syscall::SysError> {
        if self.active.is_some() {
            return Err(denied());
        }
        let reply = self.transact(wire::Command::Arm {
            generation: self.generation,
            correlation,
        })?;
        self.last_serial = reply.serial;
        self.active = Some(correlation);
        Ok(reply)
    }
    /// Before final consent consumption, the caller must require a live,
    /// matching route and account for any as-yet-undelivered observations.
    pub fn status(&self) -> Result<wire::Reply, p::syscall::SysError> {
        let correlation = self.active.ok_or_else(denied)?;
        self.transact(wire::Command::Status {
            generation: self.generation,
            correlation,
        })
    }
    pub fn cancel(&mut self) -> Result<(), p::syscall::SysError> {
        let correlation = self.active.take().ok_or_else(denied)?;
        self.transact(wire::Command::Cancel {
            generation: self.generation,
            correlation,
        })
        .map(|_| ())
    }
    pub fn receive(
        &mut self,
        sender: u64,
        bytes: &[u8],
    ) -> Result<wire::Event, p::syscall::SysError> {
        if sender != self.peer.instance.endpoint {
            return Err(denied());
        }
        self.current()?;
        let event = wire::decode_event(bytes).map_err(|_| denied())?;
        if event.generation != self.generation
            || Some(event.correlation) != self.active
            || self.last_serial.checked_add(1) != Some(event.observation.serial)
        {
            return Err(denied());
        }
        self.last_serial = event.observation.serial;
        Ok(event)
    }
}
