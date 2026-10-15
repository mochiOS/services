//! Provider-memory coordination stays in user space. The endpoint capability
//! scopes native operations; inode/path interpretation never reaches mnu.

/// Use only for preparation and BEGIN, before storage is touched. A failed
/// BEGIN leaves the transaction prepared; dropping it restores old mappings.
/// Never apply this conversion to publication or storage errors.
pub(crate) fn admission_error(error: i32) -> i32 {
    if error == 11 {
        mochios_filesystem_protocol::ERROR_MEMORY_ADMISSION_BUSY
    } else {
        error
    }
}

pub trait Update: Send {
    /// Failure must leave storage unchanged and must not cross the in-flight
    /// boundary. Only a successful BEGIN permits the caller to mutate storage.
    fn begin(&mut self) -> Result<(), i32>;
    /// Failure can follow an irrevocable publication request: never replay it.
    fn publish(&mut self) -> Result<(), i32>;
}

pub trait MemoryUpdates: Send {
    fn prepare(&self, identity: u64, old_length: u64, length: u64) -> Result<Box<dyn Update>, i32>;

    /// Nonblocking preparation with a transferable FIFO position. Backends
    /// without admission support must fail explicitly, not silently barge.
    /// The incoming reference remains owned by the IPC request on every path.
    fn prepare_admitted(
        &self,
        _identity: u64,
        _old_length: u64,
        _length: u64,
        _incoming: Option<mochi_user_platform::handle::Handle>,
    ) -> Result<Preparation, i32> {
        Err(95)
    }
}

/// Keep this owner alive until the reply has transferred its reference. A
/// borrowed ticket is closed by request cleanup, never by this response.
pub enum AdmissionReference {
    Owned(mochi_user_platform::handle::ProviderMemoryAdmission),
    Borrowed(mochi_user_platform::handle::Handle),
}

impl AdmissionReference {
    pub fn handle(&self) -> mochi_user_platform::handle::Handle {
        match self {
            Self::Owned(owner) => owner.handle(),
            Self::Borrowed(handle) => *handle,
        }
    }
}

pub enum Preparation {
    Ready(Box<dyn Update>),
    Wait(AdmissionReference),
}

pub struct ProviderUpdates {
    endpoint: mochi_user_platform::handle::Handle,
}

impl ProviderUpdates {
    /// The service retains this RECEIVE capability for its entire lifetime.
    pub fn new(endpoint: mochi_user_platform::handle::Handle) -> Self {
        Self { endpoint }
    }
}

impl MemoryUpdates for ProviderUpdates {
    fn prepare(&self, identity: u64, old_length: u64, length: u64) -> Result<Box<dyn Update>, i32> {
        let update = mochi_user_platform::handle::prepare_provider_memory_update(
            self.endpoint,
            identity,
            old_length,
            length,
        )
        .map_err(native_error)?;
        Ok(Box::new(update))
    }

    fn prepare_admitted(
        &self,
        identity: u64,
        old_length: u64,
        length: u64,
        incoming: Option<mochi_user_platform::handle::Handle>,
    ) -> Result<Preparation, i32> {
        use mochi_user_platform::handle;
        let fresh = || {
            handle::create_provider_memory_admission(self.endpoint, identity)
                .map(AdmissionReference::Owned)
                .map_err(native_error)
        };
        let ticket = match incoming {
            Some(handle) => AdmissionReference::Borrowed(handle),
            None => fresh()?,
        };
        match handle::prepare_provider_memory_update_admitted(
            self.endpoint,
            identity,
            old_length,
            length,
            ticket.handle(),
        )
        .map_err(native_error)
        {
            Ok(update) => Ok(Preparation::Ready(Box::new(update))),
            Err(11) => {
                // A failed native preparation can already have consumed the
                // ticket (e.g. boundary allocation failed). Never send that
                // closed position back to a client as something it can await.
                if admission_consumed(ticket.handle())? {
                    Ok(Preparation::Wait(fresh()?))
                } else {
                    Ok(Preparation::Wait(ticket))
                }
            }
            Err(13) if incoming.is_some() => {
                // Atomic path traversal may now name another backing. This
                // method requires the caller's fresh authorization/preflight;
                // the ticket itself grants NO mutation authority. Rescope
                // only before any update/storage operation has begun.
                Ok(Preparation::Wait(fresh()?))
            }
            Err(error) => Err(error),
        }
    }
}

fn admission_consumed(handle: mochi_user_platform::handle::Handle) -> Result<bool, i32> {
    use mochi_user_platform::{process, syscall};
    let mut items = [syscall::HandleWaitItem {
        handle,
        interests: mnu_abi::HANDLE_SIGNAL_READABLE | mnu_abi::HANDLE_SIGNAL_PEER_CLOSED,
        ..Default::default()
    }];
    // Deadline zero is a single readiness observation, never a service wait.
    match process::wait_many(&mut items, 0).map_err(native_error) {
        Ok(_) if items[0].observed & mnu_abi::HANDLE_SIGNAL_PEER_CLOSED != 0 => Ok(true),
        Ok(_) if items[0].observed & mnu_abi::HANDLE_SIGNAL_READABLE != 0 => Ok(false),
        Ok(_) => Err(5),
        Err(11) => Ok(false),
        Err(error) => Err(error),
    }
}

impl Update for mochi_user_platform::handle::ProviderMemoryUpdate {
    fn begin(&mut self) -> Result<(), i32> {
        mochi_user_platform::handle::ProviderMemoryUpdate::begin(self).map_err(native_error)
    }
    fn publish(&mut self) -> Result<(), i32> {
        mochi_user_platform::handle::ProviderMemoryUpdate::publish(self).map_err(native_error)
    }
}

fn native_error(error: mochi_user_platform::syscall::SysError) -> i32 {
    error
        .errno()
        .and_then(|error| i32::try_from(error).ok())
        .unwrap_or(5)
}
