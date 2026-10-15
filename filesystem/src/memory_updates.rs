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
