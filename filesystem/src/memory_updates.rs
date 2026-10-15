//! Provider-memory coordination stays in user space. The endpoint capability
//! scopes native operations; inode/path interpretation never reaches mnu.

pub trait Update: Send {
    fn begin(&mut self) -> Result<(), i32>;
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
