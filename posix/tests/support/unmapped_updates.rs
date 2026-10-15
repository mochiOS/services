//! Explicit host-only adapter: these images export no kernel Provider Handles.
pub struct UnmappedUpdates;

impl filesystem_service::memory_updates::MemoryUpdates for UnmappedUpdates {
    fn prepare(
        &self,
        _: u64,
        _: u64,
        _: u64,
    ) -> Result<Box<dyn filesystem_service::memory_updates::Update>, i32> {
        Ok(Box::new(UnmappedUpdate))
    }
}

struct UnmappedUpdate;
impl filesystem_service::memory_updates::Update for UnmappedUpdate {
    fn begin(&mut self) -> Result<(), i32> {
        Ok(())
    }
    fn publish(&mut self) -> Result<(), i32> {
        Ok(())
    }
}
