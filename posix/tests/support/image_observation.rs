//! Controlled native image metadata, not a client startup acknowledgement.
use posix_service::{PeerIdentity, PosixService, ProcessBackend, ProcessLifecycle};

struct Metadata {
    handle: u32,
    process_id: u64,
    revision: u64,
}
impl ProcessBackend<u32> for Metadata {
    fn image_status(&mut self, handle: u32) -> Result<mnu_abi::ProcessStatus, i32> {
        assert_eq!(handle, self.handle);
        Ok(mnu_abi::ProcessStatus {
            process_id: self.process_id,
            image_revision: self.revision,
            state: mnu_abi::PROCESS_STATE_RUNNING,
            ..Default::default()
        })
    }
    fn status(&mut self, _: u32) -> Result<ProcessLifecycle, i32> {
        panic!("no lifecycle fallback")
    }
    fn execution_usage(&mut self, _: u32) -> Result<mnu_abi::ProcessExecutionUsage, i32> {
        panic!("not CPU metadata")
    }
    fn suspend(&mut self, _: u32) -> Result<(), i32> {
        panic!("no suspension")
    }
    fn terminate(&mut self, _: u32, _: u64) -> Result<(), i32> {
        panic!("no termination")
    }
    fn release(&mut self, _: u32) {
        panic!("keep retained Handle")
    }
}

pub fn observe(service: &mut PosixService, peer: PeerIdentity, handle: u32, revision: u64) {
    service
        .refresh_image_state(
            peer,
            &mut Metadata {
                handle,
                process_id: peer.process_id,
                revision,
            },
        )
        .unwrap();
}
