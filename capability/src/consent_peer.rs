//! Consent policy adapts the shared native IPC/image capture mechanism.
use mochi_user_platform as p;
pub(crate) use p::execution_peer::ProcessReference;

pub(crate) struct Peer {
    pub instance: crate::consent::Instance,
    pub context: p::syscall::ThreadSecurityContext,
    pub process: ProcessReference,
}

pub(crate) fn capture(endpoint: u64) -> Result<Peer, p::syscall::SysError> {
    let peer = p::execution_peer::capture(endpoint)?;
    Ok(Peer {
        instance: crate::consent::Instance {
            endpoint: peer.endpoint,
            process: peer.image.process_id,
            thread: peer.context.thread_id,
            revision: peer.image.image_revision,
            digest: peer.image.digest,
        },
        context: peer.context,
        process: peer.process,
    })
}
