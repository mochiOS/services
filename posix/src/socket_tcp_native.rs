//! Native ownership and replies for the worker's TCP description registry.
use mochi_user_platform as platform;
use mochios_posix_protocol::socket as wire;
use posix_service::inet_stream_socket::{self as tcp, Started};

pub struct OwnedSource(pub u32);
impl Drop for OwnedSource {
    fn drop(&mut self) {
        let _ = platform::handle::close(self.0);
    }
}
pub type Registry = tcp::Registry<posix_service::inet_stream_native::NetworkBackend, OwnedSource>;
fn error(e: platform::syscall::SysError) -> i32 {
    mochios_posix_protocol::status::normalize_failure(e.raw())
}
pub fn pump(registry: &mut Registry) {
    let all = mnu_abi::HANDLE_SIGNAL_READABLE
        | mnu_abi::HANDLE_SIGNAL_WRITABLE
        | mnu_abi::HANDLE_SIGNAL_PEER_CLOSED;
    registry.pump(|id, set| {
        platform::handle::signal_provider_object(id, set, all & !set).map_err(error)
    });
}
/// Caller authenticated the internal dispatcher and registered POSIX peer.
/// The received source reference is consumed even if allocating a job fails.
pub fn connect(
    registry: &mut Registry,
    endpoint: u32,
    sender: u64,
    id: u64,
    address: wire::Address<'_>,
    source: OwnedSource,
) -> Result<(), i32> {
    let mut response = [0; 4 + wire::CONNECT_REPLY_LEN];
    match registry.connect(id, address, source)? {
        Started::Connected => {
            wire::ConnectReply::Connected
                .encode(&mut response[4..])
                .map_err(|_| -5)?;
            platform::ipc::reply(sender, &response)
                .map(|_| ())
                .map_err(error)
        }
        Started::InProgress => Err(-115),
        Started::Waiting(job) => {
            let prepared = (|| {
                wire::ConnectReply::Waiting
                    .encode(&mut response[4..])
                    .map_err(|_| -5)?;
                let handle = platform::handle::create_provider_object(
                    endpoint,
                    job,
                    wire::connect_job_rights(),
                )
                .map_err(error)?;
                let owned = OwnedSource(handle);
                let mut outgoing = platform::ipc::IpcObjectHandles::default();
                outgoing.count = 1;
                outgoing.handles[0] = platform::ipc::IpcObjectHandle {
                    handle: owned.0,
                    reserved: 0,
                    rights: wire::connect_job_rights(),
                };
                let result = platform::ipc::reply_object_handles(sender, &response, &outgoing)
                    .map(|_| ())
                    .map_err(error);
                if result.is_err() {
                    let _ = registry.release_job(job);
                }
                result
            })();
            if prepared.is_err() {
                let _ = registry.release_job(job);
            }
            prepared
        }
    }
}
pub fn accept(
    registry: &mut Registry,
    endpoint: u32,
    sender: u64,
    listener: u64,
    request: wire::Accept,
    credentials: (u32, u32),
) -> Result<(), i32> {
    let (id, owned) = registry.accept(listener, request, credentials, |id| {
        platform::handle::create_provider_object(endpoint, id, wire::descriptor_rights())
            .map(OwnedSource)
            .map_err(error)
    })?;
    let result = (|| {
        let mut response = [0; 4 + wire::MAX_ADDRESS_LEN];
        let length = registry
            .peer_address(id)?
            .as_address()
            .encode(&mut response[4..])
            .map_err(|_| -5)?;
        let mut outgoing = platform::ipc::IpcObjectHandles::default();
        outgoing.count = 1;
        outgoing.handles[0] = platform::ipc::IpcObjectHandle {
            handle: owned.0,
            reserved: 0,
            rights: wire::descriptor_rights(),
        };
        platform::ipc::reply_object_handles(sender, &response[..4 + length], &outgoing)
            .map(|_| ())
            .map_err(error)
    })();
    if result.is_err() {
        let _ = registry.remove(id);
    }
    drop(owned);
    result
}
