//! Resolve a sendto target using authenticated caller policy, then publish a
//! scoped WRITE/WAIT route. All row resources are explicitly IPC-attached or
//! obtained through the caller's retained filesystem roots.
use mochi_user_platform as platform;
use mochios_posix_protocol::{socket::Address, socket_route as wire};
use posix_service::{
    socket::Streams,
    socket_binding::Bindings,
    socket_route::{job_id, object_id, Routes},
    PosixService,
};
use std::sync::{Arc, Mutex};

pub fn prepare(
    endpoint: u32,
    state: &Arc<Mutex<PosixService<u32>>>,
    streams: &Streams,
    bindings: &Bindings<u32>,
    routes: &mut Routes<u32>,
    sender: u64,
    bytes: &[u8],
    attachments: &platform::ipc::IpcObjectHandles,
) -> bool {
    let result = (|| {
        if attachments.delivery_flags != mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE {
            return Err(-13);
        }
        if attachments.count != 1 {
            return Err(-22);
        }
        let attached = attachments.handles[0];
        if attached.handle == 0
            || attached.reserved != 0
            || attached.rights != mnu_abi::HANDLE_RIGHT_WRITE
        {
            return Err(-13);
        }
        let (length, address) = wire::decode(bytes).map_err(|_| -22)?;
        let Address::UnixPath(path) = address else {
            return Err(-95);
        };
        let source = platform::handle::identify_provider_object(attached.handle)
            .map_err(|error| error.raw() as i32)?;
        let mut backend = super::socket_path_native::snapshot(state, sender, path)?;
        let target = bindings.prepare_datagram_target(streams, source, path, &mut backend)?;
        let job = match routes.start(streams, target, length as usize, attached.handle) {
            Ok(job) => job,
            Err((error, target)) => {
                target.release_with(|handle| {
                    let _ = platform::handle::close(handle);
                });
                return Err(error);
            }
        };
        let prepared = object_id(job).and_then(|id| {
            platform::handle::create_provider_object(endpoint, id, wire::RIGHTS)
                .map_err(|error| error.raw() as i32)
        });
        let handle = match prepared {
            Ok(handle) => handle,
            Err(error) => {
                rollback(routes, job);
                return Err(error);
            }
        };
        pump(streams, routes);
        let mut outgoing = platform::ipc::IpcObjectHandles::default();
        outgoing.count = 1;
        outgoing.handles[0] = platform::ipc::IpcObjectHandle {
            handle,
            reserved: 0,
            rights: wire::RIGHTS,
        };
        let sent = platform::ipc::reply_object_handles(sender, &0i32.to_le_bytes(), &outgoing);
        if sent.is_err() {
            rollback(routes, job);
        }
        let _ = platform::handle::close(handle);
        sent.map(|_| ()).map_err(|_| -5)
    })();
    if let Err(error) = result {
        let _ = platform::ipc::reply(sender, &i32::to_le_bytes(error));
        false
    } else {
        true
    }
}

fn rollback(routes: &mut Routes<u32>, job: u64) {
    // The worker's common cleanup still owns the source attachment on failure.
    let _ = routes.release(
        job,
        |_| (),
        |handle| {
            let _ = platform::handle::close(handle);
        },
    );
}

pub fn pump(streams: &Streams, routes: &Routes<u32>) {
    routes.pump(streams, |job, ready| {
        if let Ok(id) = object_id(job) {
            let set = if ready {
                mnu_abi::HANDLE_SIGNAL_WRITABLE
            } else {
                0
            };
            if let Err(error) = platform::handle::signal_provider_object(
                id,
                set,
                mnu_abi::HANDLE_SIGNAL_WRITABLE & !set,
            ) {
                if error.raw() != -9 {
                    platform::logln!(
                        "posix.service: send route readiness failed errno={}",
                        error.raw()
                    );
                }
            }
        }
    });
}

pub fn provider_request(
    routes: &mut Routes<u32>,
    sender: u64,
    request: mnu_abi::provider::RequestHeader,
    flags: u32,
    attachments: u32,
    response: &mut [u8],
) {
    use mnu_abi::provider;
    let result = if flags != mnu_abi::IPC_DELIVERY_NATIVE_OBJECT {
        Err(-13)
    } else if attachments != 0 {
        Err(-22)
    } else if request.opcode != provider::OP_RELEASE {
        Err(-95)
    } else {
        job_id(request.object_id).and_then(|id| {
            routes.release(
                id,
                |handle| {
                    let _ = platform::handle::close(handle);
                },
                |handle| {
                    let _ = platform::handle::close(handle);
                },
            )
        })
    };
    if request.opcode == provider::OP_RELEASE
        && flags == mnu_abi::IPC_DELIVERY_NATIVE_OBJECT
        && attachments == 0
    {
        return;
    }
    if let Ok(length) = (provider::ResponseHeader {
        opcode: request.opcode,
        object_id: request.object_id,
        status: i64::from(result.err().unwrap_or(0)),
        value: 0,
        data_length: 0,
    })
    .encode(&[], response)
    {
        let _ = platform::ipc::reply(sender, &response[..length]);
    }
}
