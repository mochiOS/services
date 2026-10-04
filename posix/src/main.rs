#[cfg(target_os = "mochios")]
fn main() {
    use mochi_user_platform as platform;
    use mochios_posix_protocol as protocol;
    use posix_service::{PeerIdentity, PosixService, Response, STATUS_EINVAL};

    let _ = platform::logger::init_from_env();
    platform::logln!("posix.service: start");
    let Some(ready_target) = platform::service_ready::take_bootstrap_target() else {
        platform::logln!("posix.service: missing ready target");
        platform::process::exit(1);
    };
    let endpoint_handle = match platform::ipc::create_handle() {
        Ok(handle) => handle,
        Err(error) => {
            platform::logln!(
                "posix.service: endpoint handle creation failed errno={}",
                error.raw()
            );
            platform::process::exit(1);
        }
    };
    let delegated_rights = platform::handle::HANDLE_RIGHT_SEND
        | platform::handle::HANDLE_RIGHT_DUPLICATE
        | platform::handle::HANDLE_RIGHT_TRANSFER;
    if let Err(error) =
        platform::service_ready::notify_handle(ready_target, 0, endpoint_handle, delegated_rights)
    {
        platform::logln!(
            "posix.service: endpoint publication failed errno={}",
            error.raw()
        );
        platform::process::exit(1);
    }
    platform::logln!("posix.service: endpoint ready");

    let mut service = PosixService::new();
    let mut request_bytes = vec![0u8; protocol::MAX_MESSAGE_LEN];
    let mut response_bytes = vec![0u8; protocol::MAX_MESSAGE_LEN];
    loop {
        let mut received_handles = platform::ipc::IpcObjectHandles::default();
        let message = match platform::ipc::wait_object_handles(
            endpoint_handle as u64,
            &mut request_bytes,
            &mut received_handles,
        ) {
            Ok(message) => message,
            Err(_) => {
                platform::thread::yield_now();
                continue;
            }
        };
        let sender = message >> 32;
        let length = (message & 0xffff_ffff) as usize;
        let attached_count = received_handles.count as usize;
        for attachment in received_handles.handles.iter().take(attached_count) {
            let _ = platform::handle::close(attachment.handle);
        }
        let peer = platform::process::thread_security_context(sender)
            .ok()
            .map(|context| PeerIdentity {
                process_id: context.process_id,
                effective_uid: context.effective_uid,
                effective_gid: context.effective_gid,
            });
        let decoded = request_bytes
            .get(..length)
            .and_then(|bytes| protocol::decode(bytes).ok());
        let response = match (
            peer,
            decoded,
            attached_count,
        ) {
            (Some(peer), Some((header, payload)), 0) => service.handle(peer, header, payload),
            (_, Some((header, _)), _) => Response {
                header: protocol::Header {
                    opcode: protocol::OP_STATUS,
                    request_id: header.request_id,
                    status: STATUS_EINVAL,
                    ..protocol::Header::default()
                },
                payload: Vec::new(),
            },
            _ => Response {
                header: protocol::Header {
                    opcode: protocol::OP_STATUS,
                    status: STATUS_EINVAL,
                    ..protocol::Header::default()
                },
                payload: Vec::new(),
            },
        };
        if let Ok(response_len) = protocol::encode(
            response.header,
            &response.payload,
            &mut response_bytes,
        ) {
            let _ = platform::ipc::reply(sender, &response_bytes[..response_len]);
        }
    }
}

#[cfg(not(target_os = "mochios"))]
fn main() {}
