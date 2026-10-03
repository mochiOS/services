#[cfg(target_os = "mochios")]
fn main() {
    use mochi_user_platform as platform;
    use mochios_posix_protocol as protocol;
    use posix_service::{PeerIdentity, PosixService, Response, STATUS_EINVAL};

    let _ = platform::logger::init_from_env();
    platform::logln!("posix.service: start");
    let endpoint = match platform::ipc::create() {
        Ok(endpoint) => endpoint,
        Err(error) => {
            platform::logln!("posix.service: endpoint creation failed errno={}", error.raw());
            platform::process::exit(1);
        }
    };
    platform::logln!("posix.service: endpoint={endpoint}");

    let mut service = PosixService::new();
    let mut request_bytes = vec![0u8; protocol::MAX_MESSAGE_LEN];
    let mut response_bytes = vec![0u8; protocol::MAX_MESSAGE_LEN];
    loop {
        let message = match platform::ipc::wait(endpoint, &mut request_bytes) {
            Ok(message) => message,
            Err(_) => {
                platform::thread::yield_now();
                continue;
            }
        };
        let sender = message >> 32;
        let length = (message & 0xffff_ffff) as usize;
        let peer = platform::process::thread_security_context(sender)
            .ok()
            .map(|context| PeerIdentity {
                process_id: context.process_id,
                effective_uid: context.effective_uid,
                effective_gid: context.effective_gid,
            });
        let response = match (
            peer,
            request_bytes
                .get(..length)
                .and_then(|bytes| protocol::decode(bytes).ok()),
        ) {
            (Some(peer), Some((header, payload))) => service.handle(peer, header, payload),
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
