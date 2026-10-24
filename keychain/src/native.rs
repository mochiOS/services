use crate::{Peer, Random, Service, storage::Disk};
use mochi_user_platform as platform;
use mochios_keychain_protocol::{self as wire, Application, Error, Result};
use zeroize::Zeroizing;
pub struct Entropy;
impl Random for Entropy {
    fn fill(&mut self, out: &mut [u8]) -> Result<()> {
        platform::random::fill(out).map_err(|_| Error::Unavailable)
    }
}
fn peer(sender: u64, controller: u64, broker: u64) -> Result<Peer> {
    let c = platform::process::thread_security_context(sender).map_err(|_| Error::Denied)?;
    let package = core::str::from_utf8(
        c.package_id
            .get(..c.package_id_len as usize)
            .ok_or(Error::Denied)?,
    )
    .map_err(|_| Error::Denied)?
    .to_owned();
    let application = Application {
        package,
        signer: c.subject_key_id,
        provenance: c.provenance,
    };
    application.validate().map_err(|_| Error::Denied)?;
    let trusted = application.provenance == 1;
    let manager = trusted
        && application.package == "org.mochios.keychain"
        && platform::capability::check_thread(sender, wire::MANAGE) == Ok(1);
    let session_control = trusted
        && c.process_id == controller
        && application.package == "org.mochios.service-manager"
        && platform::capability::check_thread(sender, wire::SESSION) == Ok(1);
    let access = platform::capability::check_thread(sender, wire::ACCESS) == Ok(1);
    let login_broker = trusted
        && c.process_id == broker
        && application.package == "org.mochios.user"
        && platform::capability::check_thread(sender, wire::AUTHENTICATION) == Ok(1);
    // Reject callers before invoking the privileged POSIX adapter for them.
    if !access && !session_control && !login_broker {
        return Err(Error::Denied);
    }
    let ids = inspect_sender_handle(
        sender,
        |sender, rights| {
            platform::process::open_handle_for_endpoint(sender, rights).map_err(|_| Error::Denied)
        },
        |h, delegated| {
            let retained = platform::process::handle_status(h).map_err(|_| Error::Denied)?;
            if retained.process_id != c.process_id {
                return Err(Error::Denied);
            }
            let transport = mochios_posix_client::SyscallEndpointTransport::from_launch_context()
                .map_err(|_| Error::Denied)?;
            mochios_posix_client::Client::new(transport)
                .process_session_info(mochios_posix_client::ObjectHandleAttachment {
                    handle: h,
                    rights: delegated,
                })
                .map_err(|_| Error::Denied)
        },
        |h| {
            let _ = platform::handle::close(h);
        },
    )?;
    if ids.real_uid != ids.effective_uid {
        return Err(Error::Denied);
    }
    Ok(Peer {
        uid: ids.effective_uid,
        application,
        access,
        manager,
        session_control,
        login_broker,
    })
}

fn inspect_sender_handle<T>(
    sender: u64,
    open: impl FnOnce(u64, u64) -> Result<u32>,
    inspect: impl FnOnce(u32, u64) -> Result<T>,
    close: impl FnOnce(u32),
) -> Result<T> {
    let handle = open(
        sender,
        platform::handle::HANDLE_RIGHT_WAIT | platform::handle::HANDLE_RIGHT_TRANSFER,
    )?;
    let result = inspect(handle, platform::handle::HANDLE_RIGHT_WAIT);
    close(handle);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    #[test]
    fn sender_inspection_can_export_only_wait_and_always_closes_the_source() {
        for failure in [false, true] {
            let source_rights = Cell::new(0);
            let closed = Cell::new(false);
            let result = inspect_sender_handle(
                19,
                |sender, rights| {
                    assert_eq!(sender, 19);
                    source_rights.set(rights);
                    Ok(7)
                },
                |handle, delegated| {
                    assert_eq!(handle, 7);
                    assert_eq!(delegated, platform::handle::HANDLE_RIGHT_WAIT);
                    // The real kernel's export_object_handle requires TRANSFER
                    // on the source even when only WAIT is exported.
                    if source_rights.get() & platform::handle::HANDLE_RIGHT_TRANSFER == 0 {
                        return Err(Error::Denied);
                    }
                    if failure {
                        Err(Error::Unavailable)
                    } else {
                        Ok(1000u32)
                    }
                },
                |handle| {
                    assert_eq!(handle, 7);
                    closed.set(true);
                },
            );
            assert!(closed.get());
            assert_eq!(
                result,
                if failure {
                    Err(Error::Unavailable)
                } else {
                    Ok(1000)
                }
            );
        }
    }
}
pub fn run() -> Result<()> {
    let _ = platform::logger::init_from_env();
    // Pin lifecycle authority to the exact authenticated launching manager,
    // rather than any future process with the same built-in package name.
    let ready = platform::service_ready::take_bootstrap_target().ok_or(Error::Denied)?;
    let controller =
        platform::process::thread_security_context(ready.endpoint).map_err(|_| Error::Denied)?;
    if controller.provenance != 1
        || controller
            .package_id
            .get(..controller.package_id_len as usize)
            != Some(b"org.mochios.service-manager")
        || platform::capability::check_thread(ready.endpoint, wire::SESSION) != Ok(1)
    {
        return Err(Error::Denied);
    }
    let disk = Disk::new("/var/lib/keychain".into())?;
    let broker_endpoint =
        platform::process::find_by_name("user.service").map_err(|_| Error::Denied)?;
    let broker =
        platform::process::thread_security_context(broker_endpoint).map_err(|_| Error::Denied)?;
    if broker.provenance != 1
        || broker.package_id.get(..broker.package_id_len as usize) != Some(b"org.mochios.user")
        || platform::capability::check_thread(broker_endpoint, wire::AUTHENTICATION) != Ok(1)
    {
        return Err(Error::Denied);
    }
    let mut service = Service::session_controlled(disk, Entropy)?;
    let ep = platform::ipc::create().map_err(|_| Error::Unavailable)?;
    platform::service_ready::notify(ready, 0).map_err(|_| Error::Unavailable)?;
    let mut buffer = Zeroizing::new(vec![0u8; wire::MAX_FRAME]);
    loop {
        let message = platform::ipc::wait(ep, &mut buffer).map_err(|_| Error::Unavailable)?;
        let sender = message >> 32;
        let n = (message & 0xffff_ffff) as usize;
        if n > buffer.len() {
            continue;
        }
        let response = match peer(sender, controller.process_id, broker.process_id) {
            Ok(peer) => service.dispatch(&peer, &buffer[..n]),
            Err(e) => wire::Reply::error(
                wire::Request::decode(&buffer[..n])
                    .map(|(id, _)| id)
                    .unwrap_or(0),
                e,
            ),
        };
        let _ = platform::ipc::reply(sender, &response);
        use zeroize::Zeroize;
        buffer[..n].zeroize();
    }
}
