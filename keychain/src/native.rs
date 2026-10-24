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
fn peer(sender: u64) -> Result<Peer> {
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
    let h =
        platform::process::open_handle_for_endpoint(sender, platform::handle::HANDLE_RIGHT_WAIT)
            .map_err(|_| Error::Denied)?;
    let result = (|| {
        let transport = mochios_posix_client::SyscallEndpointTransport::from_launch_context()
            .map_err(|_| Error::Denied)?;
        mochios_posix_client::Client::new(transport)
            .process_session_info(mochios_posix_client::ObjectHandleAttachment {
                handle: h,
                rights: platform::handle::HANDLE_RIGHT_WAIT,
            })
            .map_err(|_| Error::Denied)
    })();
    let _ = platform::handle::close(h);
    let ids = result?;
    if ids.real_uid != ids.effective_uid {
        return Err(Error::Denied);
    }
    let trusted = application.provenance == 1;
    let manager = trusted
        && application.package == "org.mochios.keychain"
        && platform::capability::check_thread(sender, wire::MANAGE) == Ok(1);
    let session_control = trusted
        && application.package == "org.mochios.service-manager"
        && platform::capability::check_thread(sender, wire::SESSION) == Ok(1);
    let access = platform::capability::check_thread(sender, wire::ACCESS) == Ok(1);
    Ok(Peer {
        uid: ids.effective_uid,
        application,
        access,
        manager,
        session_control,
    })
}
pub fn run() -> Result<()> {
    let _ = platform::logger::init_from_env();
    let ready = platform::service_ready::take_bootstrap_target();
    let disk = Disk::new("/var/lib/keychain".into())?;
    let mut service = Service::new(disk, Entropy);
    let ep = platform::ipc::create().map_err(|_| Error::Unavailable)?;
    if let Some(target) = ready {
        platform::service_ready::notify(target, 0).map_err(|_| Error::Unavailable)?;
    }
    let mut buffer = Zeroizing::new(vec![0u8; wire::MAX_FRAME]);
    loop {
        let message = platform::ipc::wait(ep, &mut buffer).map_err(|_| Error::Unavailable)?;
        let sender = message >> 32;
        let n = (message & 0xffff_ffff) as usize;
        if n > buffer.len() {
            continue;
        }
        let response = match peer(sender) {
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
