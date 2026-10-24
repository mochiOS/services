use crate::{native_process::NativeProcess, process_watch::ProcessWatch};
use mochi_user_platform as platform;
use mochios_keychain_protocol::{Error, MAX_FRAME, Reply, Request, SERVICE_NAME};
pub(crate) fn lock(process: &NativeProcess) -> Result<(), Error> {
    let watch = ProcessWatch::open(process.watch_target()).map_err(|_| Error::Unavailable)?;
    if watch
        .exit_status()
        .map_err(|_| Error::Unavailable)?
        .is_some()
    {
        return Ok(());
    }
    let endpoint = platform::process::find_by_name(SERVICE_NAME).map_err(|_| Error::Unavailable)?;
    let c = platform::process::thread_security_context(endpoint).map_err(|_| Error::Denied)?;
    if c.process_id != process.process_id()
        || c.provenance != 1
        || c.package_id.get(..c.package_id_len as usize) != Some(b"org.mochios.keychain-service")
    {
        return Err(Error::Denied);
    }
    let request = Request::LockAll.encode(1)?;
    let mut reply = alloc::vec![0u8;MAX_FRAME];
    let result =
        platform::ipc::call(endpoint, &request, &mut reply).map_err(|_| Error::Unavailable)?;
    let n = (result & 0xffff_ffff) as usize;
    if n > reply.len() {
        return Err(Error::Invalid);
    }
    match Reply::decode(&reply[..n], 1)? {
        Reply::Ok => Ok(()),
        _ => Err(Error::Invalid),
    }
}
