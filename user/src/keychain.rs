//! The user service forwards credentials only after verifying them. Hash tags
//! select the authoritative account-credential generation; they are not vault keys.
use mochi_user_platform as platform;
use mochios_keychain_protocol::{self as wire, Error, Reply, Request, Result, Secret};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};
use zeroize::Zeroizing;
static NEXT: AtomicU64 = AtomicU64::new(1);
pub fn tag(encoded_hash: &str) -> [u8; 32] {
    Sha256::digest(encoded_hash.as_bytes()).into()
}
pub struct Connection {
    endpoint: u64,
    pub epoch: u64,
}
impl Connection {
    pub fn connect() -> Result<Self> {
        let endpoint =
            platform::process::find_by_name(wire::SERVICE_NAME).map_err(|_| Error::Unavailable)?;
        let mut c = Self { endpoint, epoch: 0 };
        c.epoch = match c.call(Request::AuthenticationEpoch)? {
            Reply::AuthenticationEpoch(e) if e != 0 => e,
            _ => return Err(Error::Invalid),
        };
        Ok(c)
    }
    fn call(&self, request: Request) -> Result<Reply> {
        let identity =
            platform::process::thread_security_context(self.endpoint).map_err(|_| Error::Denied)?;
        if identity.provenance != 1
            || identity.package_id.get(..identity.package_id_len as usize)
                != Some(b"org.mochios.keychain-service")
        {
            return Err(Error::Denied);
        }
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let frame = request.encode(id)?;
        let mut reply = Zeroizing::new(vec![0; wire::MAX_FRAME]);
        let n = (platform::ipc::call(self.endpoint, &frame, &mut reply)
            .map_err(|_| Error::Unavailable)?
            & 0xffff_ffff) as usize;
        if n > reply.len() {
            return Err(Error::Invalid);
        }
        Reply::decode(&reply[..n], id)
    }
    pub fn verified_login(&self, uid: u32, encoded_hash: &str, password: &[u8]) -> Result<()> {
        match self.call(Request::VerifiedLogin {
            uid,
            epoch: self.epoch,
            tag: tag(encoded_hash),
            password: Secret::new(password.to_vec()),
        })? {
            Reply::Ok => Ok(()),
            _ => Err(Error::Invalid),
        }
    }
    pub fn prepare_password(
        &self,
        uid: u32,
        current_hash: &str,
        next_hash: &str,
        password: &[u8],
    ) -> Result<()> {
        match self.call(Request::PrepareLoginPassword {
            uid,
            epoch: self.epoch,
            current_tag: tag(current_hash),
            next_tag: tag(next_hash),
            password: Secret::new(password.to_vec()),
        })? {
            Reply::Ok => Ok(()),
            _ => Err(Error::Invalid),
        }
    }
}
