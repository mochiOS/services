//! Credential verification stays in user.service; only the measured system
//! broker may call it. No password/hash or reusable grant is returned.
use mochi_user_platform as p;
use mochios_user_database::{UserDatabase, groups::GroupDatabase};

#[derive(Default)]
pub struct Limiter {
    failures: u8,
    blocked_until: u64,
}
impl Limiter {
    pub fn verify(
        &mut self,
        sender: u64,
        bytes: &[u8],
        users: &UserDatabase,
        groups: &GroupDatabase,
    ) -> Result<u64, i32> {
        let request = mochios_user_protocol::VerifyAdministrator::decode(bytes).map_err(|_| -22)?;
        let peer = p::execution_peer::capture(sender).map_err(|_| -13)?;
        let context = &peer.context;
        if p::capability::check_thread(sender, "capabilities.manage") != Ok(1)
            || context.provenance != 1
            || context.subject_key_id != [0; 32]
            || context.package_id.get(..context.package_id_len as usize)
                != Some(b"org.mochios.capability")
            || context
                .developer_id
                .get(..context.developer_id_len as usize)
                != Some(b"org.mochios.system")
        {
            return Err(-13);
        }
        let now = p::time::monotonic_nanoseconds().map_err(|_| -5)?;
        if now < self.blocked_until {
            return Err(-11);
        }
        let user = users.find_name(request.name);
        let hash = user
            .filter(|user| !user.locked)
            .map(|user| user.password_hash.as_str())
            .unwrap_or("!");
        let verified = user_service::password::verify(request.password, hash);
        let current = p::execution_peer::capture(sender).map_err(|_| -13)?;
        if current.image != peer.image
            || current.context != peer.context
            || !p::handle::same_object(current.process.0, peer.process.0).map_err(|_| -13)?
        {
            return Err(-13);
        }
        if !verified || !user.is_some_and(|user| !user.locked && groups.is_administrator(user)) {
            self.failures = self.failures.saturating_add(1);
            if self.failures >= 5 {
                self.blocked_until = now.checked_add(30_000_000_000).ok_or(-75)?;
                self.failures = 0;
            }
            return Err(-13);
        }
        self.failures = 0;
        Ok(request.request_id)
    }
}
