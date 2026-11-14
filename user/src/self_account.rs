//! The account target comes from authenticated POSIX credentials, never from
//! request bytes. Password entry belongs to the OS account UI.
use mochi_user_platform as p;
use mochios_posix_client::{Client, ObjectHandleAttachment, SyscallEndpointTransport};
use std::collections::BTreeMap;

pub struct Caller {
    peer: p::execution_peer::MeasuredPeer,
    pub uid: u32,
    real_uid: u32,
}
fn trusted_editor(c: &p::syscall::ThreadSecurityContext) -> bool {
    let Some(package) = c.package_id.get(..c.package_id_len as usize) else {
        return false;
    };
    c.provenance == 1
        && c.subject_key_id == [0; 32]
        && c.developer_id.get(..c.developer_id_len as usize) == Some(b"org.mochios.system")
        && matches!(package, b"org.mochios.settings" | b"org.mochios.secure-ui")
}
pub fn capture(
    client: &Client<SyscallEndpointTransport>,
    sender: u64,
    modifying: bool,
) -> Result<Caller, i32> {
    let peer = p::execution_peer::capture(sender).map_err(|_| -13)?;
    if modifying {
        if !trusted_editor(&peer.context) {
            return Err(-13);
        }
    }
    let session = client
        .process_session_info(ObjectHandleAttachment {
            handle: peer.process.0,
            rights: p::handle::HANDLE_RIGHT_WAIT,
        })
        .map_err(|_| -13)?;
    if session.real_uid != session.effective_uid {
        return Err(-13);
    }
    Ok(Caller {
        peer,
        uid: session.effective_uid,
        real_uid: session.real_uid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn self_password_entry_requires_the_measured_os_ui_identity() {
        let mut context = p::syscall::ThreadSecurityContext::default();
        let package = b"org.mochios.settings";
        let developer = b"org.mochios.system";
        context.package_id[..package.len()].copy_from_slice(package);
        context.package_id_len = package.len() as u16;
        context.developer_id[..developer.len()].copy_from_slice(developer);
        context.developer_id_len = developer.len() as u16;
        context.provenance = 1;
        assert!(trusted_editor(&context));
        context.provenance = 2;
        assert!(!trusted_editor(&context));
        context.provenance = 1;
        context.subject_key_id[0] = 1;
        assert!(!trusted_editor(&context));
        context.subject_key_id = [0; 32];
        context.package_id_len = 1;
        assert!(!trusted_editor(&context));
        context.package_id_len = u16::MAX;
        assert!(!trusted_editor(&context));
    }
    #[test]
    fn repeated_wrong_passwords_are_limited_per_real_account() {
        let mut limiter = Limiter::default();
        for _ in 0..3 {
            limiter.failed(501, 10);
        }
        assert_eq!(limiter.check(501, 11), Err(-11));
        assert_eq!(limiter.check(502, 11), Ok(()));
        assert_eq!(limiter.check(501, 30_000_000_010), Ok(()));
        limiter.succeeded(501);
        assert_eq!(limiter.check(501, 11), Ok(()));
    }
}
impl Caller {
    pub fn revalidate(
        &self,
        client: &Client<SyscallEndpointTransport>,
        sender: u64,
    ) -> Result<(), i32> {
        let current = capture(client, sender, true)?;
        if current.uid != self.uid
            || current.real_uid != self.real_uid
            || current.peer.context != self.peer.context
            || current.peer.image != self.peer.image
            || !p::handle::same_object(current.peer.process.0, self.peer.process.0).unwrap_or(false)
        {
            return Err(-13);
        }
        Ok(())
    }
}
#[derive(Default)]
pub struct Limiter {
    failures: BTreeMap<u32, (u8, u64)>,
}
impl Limiter {
    pub fn check(&self, uid: u32, now: u64) -> Result<(), i32> {
        if self
            .failures
            .get(&uid)
            .is_some_and(|(_, until)| now < *until)
        {
            Err(-11)
        } else {
            Ok(())
        }
    }
    pub fn failed(&mut self, uid: u32, now: u64) {
        let row = self.failures.entry(uid).or_default();
        row.0 = row.0.saturating_add(1);
        if row.0 >= 3 {
            row.1 = now.saturating_add(30_000_000_000);
        }
    }
    pub fn succeeded(&mut self, uid: u32) {
        self.failures.remove(&uid);
    }
}
