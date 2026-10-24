use crate::{
    Random, Service,
    login_vault::{self, LoginKey},
    storage::Storage,
    vault::Unlocked,
};
use mochios_keychain_protocol::{Error, Reply, Request, Result, Secret};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

pub(crate) struct Recovery {
    key: LoginKey,
    publication: [u8; 32],
}
enum LoginState {
    Ready { vault: Unlocked, tag: [u8; 32] },
    Recovery(Recovery),
}
pub(crate) struct PendingLogin {
    at: Instant,
    state: LoginState,
}
impl PendingLogin {
    pub(crate) fn expired(&self) -> bool {
        self.at.elapsed() > Duration::from_secs(60)
    }
}
impl<S: Storage, R: Random> Service<S, R> {
    pub(crate) fn login_request(&mut self, request: Request) -> Result<Reply> {
        match request {
            Request::AuthenticationEpoch => Ok(Reply::AuthenticationEpoch(self.session_epoch)),
            Request::VerifiedLogin {
                uid,
                epoch,
                tag,
                password,
            } => {
                if epoch != self.session_epoch {
                    return Err(Error::Conflict);
                }
                if self.pending_logins.len() >= 32 && !self.pending_logins.contains_key(&uid) {
                    return Err(Error::Limit);
                }
                self.pending_logins.remove(&uid);
                let blob = self.storage.load(uid)?;
                let state = match blob {
                    None => {
                        let key = LoginKey::new(tag, password.expose(), &mut self.random)?;
                        let mut vault = login_vault::create(uid, &key, &mut self.random)?;
                        self.publish_login(uid, &mut vault)?;
                        LoginState::Ready { vault, tag }
                    }
                    Some(blob) => {
                        let opened = if login_vault::is_login(&blob) {
                            login_vault::open(uid, password.expose(), Some(tag), &blob)
                        } else {
                            Unlocked::open(uid, password.expose(), &blob)
                        };
                        match opened {
                            Ok(mut vault) => {
                                if vault.login.is_none() {
                                    let key =
                                        LoginKey::new(tag, password.expose(), &mut self.random)?;
                                    vault =
                                        login_vault::migrate(&vault, uid, &key, &mut self.random)?;
                                    self.publish_login(uid, &mut vault)?;
                                }
                                LoginState::Ready { vault, tag }
                            }
                            Err(Error::Authentication) => LoginState::Recovery(Recovery {
                                key: LoginKey::new(tag, password.expose(), &mut self.random)?,
                                publication: Sha256::digest(&blob).into(),
                            }),
                            Err(e) => return Err(e),
                        }
                    }
                };
                self.pending_logins.insert(
                    uid,
                    PendingLogin {
                        at: Instant::now(),
                        state,
                    },
                );
                Ok(Reply::Ok)
            }
            Request::PrepareLoginPassword {
                uid,
                epoch,
                current_tag,
                next_tag,
                password,
            } => {
                if epoch != self.session_epoch {
                    return Err(Error::Conflict);
                }
                if self.storage.load(uid)?.is_none() {
                    if self.unlocked.contains_key(&uid) || self.pending_logins.contains_key(&uid) {
                        return Err(Error::Corrupt);
                    }
                    return Ok(Reply::Ok);
                }
                if self.session_user != Some(uid) {
                    return Err(Error::Locked);
                }
                self.current_publication(uid)?;
                let key = LoginKey::new(next_tag, password.expose(), &mut self.random)?;
                let mut replacement = login_vault::prepare_password_change(
                    self.unlocked.get(&uid).ok_or(Error::Locked)?,
                    uid,
                    current_tag,
                    &key,
                    &mut self.random,
                )?;
                self.publish_login(uid, &mut replacement)?;
                self.unlocked.insert(uid, replacement);
                self.pending_logins.remove(&uid);
                Ok(Reply::Ok)
            }
            _ => Err(Error::Denied),
        }
    }
    pub(crate) fn activate_login(&mut self, uid: u32) -> Result<()> {
        if let Some(pending) = self.pending_logins.remove(&uid) {
            if pending.at.elapsed() > Duration::from_secs(60) {
                return Ok(());
            }
            match pending.state {
                LoginState::Ready { mut vault, tag } => {
                    let blob = self.storage.load(uid)?.ok_or(Error::Corrupt)?;
                    vault.verify_publication(&blob)?;
                    if login_vault::consolidate(&mut vault, tag)? {
                        self.publish_login(uid, &mut vault)?;
                    }
                    self.unlocked.insert(uid, vault);
                }
                LoginState::Recovery(recovery) => {
                    self.recoveries.insert(uid, recovery);
                }
            }
        }
        Ok(())
    }
    pub(crate) fn recover_login(&mut self, uid: u32, password: Secret) -> Result<Reply> {
        let recovery = self.recoveries.get(&uid).ok_or(Error::Locked)?;
        let blob = self.storage.load(uid)?.ok_or(Error::Corrupt)?;
        if recovery.publication != <[u8; 32]>::from(Sha256::digest(&blob)) {
            return Err(Error::Corrupt);
        }
        let old = if login_vault::is_login(&blob) {
            login_vault::open(uid, password.expose(), None, &blob)?
        } else {
            Unlocked::open(uid, password.expose(), &blob)?
        };
        let mut next = login_vault::migrate(&old, uid, &recovery.key, &mut self.random)?;
        self.publish_login(uid, &mut next)?;
        self.unlocked.insert(uid, next);
        self.recoveries.remove(&uid);
        Ok(Reply::Ok)
    }
    fn publish_login(&mut self, uid: u32, vault: &mut Unlocked) -> Result<()> {
        let mut nonce = [0; 24];
        self.random.fill(&mut nonce)?;
        let blob = vault.seal(uid, &vault.data, nonce)?;
        self.storage.commit(uid, &blob)?;
        vault.record_publication(&blob);
        Ok(())
    }
}
