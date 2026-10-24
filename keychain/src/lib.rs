//! A user-space vault. Authentication is injected only by trusted transport adapters.
#[cfg(target_os = "linux")]
pub mod host;
#[cfg(any(target_os = "mochios", test))]
pub mod native;
pub mod storage;
pub mod vault;
use mochios_keychain_protocol::{
    self as wire, Application, Error, Item, MAX_GRANTS, MAX_ITEMS, PAGE_SIZE, Reply, Request,
    Result, Secret,
};
use std::collections::{BTreeMap, BTreeSet};
use storage::Storage;
use vault::{Data, Entry, Unlocked};
pub trait Random {
    fn fill(&mut self, out: &mut [u8]) -> Result<()>;
}
#[derive(Clone)]
pub struct Peer {
    pub uid: u32,
    pub application: Application,
    pub access: bool,
    pub manager: bool,
    pub session_control: bool,
}
pub struct Service<S: Storage, R: Random> {
    storage: S,
    random: R,
    unlocked: BTreeMap<u32, Unlocked>,
    known: BTreeMap<u32, BTreeSet<Application>>,
}
impl<S: Storage, R: Random> Service<S, R> {
    pub fn new(storage: S, random: R) -> Self {
        Self {
            storage,
            random,
            unlocked: BTreeMap::new(),
            known: BTreeMap::new(),
        }
    }
    pub fn execute(&mut self, peer: &Peer, request: Request) -> Result<Reply> {
        let result = self.execute_inner(peer, request);
        if matches!(result, Err(Error::Storage | Error::Corrupt)) {
            self.unlocked.remove(&peer.uid);
        }
        result
    }
    fn execute_inner(&mut self, peer: &Peer, request: Request) -> Result<Reply> {
        peer.application.validate().map_err(|_| Error::Denied)?;
        if matches!(request, Request::LockAll) {
            if !peer.session_control {
                return Err(Error::Denied);
            }
            self.unlocked.clear();
            self.known.clear();
            return Ok(Reply::Ok);
        }
        if !peer.access || request.manager() && !peer.manager {
            return Err(Error::Denied);
        }
        if self.known.len() >= 32 && !self.known.contains_key(&peer.uid) {
            return Err(Error::Limit);
        }
        let apps = self.known.entry(peer.uid).or_default();
        if apps.len() < MAX_ITEMS {
            apps.insert(peer.application.clone());
        }
        let uid = peer.uid;
        match request {
            Request::Status => Ok(Reply::Status {
                initialized: self.storage.load(uid)?.is_some(),
                unlocked: self.unlocked.contains_key(&uid),
            }),
            Request::Initialize { password } => {
                if self.storage.load(uid)?.is_some() {
                    return Err(Error::Exists);
                }
                let mut salt = [0; 16];
                self.random.fill(&mut salt)?;
                let vault = Unlocked::create(password.expose(), salt)?;
                let mut nonce = [0; 24];
                self.random.fill(&mut nonce)?;
                let b = vault.seal(uid, &vault.data, nonce)?;
                self.storage.commit(uid, &b)?;
                self.unlocked.insert(uid, vault);
                Ok(Reply::Ok)
            }
            Request::Unlock { password } => {
                let b = self.storage.load(uid)?.ok_or(Error::Missing)?;
                let v = Unlocked::open(uid, password.expose(), &b)?;
                self.unlocked.insert(uid, v);
                Ok(Reply::Ok)
            }
            Request::Lock => {
                self.unlocked.remove(&uid);
                Ok(Reply::Ok)
            }
            Request::List {
                manager,
                offset,
                generation,
            } => {
                let v = self.unlocked.get(&uid).ok_or(Error::Locked)?;
                if generation != 0 && generation != v.data.generation {
                    return Err(Error::Conflict);
                }
                let all: Vec<_> = v
                    .data
                    .entries
                    .iter()
                    .filter(|e| {
                        manager
                            || e.meta.owner == peer.application
                            || e.meta.grants.contains(&peer.application)
                    })
                    .collect();
                let offset = offset as usize;
                if offset > all.len() {
                    return Err(Error::Invalid);
                }
                Ok(Reply::Items {
                    generation: v.data.generation,
                    total: all.len() as u16,
                    items: all
                        .into_iter()
                        .skip(offset)
                        .take(PAGE_SIZE)
                        .map(|e| e.meta.clone())
                        .collect(),
                })
            }
            Request::Get { id } => {
                let v = self.unlocked.get(&uid).ok_or(Error::Locked)?;
                let e = v
                    .data
                    .readable(&peer.application)
                    .find(|e| e.meta.id == id)
                    .ok_or(Error::Missing)?;
                Ok(Reply::Secret(e.secret.clone()))
            }
            Request::Put {
                service,
                account,
                label,
                secret,
            } => {
                wire::valid_text(&service, 128, false)?;
                wire::valid_text(&account, 256, true)?;
                wire::valid_text(&label, 128, false)?;
                if secret.expose().len() > wire::MAX_SECRET {
                    return Err(Error::Limit);
                }
                let mut data = self.unlocked.get(&uid).ok_or(Error::Locked)?.data.clone();
                let id = if let Some(e) = data.entries.iter_mut().find(|e| {
                    e.meta.owner == peer.application
                        && e.meta.service == service
                        && e.meta.account == account
                }) {
                    e.secret = secret;
                    e.meta.label = label;
                    e.meta.id
                } else {
                    if data.entries.len() >= MAX_ITEMS {
                        return Err(Error::Limit);
                    }
                    let id = vault::new_id(&mut self.random)?;
                    if data.entries.iter().any(|e| e.meta.id == id) {
                        return Err(Error::Conflict);
                    }
                    data.entries.push(Entry {
                        meta: Item {
                            id,
                            owner: peer.application.clone(),
                            service,
                            account,
                            label,
                            grants: vec![],
                        },
                        secret,
                    });
                    id
                };
                data.next()?;
                self.save(uid, data)?;
                Ok(Reply::Id(id))
            }
            Request::Delete { id } => {
                let mut data = self.unlocked.get(&uid).ok_or(Error::Locked)?.data.clone();
                let at = data
                    .entries
                    .iter()
                    .position(|e| e.meta.id == id && e.meta.owner == peer.application)
                    .ok_or(Error::Missing)?;
                data.entries.remove(at);
                data.next()?;
                self.save(uid, data)?;
                Ok(Reply::Ok)
            }
            Request::Reveal { id, password } => {
                self.reauthenticate(uid, &password)?;
                let e = self
                    .unlocked
                    .get(&uid)
                    .ok_or(Error::Locked)?
                    .data
                    .entries
                    .iter()
                    .find(|e| e.meta.id == id)
                    .ok_or(Error::Missing)?;
                Ok(Reply::Secret(e.secret.clone()))
            }
            Request::ManageDelete { id, password } => {
                self.reauthenticate(uid, &password)?;
                let mut data = self.unlocked.get(&uid).ok_or(Error::Locked)?.data.clone();
                let at = data
                    .entries
                    .iter()
                    .position(|e| e.meta.id == id)
                    .ok_or(Error::Missing)?;
                data.entries.remove(at);
                data.next()?;
                self.save(uid, data)?;
                Ok(Reply::Ok)
            }
            Request::Grant {
                id,
                target,
                revoke,
                password,
            } => {
                target.validate()?;
                self.reauthenticate(uid, &password)?;
                let mut data = self.unlocked.get(&uid).ok_or(Error::Locked)?.data.clone();
                let e = data
                    .entries
                    .iter_mut()
                    .find(|e| e.meta.id == id)
                    .ok_or(Error::Missing)?;
                if target == e.meta.owner {
                    return Err(Error::Invalid);
                }
                if revoke {
                    e.meta.grants.retain(|a| *a != target);
                } else {
                    if !self
                        .known
                        .get(&uid)
                        .is_some_and(|apps| apps.contains(&target))
                        && !data_applications(&self.unlocked.get(&uid).unwrap().data)
                            .contains(&target)
                    {
                        return Err(Error::Invalid);
                    }
                    if !e.meta.grants.contains(&target) {
                        if e.meta.grants.len() >= MAX_GRANTS {
                            return Err(Error::Limit);
                        }
                        e.meta.grants.push(target);
                    }
                }
                data.next()?;
                self.save(uid, data)?;
                Ok(Reply::Ok)
            }
            Request::Applications => {
                let v = self.unlocked.get(&uid).ok_or(Error::Locked)?;
                let mut apps = data_applications(&v.data);
                if let Some(known) = self.known.get(&uid) {
                    apps.extend(known.iter().cloned());
                }
                if apps.len() > MAX_ITEMS {
                    return Err(Error::Limit);
                }
                Ok(Reply::Applications(apps.into_iter().collect()))
            }
            Request::ChangePassword { old, new } => {
                self.reauthenticate(uid, &old)?;
                let mut salt = [0; 16];
                self.random.fill(&mut salt)?;
                let mut replacement = self
                    .unlocked
                    .get(&uid)
                    .ok_or(Error::Locked)?
                    .rekey(new.expose(), salt)?;
                replacement.data.next()?;
                let mut nonce = [0; 24];
                self.random.fill(&mut nonce)?;
                let b = replacement.seal(uid, &replacement.data, nonce)?;
                if let Err(e) = self.storage.commit(uid, &b) {
                    self.unlocked.remove(&uid);
                    return Err(e);
                }
                self.unlocked.insert(uid, replacement);
                Ok(Reply::Ok)
            }
            Request::LockAll => Err(Error::Denied),
        }
    }
    fn reauthenticate(&mut self, uid: u32, password: &Secret) -> Result<()> {
        if !self.unlocked.contains_key(&uid) {
            return Err(Error::Locked);
        }
        let b = self.storage.load(uid)?.ok_or(Error::Missing)?;
        let _verified = Unlocked::open(uid, password.expose(), &b)?;
        Ok(())
    }
    fn save(&mut self, uid: u32, data: Data) -> Result<()> {
        let mut nonce = [0; 24];
        self.random.fill(&mut nonce)?;
        let blob = self
            .unlocked
            .get(&uid)
            .ok_or(Error::Locked)?
            .seal(uid, &data, nonce)?;
        if let Err(e) = self.storage.commit(uid, &blob) {
            self.unlocked.remove(&uid);
            return Err(e);
        }
        self.unlocked.get_mut(&uid).ok_or(Error::Locked)?.data = data;
        Ok(())
    }
    pub fn dispatch(&mut self, peer: &Peer, frame: &[u8]) -> zeroize::Zeroizing<Vec<u8>> {
        match Request::decode(frame) {
            Ok((id, r)) => match self.execute(peer, r) {
                Ok(reply) => reply.encode(id).unwrap_or_else(|e| Reply::error(id, e)),
                Err(e) => Reply::error(id, e),
            },
            Err(e) => Reply::error(0, e),
        }
    }
}
fn data_applications(d: &Data) -> BTreeSet<Application> {
    let mut a = BTreeSet::new();
    for e in &d.entries {
        a.insert(e.meta.owner.clone());
        a.extend(e.meta.grants.iter().cloned());
    }
    a
}

#[cfg(test)]
mod tests;
