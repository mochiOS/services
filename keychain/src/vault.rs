use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use mochios_keychain_protocol::{
    Application, Error, Item, ItemId, MAX_ITEMS, MAX_SECRET, Reader, Result, Secret, Writer,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;
const MAGIC: &[u8; 8] = b"MKEYV001";
const HEADER: usize = 64;
pub const MAX_FILE: usize = 2 * 1024 * 1024;
pub const MEMORY_KIB: u32 = 65536;
pub const PASSES: u32 = 3;
#[derive(Clone)]
pub struct Entry {
    pub meta: Item,
    pub secret: Secret,
}
#[derive(Clone)]
pub struct Data {
    pub generation: u64,
    pub entries: Vec<Entry>,
}
impl Data {
    pub fn empty() -> Self {
        Self {
            generation: 1,
            entries: vec![],
        }
    }
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        if self.entries.len() > MAX_ITEMS {
            return Err(Error::Limit);
        }
        let mut w = Writer::new();
        w.u64(self.generation);
        w.u16(self.entries.len() as u16);
        for e in &self.entries {
            w.item(&e.meta)?;
            w.bytes(e.secret.expose(), MAX_SECRET)?;
        }
        Ok(w.finish())
    }
    pub(crate) fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b);
        let generation = r.u64()?;
        let n = r.u16()? as usize;
        if generation == 0 || n > MAX_ITEMS {
            return Err(Error::Corrupt);
        }
        let mut entries = Vec::<Entry>::with_capacity(n);
        for _ in 0..n {
            let meta = r.item()?;
            if entries.iter().any(|e| {
                e.meta.id == meta.id
                    || (e.meta.owner == meta.owner
                        && e.meta.service == meta.service
                        && e.meta.account == meta.account)
            }) {
                return Err(Error::Corrupt);
            }
            entries.push(Entry {
                meta,
                secret: r.secret(MAX_SECRET)?,
            });
        }
        r.end()?;
        Ok(Self {
            generation,
            entries,
        })
    }
    pub fn readable<'a>(&'a self, caller: &Application) -> impl Iterator<Item = &'a Entry> {
        self.entries
            .iter()
            .filter(move |e| &e.meta.owner == caller || e.meta.grants.contains(caller))
    }
    pub fn next(&mut self) -> Result<()> {
        self.generation = self.generation.checked_add(1).ok_or(Error::Limit)?;
        Ok(())
    }
}
pub struct Unlocked {
    pub data: Data,
    pub(crate) key: Zeroizing<[u8; 32]>,
    pub(crate) salt: [u8; 16],
    pub(crate) publication: Option<[u8; 32]>,
    pub(crate) login: Option<crate::login_vault::Protection>,
}
impl Unlocked {
    pub fn create(password: &[u8], salt: [u8; 16]) -> Result<Self> {
        new_password(password)?;
        Ok(Self {
            data: Data::empty(),
            key: derive(password, &salt)?,
            salt,
            publication: None,
            login: None,
        })
    }
    pub fn open(uid: u32, password: &[u8], blob: &[u8]) -> Result<Self> {
        let salt = header(uid, blob)?;
        let key = derive(password, &salt)?;
        let data = decrypt_data(uid, &key, blob)?;
        Ok(Self {
            data,
            key,
            salt,
            publication: Some(Sha256::digest(blob).into()),
            login: None,
        })
    }
    pub fn seal(&self, uid: u32, data: &Data, nonce: [u8; 24]) -> Result<Vec<u8>> {
        if self.login.is_some() {
            return crate::login_vault::seal(self, uid, data, nonce);
        }
        let plain = data.encode()?;
        let mut head = [0u8; HEADER];
        head[..8].copy_from_slice(MAGIC);
        head[8..12].copy_from_slice(&uid.to_le_bytes());
        head[12..16].copy_from_slice(&1u32.to_le_bytes());
        head[16..32].copy_from_slice(&self.salt);
        head[32..56].copy_from_slice(&nonce);
        head[56..60].copy_from_slice(&((plain.len() + 16) as u32).to_le_bytes());
        let encrypted = XChaCha20Poly1305::new_from_slice(self.key.as_ref())
            .map_err(|_| Error::Corrupt)?
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plain,
                    aad: &head,
                },
            )
            .map_err(|_| Error::Corrupt)?;
        let mut out = head.to_vec();
        out.extend_from_slice(&encrypted);
        if out.len() > MAX_FILE {
            return Err(Error::Limit);
        }
        Ok(out)
    }
    pub fn rekey(&self, password: &[u8], salt: [u8; 16]) -> Result<Self> {
        if self.login.is_some() {
            return Err(Error::Denied);
        }
        new_password(password)?;
        Ok(Self {
            data: self.data.clone(),
            key: derive(password, &salt)?,
            salt,
            publication: None,
            login: None,
        })
    }
    pub(crate) fn record_publication(&mut self, blob: &[u8]) {
        self.publication = Some(Sha256::digest(blob).into());
    }
    pub(crate) fn verify_publication(&self, blob: &[u8]) -> Result<()> {
        // This digest covers ciphertext, not the password or a secret verifier.
        // Reauthentication must apply to the exact vault currently in memory.
        if self.publication != Some(Sha256::digest(blob).into()) {
            return Err(Error::Corrupt);
        }
        Ok(())
    }
}
fn decrypt_data(uid: u32, key: &[u8; 32], blob: &[u8]) -> Result<Data> {
    header(uid, blob)?;
    let plain = Zeroizing::new(
        XChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| Error::Corrupt)?
            .decrypt(
                XNonce::from_slice(&blob[32..56]),
                Payload {
                    msg: &blob[HEADER..],
                    aad: &blob[..HEADER],
                },
            )
            .map_err(|_| Error::Authentication)?,
    );
    Data::decode(&plain).map_err(|_| Error::Corrupt)
}
pub fn header(uid: u32, b: &[u8]) -> Result<[u8; 16]> {
    if b.len() < HEADER + 16
        || b.len() > MAX_FILE
        || &b[..8] != MAGIC
        || u32::from_le_bytes(b[8..12].try_into().unwrap()) != uid
        || b[12..16] != 1u32.to_le_bytes()
        || b[60..64] != [0; 4]
        || u32::from_le_bytes(b[56..60].try_into().unwrap()) as usize != b.len() - HEADER
    {
        return Err(Error::Corrupt);
    }
    Ok(b[16..32].try_into().unwrap())
}
fn new_password(p: &[u8]) -> Result<()> {
    if p.len() > 1024
        || std::str::from_utf8(p)
            .ok()
            .is_none_or(|s| s.chars().count() < 12 || s.chars().any(char::is_control))
    {
        return Err(Error::Invalid);
    }
    Ok(())
}
fn derive(p: &[u8], salt: &[u8; 16]) -> Result<Zeroizing<[u8; 32]>> {
    if p.is_empty() {
        return Err(Error::Authentication);
    }
    derive_login(p, salt)
}
pub(crate) fn derive_login(p: &[u8], salt: &[u8; 16]) -> Result<Zeroizing<[u8; 32]>> {
    if p.len() > 1024 {
        return Err(Error::Authentication);
    }
    let params = Params::new(MEMORY_KIB, PASSES, 1, Some(32)).map_err(|_| Error::Corrupt)?;
    let mut key = Zeroizing::new([0; 32]);
    let mut memory = Vec::<argon2::Block>::new();
    memory
        .try_reserve_exact(MEMORY_KIB as usize)
        .map_err(|_| Error::Limit)?;
    memory.resize(MEMORY_KIB as usize, argon2::Block::default());
    let mut memory = Zeroizing::new(memory);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into_with_memory(p, salt, key.as_mut(), &mut memory)
        .map_err(|_| Error::Authentication)?;
    Ok(key)
}
pub fn new_id(random: &mut impl crate::Random) -> Result<ItemId> {
    let mut id = [0; 16];
    random.fill(&mut id)?;
    if id == [0; 16] {
        return Err(Error::Unavailable);
    }
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hex(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks_exact(2)
            .map(|b| u8::from_str_radix(core::str::from_utf8(b).unwrap(), 16).unwrap())
            .collect()
    }
    #[test]
    fn matches_independent_argon2_and_libsodium_fixture_and_rejects_tampering() {
        // Public fixed test inputs, generated independently using libargon2
        // argon2id_hash_raw and libsodium's XChaCha20-Poly1305 IETF API.
        let password = b"correct horse battery staple";
        let salt = core::array::from_fn(|i| i as u8);
        let nonce = core::array::from_fn(|i| i as u8);
        let key = derive(password, &salt).unwrap();
        assert_eq!(
            key.as_slice(),
            hex("0d1a3c6523c8f06e4e0af9c515aa5b5448cfebd6838f2d52c3d8b6ef8ddc3c2e")
        );
        let blob = hex(
            "4d4b455956303031e803000001000000000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f10111213141516171a0000000000000074905bcea29376db13f9f3ab02122cfff766caa2364658180ae1",
        );
        let vault = Unlocked::create(password, salt).unwrap();
        assert_eq!(vault.seal(1000, &vault.data, nonce).unwrap(), blob);
        assert!(
            Unlocked::open(1000, password, &blob)
                .unwrap()
                .data
                .entries
                .is_empty()
        );
        for n in 0..blob.len() {
            assert!(Unlocked::open(1000, password, &blob[..n]).is_err());
            let mut changed = blob.clone();
            changed[n] ^= 1;
            assert!(
                decrypt_data(1000, &key, &changed).is_err(),
                "unauthenticated byte {n}"
            );
        }
        let mut extra = blob.clone();
        extra.push(0);
        assert!(Unlocked::open(1000, password, &extra).is_err());
    }
}
