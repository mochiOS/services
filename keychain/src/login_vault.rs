//! Login-password-wrapped random data keys. No plaintext key or password is persisted.
use crate::{
    Random,
    vault::{Data, MAX_FILE, Unlocked, derive_login},
};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use mochios_keychain_protocol::{Error, Result};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"MKEYV002";
const HEADER: usize = 64;
const SLOT: usize = 120;
pub struct LoginKey {
    pub tag: [u8; 32],
    salt: [u8; 16],
    key: Zeroizing<[u8; 32]>,
}
#[derive(Clone)]
pub struct Slot {
    tag: [u8; 32],
    salt: [u8; 16],
    nonce: [u8; 24],
    encrypted: [u8; 48],
}
pub struct Protection {
    slots: Vec<Slot>,
}
impl LoginKey {
    pub fn new(tag: [u8; 32], password: &[u8], random: &mut impl Random) -> Result<Self> {
        let mut salt = [0; 16];
        random.fill(&mut salt)?;
        Ok(Self {
            tag,
            salt,
            key: derive_login(password, &salt)?,
        })
    }
    fn wrap(&self, uid: u32, key: &[u8; 32], random: &mut impl Random) -> Result<Slot> {
        let mut nonce = [0; 24];
        random.fill(&mut nonce)?;
        let encrypted = XChaCha20Poly1305::new_from_slice(self.key.as_ref())
            .map_err(|_| Error::Corrupt)?
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: key,
                    aad: &slot_aad(uid, &self.tag, &self.salt),
                },
            )
            .map_err(|_| Error::Corrupt)?
            .try_into()
            .map_err(|_| Error::Corrupt)?;
        Ok(Slot {
            tag: self.tag,
            salt: self.salt,
            nonce,
            encrypted,
        })
    }
}
fn slot_aad(uid: u32, tag: &[u8; 32], salt: &[u8; 16]) -> Vec<u8> {
    let mut aad = b"mochiOS keychain login key v2".to_vec();
    aad.extend_from_slice(&uid.to_le_bytes());
    aad.extend_from_slice(tag);
    aad.extend_from_slice(salt);
    aad
}
pub fn is_login(blob: &[u8]) -> bool {
    blob.get(..8) == Some(MAGIC.as_slice())
}
pub fn create(uid: u32, login: &LoginKey, random: &mut impl Random) -> Result<Unlocked> {
    let mut key = Zeroizing::new([0; 32]);
    random.fill(key.as_mut())?;
    if key.iter().all(|b| *b == 0) {
        return Err(Error::Unavailable);
    }
    let slot = login.wrap(uid, &key, random)?;
    Ok(Unlocked {
        data: Data::empty(),
        key,
        salt: [0; 16],
        publication: None,
        login: Some(Protection { slots: vec![slot] }),
    })
}
pub fn migrate(
    vault: &Unlocked,
    uid: u32,
    login: &LoginKey,
    random: &mut impl Random,
) -> Result<Unlocked> {
    // Rotate the data key when leaving the legacy password-derived format.
    let mut next = create(uid, login, random)?;
    next.data = vault.data.clone();
    next.data.next()?;
    Ok(next)
}
pub fn prepare_password_change(
    vault: &Unlocked,
    uid: u32,
    current_tag: [u8; 32],
    next: &LoginKey,
    random: &mut impl Random,
) -> Result<Unlocked> {
    let protection = vault.login.as_ref().ok_or(Error::Locked)?;
    // Preserve the wrapper selected by the authoritative account DB, never a
    // previous failed password-change candidate. At most two wrappers exist.
    let old = protection
        .slots
        .iter()
        .find(|s| s.tag == current_tag)
        .ok_or(Error::Conflict)?
        .clone();
    let new = next.wrap(uid, &vault.key, random)?;
    let slots = if old.tag == new.tag {
        vec![new]
    } else {
        vec![old, new]
    };
    let mut data = vault.data.clone();
    data.next()?;
    Ok(Unlocked {
        data,
        key: vault.key.clone(),
        salt: [0; 16],
        publication: None,
        login: Some(Protection { slots }),
    })
}
pub fn open(uid: u32, password: &[u8], tag: Option<[u8; 32]>, blob: &[u8]) -> Result<Unlocked> {
    let slots = parse(uid, blob)?;
    for slot in slots.iter().filter(|s| tag.is_none_or(|t| s.tag == t)) {
        let wrapping = derive_login(password, &slot.salt)?;
        let plain = match XChaCha20Poly1305::new_from_slice(wrapping.as_ref())
            .map_err(|_| Error::Corrupt)?
            .decrypt(
                XNonce::from_slice(&slot.nonce),
                Payload {
                    msg: &slot.encrypted,
                    aad: &slot_aad(uid, &slot.tag, &slot.salt),
                },
            ) {
            Ok(p) => Zeroizing::new(p),
            Err(_) => continue,
        };
        let mut key = Zeroizing::new([0; 32]);
        if plain.len() != 32 {
            return Err(Error::Corrupt);
        }
        key.copy_from_slice(&plain);
        let aad_len = HEADER + slots.len() * SLOT;
        let data = Zeroizing::new(
            XChaCha20Poly1305::new_from_slice(key.as_ref())
                .map_err(|_| Error::Corrupt)?
                .decrypt(
                    XNonce::from_slice(&blob[24..48]),
                    Payload {
                        msg: &blob[aad_len..],
                        aad: &blob[..aad_len],
                    },
                )
                .map_err(|_| Error::Corrupt)?,
        );
        let mut vault = Unlocked {
            data: Data::decode(&data).map_err(|_| Error::Corrupt)?,
            key,
            salt: [0; 16],
            publication: None,
            login: Some(Protection {
                slots: slots.clone(),
            }),
        };
        vault.record_publication(blob);
        return Ok(vault);
    }
    Err(Error::Authentication)
}
pub fn consolidate(vault: &mut Unlocked, tag: [u8; 32]) -> Result<bool> {
    let p = vault.login.as_mut().ok_or(Error::Corrupt)?;
    let chosen = p
        .slots
        .iter()
        .find(|s| s.tag == tag)
        .ok_or(Error::Authentication)?
        .clone();
    let changed = p.slots.len() != 1;
    p.slots = vec![chosen];
    if changed {
        vault.data.next()?;
    }
    Ok(changed)
}
pub fn seal(vault: &Unlocked, uid: u32, data: &Data, nonce: [u8; 24]) -> Result<Vec<u8>> {
    let slots = &vault.login.as_ref().ok_or(Error::Corrupt)?.slots;
    if slots.is_empty() || slots.len() > 2 {
        return Err(Error::Corrupt);
    }
    let plain = data.encode()?;
    let mut head = vec![0; HEADER];
    head[..8].copy_from_slice(MAGIC);
    head[8..12].copy_from_slice(&uid.to_le_bytes());
    head[12..16].copy_from_slice(&2u32.to_le_bytes());
    head[16] = slots.len() as u8;
    head[24..48].copy_from_slice(&nonce);
    head[48..52].copy_from_slice(&((plain.len() + 16) as u32).to_le_bytes());
    for s in slots {
        head.extend_from_slice(&s.tag);
        head.extend_from_slice(&s.salt);
        head.extend_from_slice(&s.nonce);
        head.extend_from_slice(&s.encrypted);
    }
    let encrypted = XChaCha20Poly1305::new_from_slice(vault.key.as_ref())
        .map_err(|_| Error::Corrupt)?
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &plain,
                aad: &head,
            },
        )
        .map_err(|_| Error::Corrupt)?;
    head.extend_from_slice(&encrypted);
    if head.len() > MAX_FILE {
        return Err(Error::Limit);
    }
    Ok(head)
}
fn parse(uid: u32, b: &[u8]) -> Result<Vec<Slot>> {
    if b.len() < HEADER + SLOT + 16
        || b.len() > MAX_FILE
        || !is_login(b)
        || b[8..12] != uid.to_le_bytes()
        || b[12..16] != 2u32.to_le_bytes()
        || !(1..=2).contains(&b[16])
        || b[17..24] != [0; 7]
        || b[52..64] != [0; 12]
    {
        return Err(Error::Corrupt);
    }
    let n = b[16] as usize;
    let aad = HEADER + n * SLOT;
    if b.len() < aad + 16
        || u32::from_le_bytes(b[48..52].try_into().unwrap()) as usize != b.len() - aad
    {
        return Err(Error::Corrupt);
    }
    let mut slots = vec![];
    for chunk in b[HEADER..aad].chunks_exact(SLOT) {
        let slot = Slot {
            tag: chunk[..32].try_into().unwrap(),
            salt: chunk[32..48].try_into().unwrap(),
            nonce: chunk[48..72].try_into().unwrap(),
            encrypted: chunk[72..].try_into().unwrap(),
        };
        if slots.iter().any(|s: &Slot| s.tag == slot.tag) {
            return Err(Error::Corrupt);
        }
        slots.push(slot);
    }
    Ok(slots)
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fixed;
    impl Random for Fixed {
        fn fill(&mut self, b: &mut [u8]) -> Result<()> {
            b.fill(4);
            Ok(())
        }
    }
    fn hex(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks_exact(2)
            .map(|b| u8::from_str_radix(core::str::from_utf8(b).unwrap(), 16).unwrap())
            .collect()
    }
    #[test]
    fn format_matches_independent_argon2_libsodium_and_authenticates_wrappers() {
        let login = LoginKey {
            tag: [5; 32],
            salt: core::array::from_fn(|n| n as u8),
            key: derive_login(b"login-password", &core::array::from_fn(|n| n as u8)).unwrap(),
        };
        assert_eq!(
            login.key.as_slice(),
            hex("fa4bfdd4001529eda19dca49f52f91e41b64cc1cc04d98f980aa5df50e75b00a")
        );
        let slot = login.wrap(1000, &[3; 32], &mut Fixed).unwrap();
        let vault = Unlocked {
            data: Data::empty(),
            key: Zeroizing::new([3; 32]),
            salt: [0; 16],
            publication: None,
            login: Some(Protection { slots: vec![slot] }),
        };
        let blob = seal(&vault, 1000, &vault.data, [6; 24]).unwrap();
        assert_eq!(
            blob,
            hex(
                "4d4b455956303032e80300000200000001000000000000000606060606060606060606060606060606060606060606061a0000000000000000000000000000000505050505050505050505050505050505050505050505050505050505050505000102030405060708090a0b0c0d0e0f0404040404040404040404040404040404040404040404044bfdca61114d52be4ae705d500b6870f4ba0fa8966d54bd31bfc673fa8859e831f92fa21351b181b766fa0704f870df34756798a8f62da4817c71e05c8a439a00e441f88751b58e0ceaf"
            )
        );
        assert!(open(1000, b"login-password", Some([5; 32]), &blob).is_ok());
        assert!(open(1001, b"login-password", Some([5; 32]), &blob).is_err());
        assert!(open(1000, b"wrong", Some([5; 32]), &blob).is_err());
        for i in [
            0,
            8,
            12,
            16,
            17,
            24,
            48,
            52,
            64,
            96,
            112,
            136,
            184,
            blob.len() - 1,
        ] {
            let mut changed = blob.clone();
            changed[i] ^= 1;
            assert!(
                open(1000, b"login-password", Some([5; 32]), &changed).is_err(),
                "tampered byte {i}"
            );
        }
        for n in 0..blob.len() {
            assert!(parse(1000, &blob[..n]).is_err());
        }
        let mut extra = blob;
        extra.push(0);
        assert!(parse(1000, &extra).is_err());
    }
}
