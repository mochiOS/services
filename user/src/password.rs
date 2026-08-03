use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

const ALGORITHM: &str = "pbkdf2-sha256";
const ITERATIONS: u32 = 100_000;
const MAX_ACCEPTED_ITERATIONS: u32 = 2_000_000;
const SALT_LEN: usize = 16;
const HASH_LEN: usize = 32;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasswordError {
    Random,
}

pub fn hash(password: &[u8]) -> Result<String, PasswordError> {
    let mut salt = [0u8; SALT_LEN];
    mochi_user_platform::random::fill(&mut salt).map_err(|_| PasswordError::Random)?;
    Ok(encode_hash(password, &salt, ITERATIONS))
}

pub fn verify(password: &[u8], encoded: &str) -> bool {
    let parsed = parse_hash(encoded);
    let (iterations, salt, expected) =
        parsed.unwrap_or((ITERATIONS, [0u8; SALT_LEN], [0u8; HASH_LEN]));
    let mut actual = derive(password, &salt, iterations);
    let matches = parsed.is_some() && constant_time_equal(&actual, &expected);
    actual.zeroize();
    matches
}

fn encode_hash(password: &[u8], salt: &[u8; SALT_LEN], iterations: u32) -> String {
    let mut digest = derive(password, salt, iterations);
    let encoded = format!(
        "{ALGORITHM}${iterations}${}${}",
        encode_hex(salt),
        encode_hex(&digest)
    );
    digest.zeroize();
    encoded
}

fn parse_hash(encoded: &str) -> Option<(u32, [u8; SALT_LEN], [u8; HASH_LEN])> {
    let mut fields = encoded.split('$');
    if fields.next()? != ALGORITHM {
        return None;
    }
    let iterations = fields.next()?.parse::<u32>().ok()?;
    if iterations < ITERATIONS || iterations > MAX_ACCEPTED_ITERATIONS {
        return None;
    }
    let salt = decode_hex::<SALT_LEN>(fields.next()?)?;
    let digest = decode_hex::<HASH_LEN>(fields.next()?)?;
    if fields.next().is_some() {
        return None;
    }
    Some((iterations, salt, digest))
}

fn derive(password: &[u8], salt: &[u8], iterations: u32) -> [u8; HASH_LEN] {
    let mut initial = Vec::with_capacity(salt.len() + 4);
    initial.extend_from_slice(salt);
    initial.extend_from_slice(&1u32.to_be_bytes());
    let mut block = prf(password, &initial);
    let mut output = block;
    for _ in 1..iterations {
        block = prf(password, &block);
        for (destination, byte) in output.iter_mut().zip(block) {
            *destination ^= byte;
        }
    }
    block.zeroize();
    output
}

fn prf(key: &[u8], message: &[u8]) -> [u8; HASH_LEN] {
    let Ok(mut mac) = HmacSha256::new_from_slice(key) else {
        return [0u8; HASH_LEN];
    };
    mac.update(message);
    mac.finalize().into_bytes().into()
}

fn constant_time_equal(left: &[u8; HASH_LEN], right: &[u8; HASH_LEN]) -> bool {
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn decode_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.len() != N * 2 {
        return None;
    }
    let mut output = [0u8; N];
    for (index, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        output[index] = decode_nibble(pair[0])?
            .checked_mul(16)?
            .checked_add(decode_nibble(pair[1])?)?;
    }
    Some(output)
}

fn decode_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pbkdf2_matches_rfc_6070_structure_with_sha256_vectors() {
        assert_eq!(
            encode_hex(&derive(b"password", b"salt", 1)),
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
        );
        assert_eq!(
            encode_hex(&derive(b"password", b"salt", 2)),
            "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"
        );
    }

    #[test]
    fn encoded_hash_verifies_and_rejects_changes() {
        let encoded = encode_hash(b"secret", &[0x5a; SALT_LEN], ITERATIONS);
        assert!(verify(b"secret", &encoded));
        assert!(!verify(b"Secret", &encoded));
        assert!(!verify(b"secret", "!"));
        assert!(!verify(b"secret", "pbkdf2-sha256$0$00$00"));
    }

    #[test]
    fn empty_password_is_hashed_and_verified() {
        let encoded = encode_hash(b"", &[0x5a; SALT_LEN], ITERATIONS);
        assert!(verify(b"", &encoded));
        assert!(!verify(b"non-empty", &encoded));
    }
}
