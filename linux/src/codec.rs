#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DecodeError {
    InvalidHex,
    InvalidRle,
    Allocation,
}

pub(crate) fn decode_hex(value: &str) -> Result<Vec<u8>, DecodeError> {
    if !value.len().is_multiple_of(2) {
        return Err(DecodeError::InvalidHex);
    }
    let mut decoded = Vec::new();
    decoded
        .try_reserve_exact(value.len() / 2)
        .map_err(|_| DecodeError::Allocation)?;
    for pair in value.as_bytes().chunks_exact(2) {
        let high = hex_nibble(pair[0]).ok_or(DecodeError::InvalidHex)?;
        let low = hex_nibble(pair[1]).ok_or(DecodeError::InvalidHex)?;
        decoded.push((high << 4) | low);
    }
    Ok(decoded)
}

pub(crate) fn decode_rle32(encoded: &[u8], expected: usize) -> Result<Vec<u8>, DecodeError> {
    if encoded.len() % 6 != 0 || expected % 4 != 0 {
        return Err(DecodeError::InvalidRle);
    }
    let mut decoded = Vec::new();
    decoded
        .try_reserve_exact(expected)
        .map_err(|_| DecodeError::Allocation)?;
    for run in encoded.chunks_exact(6) {
        let count = usize::from(u16::from_le_bytes([run[0], run[1]]));
        if count == 0 {
            return Err(DecodeError::InvalidRle);
        }
        let bytes = count.checked_mul(4).ok_or(DecodeError::InvalidRle)?;
        if decoded.len().saturating_add(bytes) > expected {
            return Err(DecodeError::InvalidRle);
        }
        for _ in 0..count {
            decoded.extend_from_slice(&run[2..6]);
        }
    }
    if decoded.len() == expected {
        Ok(decoded)
    } else {
        Err(DecodeError::InvalidRle)
    }
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_decode_rejects_odd_and_non_hex_input() {
        assert_eq!(decode_hex("00aF"), Ok(vec![0x00, 0xaf]));
        assert_eq!(decode_hex("0"), Err(DecodeError::InvalidHex));
        assert_eq!(decode_hex("gg"), Err(DecodeError::InvalidHex));
    }

    #[test]
    fn rle32_requires_exact_decoded_size() {
        let encoded = [2, 0, 0x11, 0x22, 0x33, 0x44];
        assert_eq!(
            decode_rle32(&encoded, 8),
            Ok(vec![0x11, 0x22, 0x33, 0x44, 0x11, 0x22, 0x33, 0x44])
        );
        assert_eq!(decode_rle32(&encoded, 4), Err(DecodeError::InvalidRle));
        assert_eq!(decode_rle32(&encoded, 12), Err(DecodeError::InvalidRle));
    }

    #[test]
    fn rle32_rejects_zero_and_partial_runs() {
        assert_eq!(
            decode_rle32(&[0, 0, 1, 2, 3, 4], 4),
            Err(DecodeError::InvalidRle)
        );
        assert_eq!(
            decode_rle32(&[1, 0, 1, 2, 3], 4),
            Err(DecodeError::InvalidRle)
        );
    }
}
