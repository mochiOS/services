use crate::present::{DamageRect, DisplayGeometry};

pub(crate) const OP_GET_INFO: u32 = 1;
pub(crate) const OP_PRESENT: u32 = 2;
pub(crate) const OP_CLAIM_PRESENT_OWNER: u32 = 3;
pub(crate) const OP_PRESENT_RECT: u32 = 4;

pub(crate) fn read_u32(buffer: &[u8], offset: usize) -> Option<u32> {
    let bytes = buffer.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

pub(crate) fn put_u32(buffer: &mut [u8], offset: usize, value: u32) -> bool {
    let Some(bytes) = buffer.get_mut(offset..offset.saturating_add(4)) else {
        return false;
    };
    bytes.copy_from_slice(&value.to_le_bytes());
    true
}

pub(crate) fn decode_geometry(buffer: &[u8]) -> Option<DisplayGeometry> {
    Some(DisplayGeometry {
        width: read_u32(buffer, 4)?,
        height: read_u32(buffer, 8)?,
        stride: read_u32(buffer, 12)?,
        format: read_u32(buffer, 16)?,
    })
}

pub(crate) fn decode_damage(buffer: &[u8]) -> Option<DamageRect> {
    Some(DamageRect {
        x: read_u32(buffer, 20)?,
        y: read_u32(buffer, 24)?,
        width: read_u32(buffer, 28)?,
        height: read_u32(buffer, 32)?,
    })
}

pub(crate) fn errno_status(errno: u64) -> u32 {
    let signed = errno as i64;
    if signed < 0 {
        signed.wrapping_neg() as u32
    } else {
        errno as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> [u8; 36] {
        let mut request = [0u8; 36];
        for (offset, value) in [
            (0, OP_PRESENT_RECT),
            (4, 640),
            (8, 480),
            (12, 672),
            (16, crate::present::PIXEL_FORMAT_XRGB8888),
            (20, 7),
            (24, 9),
            (28, 11),
            (32, 13),
        ] {
            assert!(put_u32(&mut request, offset, value));
        }
        request
    }

    #[test]
    fn decodes_explicit_geometry_and_damage_fields() {
        let request = request();
        assert_eq!(
            decode_geometry(&request),
            Some(DisplayGeometry {
                width: 640,
                height: 480,
                stride: 672,
                format: crate::present::PIXEL_FORMAT_XRGB8888,
            })
        );
        assert_eq!(
            decode_damage(&request),
            Some(DamageRect {
                x: 7,
                y: 9,
                width: 11,
                height: 13,
            })
        );
    }

    #[test]
    fn rejects_short_fields_and_small_encode_buffers() {
        let request = request();
        assert_eq!(decode_geometry(&request[..19]), None);
        assert_eq!(decode_damage(&request[..35]), None);
        assert!(!put_u32(&mut [0u8; 3], 0, 1));
        assert!(!put_u32(&mut [0u8; 4], usize::MAX, 1));
    }
}
