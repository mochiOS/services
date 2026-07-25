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
