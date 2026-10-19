//! Convert ext4plus's packed, unsigned Duration into signed inode timestamps.
//!
//! The pinned library concatenates the extra epoch bits with the low unsigned
//! seconds. ext4 instead adds those epoch bits to a sign-extended low i32.
//! Keep this adapter local to ext4 metadata; ordinary Duration is not encoded
//! this way. See https://docs.kernel.org/filesystems/ext4/inodes.html .

use std::time::Duration;

pub(super) fn decode(value: Duration) -> Option<(i64, u32)> {
    let packed = value.as_secs();
    // Two extra epoch bits and the original low 32-bit seconds field.
    if packed >> 34 != 0 {
        return None;
    }
    let low = i64::from(packed as u32 as i32);
    let epoch = ((packed >> 32) as i64) << 32;
    Some((low + epoch, value.subsec_nanos()))
}
