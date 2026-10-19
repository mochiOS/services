//! Checked signed timestamp updates, separate from the legacy packed Duration API.
//!
//! ext4 adds its two epoch bits to sign-extended low seconds. Extra fields
//! belong to an inode only when both its record and i_extra_isize cover them.
//! https://docs.kernel.org/filesystems/ext4/inodes.html#inode-timestamps

use super::Inode;
use crate::util::{read_u16le, write_u32le};
use core::fmt;

/// Seconds relative to the Unix epoch and a nonnegative fractional second.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InodeTimestamp {
    /// Whole signed seconds relative to 1970-01-01 00:00:00 UTC.
    pub seconds: i64,
    /// Fraction within that second, in the range 0..1_000_000_000.
    pub nanoseconds: u32,
}

/// Failure before any timestamp fields have been modified.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimestampError {
    /// The supplied fractional second is not normalized.
    InvalidNanoseconds,
    /// The inode cannot encode the supplied signed seconds.
    OutOfRange,
    /// The declared extended inode fields exceed the allocated record.
    InvalidInodeLayout,
}

impl fmt::Display for TimestampError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidNanoseconds => {
                "timestamp nanoseconds must be less than one billion"
            }
            Self::OutOfRange => {
                "timestamp seconds are outside the inode's representable range"
            }
            Self::InvalidInodeLayout => {
                "inode extra fields exceed the inode record"
            }
        })
    }
}

impl core::error::Error for TimestampError {}

fn encode(
    value: InodeTimestamp,
    extra: bool,
) -> Result<(u32, u32), TimestampError> {
    if value.nanoseconds >= 1_000_000_000 {
        return Err(TimestampError::InvalidNanoseconds);
    }
    let maximum = if extra {
        0x3_7fff_ffff
    } else {
        i64::from(i32::MAX)
    };
    if value.seconds < i64::from(i32::MIN) || value.seconds > maximum {
        return Err(TimestampError::OutOfRange);
    }
    let low = value.seconds as u32;
    // Bounds above make subtraction safe, including negative dates.
    let epoch = ((value.seconds - i64::from(low as i32)) >> 32) as u32;
    Ok((low, epoch | (value.nanoseconds << 2)))
}

impl Inode {
    /// Stage access, modification and change times, preserving `None` fields.
    ///
    /// All requested values and the inode layout are checked before changing
    /// any field. Call [`Self::write`] afterwards to persist the inode. This
    /// does not check credentials, choose current time, or change ctime on the
    /// caller's behalf; those policies belong to the filesystem service.
    ///
    /// Fields without an ext4 extra word have signed 32-bit seconds and whole
    /// second precision. Their fractional seconds are rounded down, never up.
    /// Fields with an extra word represent -2147483648..=15032385535 seconds
    /// with nanosecond precision. Seconds outside the field's range are rejected,
    /// not masked into another date. No inode extensions or xattrs are grown.
    pub fn set_signed_timestamps(
        &mut self,
        access: Option<InodeTimestamp>,
        modification: Option<InodeTimestamp>,
        change: Option<InodeTimestamp>,
    ) -> Result<(), TimestampError> {
        if access.is_none() && modification.is_none() && change.is_none() {
            return Ok(());
        }
        let declared_size = if self.inode_data.len() >= 0x82 {
            128 + usize::from(read_u16le(&self.inode_data, 0x80))
        } else {
            128
        };
        if declared_size > self.inode_data.len() {
            return Err(TimestampError::InvalidInodeLayout);
        }
        let fields = [
            (access, 0x08, 0x8c),
            (modification, 0x10, 0x88),
            (change, 0x0c, 0x84),
        ];
        let mut encoded = [None; 3];
        for (slot, (value, _, extra_offset)) in encoded.iter_mut().zip(fields) {
            if let Some(value) = value {
                let has_extra = declared_size >= extra_offset + 4;
                *slot = Some((encode(value, has_extra)?, has_extra));
            }
        }
        for ((_, low_offset, extra_offset), value) in
            fields.into_iter().zip(encoded)
        {
            if let Some(((low, extra), has_extra)) = value {
                write_u32le(&mut self.inode_data, low_offset, low);
                if has_extra {
                    write_u32le(&mut self.inode_data, extra_offset, extra);
                }
            }
        }
        Ok(())
    }
}
