//! Explicit translation between independently versioned user-space protocols.
use mochios_filesystem_protocol as filesystem;
use mochios_posix_protocol::file_time::{Change, Update};

pub fn translate(times: Update) -> filesystem::FileTimeUpdate {
    fn field(value: Change) -> filesystem::TimestampUpdate {
        match value {
            Change::Set {
                seconds,
                nanoseconds,
            } => filesystem::TimestampUpdate::Set {
                seconds,
                nanoseconds,
            },
            Change::Now => filesystem::TimestampUpdate::Now,
            Change::Omit => filesystem::TimestampUpdate::Omit,
        }
    }
    filesystem::FileTimeUpdate {
        access: field(times.access),
        modification: field(times.modification),
    }
}
