//! Translate admitted open policy without path lookups or authority changes.
use crate::PreparedOpen;
use mochios_filesystem_protocol as filesystem;
use mochios_posix_protocol as posix;

impl PreparedOpen {
    pub fn filesystem_flags(&self, attached_base: bool) -> u32 {
        let mut flags = filesystem::OPEN_AT_ROOT_ATTACHED;
        if attached_base {
            flags |= filesystem::OPEN_AT_BASE_ATTACHED;
        }
        for (source, target) in [
            (posix::OPEN_READ, filesystem::OPEN_AT_READ),
            (posix::OPEN_WRITE, filesystem::OPEN_AT_WRITE),
            (posix::OPEN_CREATE, filesystem::OPEN_AT_CREATE),
            (posix::OPEN_EXCLUSIVE, filesystem::OPEN_AT_EXCLUSIVE),
            (posix::OPEN_TRUNCATE, filesystem::OPEN_AT_TRUNCATE),
            (posix::OPEN_APPEND, filesystem::OPEN_AT_APPEND),
            (posix::OPEN_NONBLOCK, filesystem::OPEN_AT_NONBLOCK),
            (posix::OPEN_DIRECTORY, filesystem::OPEN_AT_DIRECTORY),
            (posix::OPEN_NOFOLLOW, filesystem::OPEN_AT_NOFOLLOW),
            (
                posix::OPEN_CURSOR_RECORDS,
                filesystem::OPEN_AT_CURSOR_RECORDS,
            ),
            (posix::OPEN_EXECUTE, filesystem::OPEN_AT_EXECUTE),
        ] {
            if self.options & source != 0 {
                flags |= target;
            }
        }
        flags
    }
}
