//! Read-only user-space filesystem access before a POSIX endpoint exists.
//! The caller selects an authenticated partition; this module has no boot
//! slot, service-name, pathname-policy, or kernel descriptor knowledge.

use std::error::Error;
use std::io;
use std::sync::Arc;

use ext4plus::{Ext4, FollowSymlinks};

use crate::ext4::ImmutableExt4Storage;
use crate::storage::{PartitionIo, SectorDevice};

pub struct BootstrapReader {
    filesystem: Ext4,
}

impl BootstrapReader {
    pub fn load<D>(partition: Arc<PartitionIo<D>>) -> io::Result<Self>
    where
        D: SectorDevice + Send + 'static,
        D::Error: Error + Send + Sync + 'static,
    {
        // Never attach a writer to the boot generation.
        let filesystem =
            Ext4::load(Box::new(ImmutableExt4Storage::new(partition))).map_err(io::Error::other)?;
        Ok(Self { filesystem })
    }

    pub fn read(&self, path: &str, maximum_bytes: usize) -> io::Result<Vec<u8>> {
        if !path.starts_with('/') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "absolute path required",
            ));
        }
        let inode = self
            .filesystem
            .path_to_inode(
                path.try_into().map_err(io::Error::other)?,
                FollowSymlinks::All,
            )
            .map_err(io::Error::other)?;
        if !inode.file_type().is_regular_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "regular file required",
            ));
        }
        let length = usize::try_from(inode.metadata().len()).map_err(io::Error::other)?;
        if length > maximum_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "bootstrap file exceeds limit",
            ));
        }
        let mut output = Vec::new();
        output.try_reserve_exact(length).map_err(io::Error::other)?;
        output.resize(length, 0);
        let mut file =
            ext4plus::file::File::open_inode(&self.filesystem, inode).map_err(io::Error::other)?;
        let mut done = 0;
        while done < length {
            let count = file
                .read_bytes_at(&mut output[done..], done as u64)
                .map_err(io::Error::other)?;
            if count == 0 || count > length - done {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "incomplete boot generation file",
                ));
            }
            done += count;
        }
        Ok(output)
    }
}
