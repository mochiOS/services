//! Read-only user-space filesystem access before a POSIX endpoint exists.
//! The caller selects an authenticated partition; this module has no boot
//! slot, service-name, pathname-policy, or kernel descriptor knowledge.

use std::error::Error;
use std::io;
use std::sync::Arc;

use ext4plus::error::Ext4Error;
use ext4plus::{Ext4, FollowSymlinks};
use ext4plus::{dir::Dir, inode::Inode};

use crate::ext4::ImmutableExt4Storage;
use crate::storage::{PartitionIo, SectorDevice};

pub struct BootstrapReader {
    filesystem: Ext4,
}

pub struct BootstrapDirectoryPage {
    pub names: Vec<String>,
    /// Cookie in this immutable directory's on-disk entry order.
    pub next_entry: u64,
    pub eof: bool,
}

// ext4plus's std conversion is unavailable with our no-default-features
// dependency. Preserve typed failures without enabling its host filesystem I/O.
fn filesystem_error(error: Ext4Error) -> io::Error {
    let kind = match error {
        Ext4Error::NotFound => io::ErrorKind::NotFound,
        Ext4Error::IsADirectory => io::ErrorKind::IsADirectory,
        Ext4Error::NotADirectory => io::ErrorKind::NotADirectory,
        Ext4Error::NotAbsolute
        | Ext4Error::MalformedPath
        | Ext4Error::IsASpecialFile
        | Ext4Error::NotASymlink
        | Ext4Error::InvalidXattrName
        | Ext4Error::DotEntry => io::ErrorKind::InvalidInput,
        Ext4Error::NotUtf8 => io::ErrorKind::InvalidData,
        Ext4Error::Encrypted => io::ErrorKind::PermissionDenied,
        Ext4Error::Readonly => io::ErrorKind::ReadOnlyFilesystem,
        Ext4Error::FileTooLarge => io::ErrorKind::FileTooLarge,
        Ext4Error::AlreadyExists => io::ErrorKind::AlreadyExists,
        Ext4Error::NoSpace => io::ErrorKind::StorageFull,
        Ext4Error::PathTooLong => return io::Error::from_raw_os_error(36),
        Ext4Error::TooManySymlinks => return io::Error::from_raw_os_error(40),
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, error)
}

impl BootstrapReader {
    pub fn load<D>(partition: Arc<PartitionIo<D>>) -> io::Result<Self>
    where
        D: SectorDevice + Send + 'static,
        D::Error: Error + Send + Sync + 'static,
    {
        // Never attach a writer to the boot generation.
        let filesystem =
            Ext4::load(Box::new(ImmutableExt4Storage::new(partition))).map_err(filesystem_error)?;
        Ok(Self { filesystem })
    }

    fn inode(&self, path: &str) -> io::Result<Inode> {
        if !path.starts_with('/') || path.contains('\0') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "absolute path required",
            ));
        }
        self.filesystem
            .path_to_inode(
                path.try_into()
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?,
                FollowSymlinks::All,
            )
            .map_err(filesystem_error)
    }

    fn regular_inode(&self, path: &str) -> io::Result<Inode> {
        let inode = self.inode(path)?;
        if inode.file_type().is_dir() {
            return Err(io::Error::from_raw_os_error(21));
        }
        if !inode.file_type().is_regular_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "regular file required",
            ));
        }
        Ok(inode)
    }

    pub fn read(&self, path: &str, maximum_bytes: usize) -> io::Result<Vec<u8>> {
        let inode = self.regular_inode(path)?;
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
            ext4plus::file::File::open_inode(&self.filesystem, inode).map_err(filesystem_error)?;
        Self::read_range(&mut file, &mut output, 0)?;
        Ok(output)
    }

    /// Fill only the supplied range, without allocating the entire file.
    /// The selected partition must remain immutable for this reader's lifetime.
    pub fn read_at(&self, path: &str, offset: u64, output: &mut [u8]) -> io::Result<usize> {
        offset.checked_add(output.len() as u64).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "bootstrap range overflow")
        })?;
        let inode = self.regular_inode(path)?;
        let remaining = inode.metadata().len().saturating_sub(offset);
        let length = remaining.min(output.len() as u64) as usize;
        let mut file =
            ext4plus::file::File::open_inode(&self.filesystem, inode).map_err(filesystem_error)?;
        Self::read_range(&mut file, &mut output[..length], offset)?;
        Ok(length)
    }

    fn read_range(
        file: &mut ext4plus::file::File,
        output: &mut [u8],
        offset: u64,
    ) -> io::Result<()> {
        let mut done = 0;
        while done < output.len() {
            let count = file
                .read_bytes_at(&mut output[done..], offset + done as u64)
                .map_err(filesystem_error)?;
            if count == 0 || count > output.len() - done {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "incomplete boot generation file",
                ));
            }
            done += count;
        }
        Ok(())
    }

    /// Paginate names with both entry and byte limits for bounded IPC replies.
    /// Dot entries are consumed but never exposed to recursive package walkers.
    pub fn read_directory(
        &self,
        path: &str,
        start_entry: u64,
        maximum_entries: usize,
        maximum_name_bytes: usize,
    ) -> io::Result<BootstrapDirectoryPage> {
        if maximum_entries == 0 || maximum_name_bytes == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty directory page budget",
            ));
        }
        let start = usize::try_from(start_entry)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let inode = self.inode(path)?;
        if !inode.file_type().is_dir() {
            return Err(io::Error::from_raw_os_error(20));
        }
        let directory = Dir::open_inode(&self.filesystem, inode).map_err(filesystem_error)?;
        let mut page = BootstrapDirectoryPage {
            names: Vec::new(),
            next_entry: start_entry,
            eof: true,
        };
        let mut bytes = 0usize;
        for (index, entry) in directory.read_dir().map_err(filesystem_error)?.enumerate() {
            let entry = entry.map_err(filesystem_error)?;
            if index < start {
                continue;
            }
            let name = entry.file_name();
            let name = name
                .as_str()
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            if name != "." && name != ".." {
                if page.names.len() == maximum_entries || name.len() > maximum_name_bytes - bytes {
                    if page.names.is_empty() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "directory entry exceeds page budget",
                        ));
                    }
                    page.eof = false;
                    break;
                }
                page.names.try_reserve(1).map_err(io::Error::other)?;
                let mut owned = String::new();
                owned
                    .try_reserve_exact(name.len())
                    .map_err(io::Error::other)?;
                owned.push_str(name);
                page.names.push(owned);
                bytes += name.len();
            }
            page.next_entry = page.next_entry.checked_add(1).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "directory cookie overflow")
            })?;
        }
        Ok(page)
    }
}
