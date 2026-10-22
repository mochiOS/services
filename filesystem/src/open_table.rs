//! One provider-object ID space, with explicit disk/device backing.

use std::collections::HashMap;

use crate::namespace::Node;
use crate::null_device::NullDescription;
use crate::service::OpenFile;

const ENOTDIR: i32 = 20;
const EISDIR: i32 = 21;
const ENOTSUP: i32 = 95;

pub(crate) struct DeviceOpen {
    pub node: Node,
    pub backing: DeviceBacking,
}

pub(crate) enum DeviceBacking {
    Directory(DirectoryOpen),
    Null(NullDescription),
    ExternalMetadata(crate::devfs::ExternalOpen),
}

pub(crate) struct DirectoryOpen {
    pub offset: u64,
    pub flags: u32,
    pub cursor_records: bool,
}

impl DeviceOpen {
    pub fn null(&self) -> Result<&NullDescription, i32> {
        match &self.backing {
            DeviceBacking::Null(null) => Ok(null),
            DeviceBacking::Directory(_) => Err(EISDIR),
            DeviceBacking::ExternalMetadata(_) => Err(ENOTSUP),
        }
    }
    pub fn directory_mut(&mut self) -> Result<&mut DirectoryOpen, i32> {
        match &mut self.backing {
            DeviceBacking::Directory(directory) => Ok(directory),
            DeviceBacking::Null(_) => Err(ENOTDIR),
            DeviceBacking::ExternalMetadata(_) => Err(ENOTDIR),
        }
    }
    pub fn is_directory(&self) -> bool {
        match &self.backing {
            DeviceBacking::Directory(_) => true,
            DeviceBacking::Null(_) => false,
            DeviceBacking::ExternalMetadata(_) => false,
        }
    }
    pub fn flags(&self) -> Result<u32, i32> {
        match &self.backing {
            DeviceBacking::Directory(directory) => Ok(directory.flags),
            DeviceBacking::Null(null) => Ok(null.flags()),
            DeviceBacking::ExternalMetadata(_) => Err(ENOTSUP),
        }
    }
    pub fn set_flags(&mut self, flags: u32) -> Result<(), i32> {
        match &mut self.backing {
            DeviceBacking::Directory(directory) => {
                directory.flags = flags;
                Ok(())
            }
            DeviceBacking::Null(null) => null.set_flags(flags),
            DeviceBacking::ExternalMetadata(_) => Err(ENOTSUP),
        }
    }
}

enum Description {
    Disk(OpenFile),
    Device(DeviceOpen),
}

#[derive(Default)]
pub(crate) struct OpenTable(HashMap<u64, Description>);

impl OpenTable {
    pub fn try_reserve(&mut self, additional: usize) -> Result<(), std::collections::TryReserveError> {
        self.0.try_reserve(additional)
    }

    // Existing ext4 operations access only disk descriptions. Device operations
    // must select the other variant explicitly; no fake inode or disk fallback.
    pub fn get(&self, id: &u64) -> Option<&OpenFile> {
        match self.0.get(id)? {
            Description::Disk(open) => Some(open),
            _ => None,
        }
    }
    pub fn get_mut(&mut self, id: &u64) -> Option<&mut OpenFile> {
        match self.0.get_mut(id)? {
            Description::Disk(open) => Some(open),
            _ => None,
        }
    }
    pub fn device(&self, id: u64) -> Option<&DeviceOpen> {
        match self.0.get(&id)? {
            Description::Device(open) => Some(open),
            _ => None,
        }
    }
    pub fn device_mut(&mut self, id: u64) -> Option<&mut DeviceOpen> {
        match self.0.get_mut(&id)? {
            Description::Device(open) => Some(open),
            _ => None,
        }
    }
    pub fn insert(&mut self, id: u64, open: OpenFile) {
        self.0.insert(id, Description::Disk(open));
    }
    pub fn insert_device(&mut self, id: u64, open: DeviceOpen) {
        self.0.insert(id, Description::Device(open));
    }
    pub fn remove(&mut self, id: &u64) {
        self.0.remove(id);
    }
    pub fn values(&self) -> impl Iterator<Item = &OpenFile> {
        self.0.values().filter_map(|open| match open {
            Description::Disk(open) => Some(open),
            _ => None,
        })
    }
    pub fn values_mut(&mut self) -> impl Iterator<Item = &mut OpenFile> {
        self.0.values_mut().filter_map(|open| match open {
            Description::Disk(open) => Some(open),
            _ => None,
        })
    }
}
