//! One provider-object ID space, with explicit disk/device backing.

use std::collections::HashMap;

use crate::namespace::Node;
use crate::null_device::NullDescription;
use crate::service::OpenFile;

pub(crate) struct DeviceOpen {
    pub node: Node,
    pub null: Option<NullDescription>,
    pub offset: u64,
    pub directory_flags: u32,
}

enum Description {
    Disk(OpenFile),
    Device(DeviceOpen),
}

#[derive(Default)]
pub(crate) struct OpenTable(HashMap<u64, Description>);

impl OpenTable {
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
