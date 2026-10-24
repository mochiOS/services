//! Inode-scoped FIFO ownership. Keys are derived only from a validated reply
//! from the caller's held filesystem endpoint, never from a public request.
use crate::{
    fifo::{Access, Channel, DescriptionId, Error, Readiness, WaitCondition},
    fifo_inode,
    fifo_provider::{self, Binding},
    filesystem_reference::Reference,
};
use mnu_abi::{IpcObjectHandle, IpcObjectHandles, provider};
use mochios_filesystem_protocol as wire;
use std::sync::atomic::{AtomicU64, Ordering};

pub const MAX_CHANNELS: usize = 128;
pub const MAX_DESCRIPTIONS: usize = 1024;
// Notification objects use the upper half of the positive object ID space.
// Neither these IDs nor their tags grant authority; native Handle delivery does.
pub const MAX_DATA_OBJECT_ID: u64 = (1 << 62) - 1;
static NEXT_SCOPE: AtomicU64 = AtomicU64::new(1);

/// Local namespace for one held filesystem authority. Allocate a fresh scope
/// when replacing that authority. This token grants no native rights and is
/// never accepted from IPC bytes; inode pins, not this number, retain resources.
#[derive(Clone, Copy)]
pub struct FilesystemScope(u64);
impl FilesystemScope {
    pub fn new() -> Result<Self, i32> {
        let mut value = NEXT_SCOPE.load(Ordering::Relaxed);
        loop {
            let next = value.checked_add(1).ok_or(-75)?;
            match NEXT_SCOPE.compare_exchange_weak(
                value,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(Self(value)),
                Err(current) => value = current,
            }
        }
    }

    /// After successful native IPC on this scope's held filesystem endpoint.
    /// `access` comes from the authenticated open policy, not a data-client
    /// claim. Validation failure leaves incoming references with the caller;
    /// adopt consumes the metadata reference even if adoption itself fails.
    /// Adoption uses positive errno, like Reference::from_received; this
    /// boundary returns negative POSIX service statuses.
    pub fn admit(
        self,
        header: wire::Header,
        request_id: u64,
        payload: &[u8],
        objects: &mut IpcObjectHandles,
        access: Access,
        adopt: impl FnOnce(IpcObjectHandle) -> Result<Reference, i32>,
    ) -> Result<AdmittedInode, i32> {
        let status = fifo_inode::validate_reply(header, request_id, payload, objects)?;
        let object = std::mem::take(&mut objects.handles[0]);
        objects.count = 0;
        let metadata = adopt(object).map_err(|error| if error > 0 { -error } else { -5 })?;
        Ok(AdmittedInode {
            key: ChannelKey {
                scope: self.0,
                device: status.device,
                inode: status.node_id,
            },
            access,
            metadata,
        })
    }
}

pub struct AdmittedInode {
    key: ChannelKey,
    access: Access,
    metadata: Reference,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChannelKey {
    scope: u64,
    device: u64,
    inode: u64,
}

struct Entry {
    key: ChannelKey,
    channel: Channel,
}
struct Open {
    id: u64,
    key: ChannelKey,
    description: DescriptionId,
    metadata: Reference,
}

#[derive(Default)]
pub struct Manager {
    channels: Vec<Entry>,
    opens: Vec<Open>,
    last_id: u64,
}

pub struct Opened {
    pub object_id: u64,
    pub handle: u32,
    pub rights: u64,
    pub channel: ChannelKey,
}
pub struct Dispatch {
    pub reply_length: Option<usize>,
    pub changed: Option<ChannelKey>,
}

fn open_error(error: Error) -> i32 {
    match error {
        Error::NoReaders => -6,
        Error::NoMemory => -12,
        Error::ResourceLimit => -23,
        _ => -5,
    }
}

impl Manager {
    pub fn is_empty(&self) -> bool {
        self.opens.is_empty()
    }
    /// Create/initialize one owned native reference before changing peer state.
    /// `create` performs only local native calls and must close any partially
    /// created reference before returning an error. Publication failure AFTER
    /// success must close the returned Handle; native OP_RELEASE then retires it.
    /// Success registers the owner-held reference, not a completed POSIX open:
    /// a blocking caller must await open_ready before publishing a user FD.
    pub fn open(
        &mut self,
        admitted: AdmittedInode,
        nonblocking: bool,
        create: impl FnOnce(u64, u64, u64) -> Result<u32, i32>,
        mut close: impl FnMut(u32),
    ) -> Result<Opened, i32> {
        if self.opens.len() == MAX_DESCRIPTIONS {
            return Err(-23);
        }
        let index = self
            .channels
            .iter()
            .position(|entry| entry.key == admitted.key);
        if index.is_none() && self.channels.len() == MAX_CHANNELS {
            return Err(-23);
        }
        let mut new_channel = Channel::default();
        match index {
            Some(index) => self.channels[index]
                .channel
                .reserve_open(admitted.access, nonblocking),
            None => new_channel.reserve_open(admitted.access, nonblocking),
        }
        .map_err(open_error)?;
        self.opens.try_reserve(1).map_err(|_| -12)?;
        if index.is_none() {
            self.channels.try_reserve(1).map_err(|_| -12)?;
        }
        let id = self
            .last_id
            .checked_add(1)
            .filter(|id| *id <= MAX_DATA_OBJECT_ID)
            .ok_or(-75)?;
        self.last_id = id; // Never reuse an ID, even after native creation fails.
        let rights = mochios_posix_protocol::fifo::COMMON_DATA_RIGHTS
            | match admitted.access {
                Access::Read => mnu_abi::HANDLE_RIGHT_READ,
                Access::Write => mnu_abi::HANDLE_RIGHT_WRITE,
            };
        let options = if nonblocking {
            mnu_abi::HANDLE_OPTION_NONBLOCKING
        } else {
            0
        };
        let handle = create(id, rights, options)?;
        if handle == 0 {
            return Err(-5);
        }
        let opened = match index {
            Some(index) => self.channels[index]
                .channel
                .open(admitted.access, nonblocking),
            None => new_channel.open(admitted.access, nonblocking),
        };
        let description = match opened {
            Ok(description) => description,
            Err(error) => {
                close(handle);
                return Err(open_error(error));
            }
        };
        let key = admitted.key;
        if index.is_none() {
            self.channels.push(Entry {
                key,
                channel: new_channel,
            });
        }
        self.opens.push(Open {
            id,
            key,
            description,
            metadata: admitted.metadata,
        });
        Ok(Opened {
            object_id: id,
            handle,
            rights,
            channel: key,
        })
    }

    pub fn readiness(&self, object_id: u64) -> Result<Readiness, i32> {
        let opened = self
            .opens
            .iter()
            .find(|entry| entry.id == object_id)
            .ok_or(-9)?;
        self.channels
            .iter()
            .find(|entry| entry.key == opened.key)
            .ok_or(-5)?
            .channel
            .readiness(opened.description)
            .map_err(|_| -9)
    }

    pub(crate) fn wait_target(
        &self,
        object_id: u64,
        condition: WaitCondition,
    ) -> Result<(ChannelKey, bool), i32> {
        if matches!(condition, WaitCondition::Write(0)) {
            return Err(-22);
        }
        let opened = self
            .opens
            .iter()
            .find(|entry| entry.id == object_id)
            .ok_or(-9)?;
        let channel = self
            .channels
            .iter()
            .find(|entry| entry.key == opened.key)
            .ok_or(-5)?;
        let ready = channel
            .channel
            .wait_ready(opened.description, condition)
            .map_err(|_| -9)?;
        Ok((opened.key, ready))
    }

    /// Update only the affected channel, including peers of a just-released
    /// description. No temporary allocation or synchronous peer RPC is needed.
    pub fn visit_signals(
        &self,
        key: ChannelKey,
        mut visit: impl FnMut(u64, u64) -> Result<(), i32>,
    ) -> Result<(), i32> {
        let Some(channel) = self.channels.iter().find(|entry| entry.key == key) else {
            return Ok(());
        };
        for opened in self.opens.iter().filter(|entry| entry.key == key) {
            let ready = channel
                .channel
                .readiness(opened.description)
                .map_err(|_| -5)?;
            visit(opened.id, fifo_provider::native_signals(ready))?;
        }
        Ok(())
    }

    pub fn duplicate_metadata(
        &self,
        object_id: u64,
        source_rights: u64,
        requested_rights: u64,
    ) -> Result<u32, i32> {
        self.opens
            .iter()
            .find(|entry| entry.id == object_id)
            .ok_or(-9)?
            .metadata
            .duplicate(source_rights, requested_rights)
            .map_err(|error| -error)
    }

    pub fn handle_provider_request(
        &mut self,
        request: &[u8],
        delivery: u32,
        attachments: u32,
        response: &mut [u8],
    ) -> Result<Dispatch, i32> {
        let (header, _) = provider::RequestHeader::decode(request).map_err(|_| -22)?;
        let failure = if delivery != mnu_abi::IPC_DELIVERY_NATIVE_OBJECT {
            Some(-13)
        } else if attachments != 0 {
            Some(-22)
        } else {
            None
        };
        if let Some(status) = failure {
            let length = provider::ResponseHeader {
                opcode: header.opcode,
                object_id: header.object_id,
                status,
                value: 0,
                data_length: 0,
            }
            .encode(&[], response)
            .map_err(|_| -22)?;
            return Ok(Dispatch {
                reply_length: Some(length),
                changed: None,
            });
        }
        let index = self
            .opens
            .iter()
            .position(|entry| entry.id == header.object_id)
            .ok_or(-9)?;
        let key = self.opens[index].key;
        let channel = self
            .channels
            .iter()
            .position(|entry| entry.key == key)
            .ok_or(-5)?;
        let binding = Binding::new(header.object_id, self.opens[index].description)?;
        let length = fifo_provider::handle_provider_request(
            &mut self.channels[channel].channel,
            binding,
            request,
            delivery,
            attachments,
            response,
        )?;
        if header.opcode == provider::OP_RELEASE {
            self.opens.swap_remove(index); // Drops the exact retained inode reference.
            if !self.opens.iter().any(|entry| entry.key == key) {
                self.channels.swap_remove(channel);
            }
        }
        Ok(Dispatch {
            reply_length: length,
            changed: Some(key),
        })
    }
}
