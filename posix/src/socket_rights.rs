//! Owned ancillary references across multi-batch staging and queued messages.
//! Only the native adapter may adopt kernel-received references. Wire integers
//! and FD metadata never confer authority; native rights remain authoritative.

use mochios_posix_protocol::{InheritedFdMetadata, socket::MAX_TRANSFERRED_DESCRIPTORS};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

/// One local owner of a receiver-local reference. Not Clone/Copy: explicit
/// snapshots share the close duty, never create additional native authority.
struct LeaseData {
    handle: u32,
    rights: u64,
    metadata: InheritedFdMetadata,
    close: fn(u32),
}
pub struct Lease {
    data: crate::socket_reference::Shared<LeaseData>,
}
impl Lease {
    /// Ownership is consumed on success AND error. Inputs must come from the
    /// kernel's attachment metadata, never from a self-reported wire Handle.
    /// Each reference must be adopted once, after adapter-level deduplication.
    pub fn adopt(
        handle: u32,
        rights: u64,
        metadata: InheritedFdMetadata,
        close: fn(u32),
    ) -> Result<Self, i32> {
        let data = LeaseData {
            handle,
            rights,
            metadata,
            close,
        };
        if handle == 0
            || rights & mnu_abi::HANDLE_RIGHT_TRANSFER == 0
            || rights & !mnu_abi::HANDLE_RIGHT_ALL != 0
        {
            return Err(-13);
        }
        // Sender CLOEXEC is descriptor-local, not inherited by SCM_RIGHTS.
        // Receiver CLOEXEC will be selected by recvmsg's own flags.
        if metadata.descriptor_flags != 0
            || metadata.open_flags & 3 == 3
            || mochios_posix_protocol::inherited_fd_kind_requires_handle(metadata.kind)
                != Some(true)
        {
            return Err(-22);
        }
        Ok(Self {
            data: crate::socket_reference::Shared::try_new(data)?,
        })
    }
    pub fn handle(&self) -> u32 {
        self.data.get().handle
    }
    pub fn rights(&self) -> u64 {
        self.data.get().rights
    }
    /// Reporting/dispatch hints only. Every actual access is checked against
    /// the attached native object's type and kernel-enforced rights.
    pub fn metadata(&self) -> InheritedFdMetadata {
        self.data.get().metadata
    }
    /// More than one userspace owner shares ONE native reference. Queue GC
    /// must treat that reference as a root while an external snapshot owns it.
    pub fn is_exclusive(&self) -> bool {
        self.data.owners() == 1
    }
    fn retain(&self) -> Result<Self, i32> {
        Ok(Self {
            data: self.data.retain()?,
        })
    }
}
impl Drop for LeaseData {
    fn drop(&mut self) {
        if self.handle != 0 {
            (self.close)(self.handle);
        }
    }
}

struct Accounting {
    limit: usize,
    used: AtomicUsize,
}
/// Owned by the socket worker, not a global authority. Staging and queued
/// bundles share one bounded allowance, including accepted-but-unread data.
#[derive(Clone)]
pub struct Budget(Arc<Accounting>);
impl Budget {
    pub fn new(limit: usize) -> Self {
        Self(Arc::new(Accounting {
            limit,
            used: AtomicUsize::new(0),
        }))
    }
    pub fn used(&self) -> usize {
        self.0.used.load(Ordering::Relaxed)
    }
    fn reserve(&self, count: usize) -> Result<Charge, i32> {
        let mut used = self.used();
        loop {
            let next = used
                .checked_add(count)
                .filter(|next| *next <= self.0.limit)
                .ok_or(-105)?;
            match self.0.used.compare_exchange_weak(
                used,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(current) => used = current,
            }
        }
        Ok(Charge {
            budget: self.clone(),
            count,
        })
    }
}
struct Charge {
    budget: Budget,
    count: usize,
}
impl Drop for Charge {
    fn drop(&mut self) {
        self.budget.0.used.fetch_sub(self.count, Ordering::Relaxed);
    }
}

/// No queue access or publication until every declared reference has arrived.
/// Final release of the staging transaction drops this value to abort it.
pub struct Pending {
    expected: usize,
    bundle: Bundle,
}
impl Pending {
    pub fn new(expected: usize, budget: &Budget) -> Result<Self, i32> {
        if expected > MAX_TRANSFERRED_DESCRIPTORS {
            return Err(-22);
        }
        let charge = budget.reserve(expected)?;
        let mut leases = Vec::new();
        leases.try_reserve_exact(expected).map_err(|_| -12)?;
        Ok(Self {
            expected,
            bundle: Bundle {
                leases,
                _charge: charge,
            },
        })
    }
    pub fn received(&self) -> usize {
        self.bundle.leases.len()
    }
    pub fn is_complete(&self) -> bool {
        self.received() == self.expected
    }
    /// Offset is a transaction-local index, not an FD or resource identity.
    /// On error the old stage is untouched; all newly supplied leases close.
    /// A repeated batch is NOT appended twice after an ambiguous/lost reply.
    pub fn append(&mut self, offset: usize, leases: Vec<Lease>) -> Result<(), i32> {
        if offset != self.received()
            || leases.is_empty()
            || leases.len() > mnu_abi::IPC_MAX_OBJECT_HANDLES - 1
            || leases.len() > self.expected - self.received()
        {
            return Err(-22);
        }
        // Capacity was reserved before receiving any batch; no allocation or
        // other fallible action remains between validation and ownership move.
        self.bundle.leases.extend(leases);
        Ok(())
    }
    /// Failure retains the entire transaction for completion or explicit abort.
    pub fn finish(self) -> Result<Bundle, Self> {
        if self.received() != self.expected {
            Err(self)
        } else {
            Ok(self.bundle)
        }
    }
}

/// Ready ancillary data. Dropping a message, including all queue discard paths,
/// closes every remaining lease and returns the corresponding budget charge.
pub struct Bundle {
    leases: Vec<Lease>,
    _charge: Charge,
}
impl Bundle {
    /// Snapshot a bounded prefix without duplicating native authority. Each
    /// logical retained reference consumes worker quota. Only the final local
    /// owner closes its native Handle; delivery still requires explicit IPC.
    pub fn snapshot(&self, maximum: usize) -> Result<Self, i32> {
        let count = maximum.min(self.len());
        let charge = self._charge.budget.reserve(count)?;
        let mut leases = Vec::new();
        leases.try_reserve_exact(count).map_err(|_| -12)?;
        for lease in &self.leases[..count] {
            leases.push(lease.retain()?);
        }
        Ok(Self {
            leases,
            _charge: charge,
        })
    }
    pub fn leases(&self) -> &[Lease] {
        &self.leases
    }
    pub fn len(&self) -> usize {
        self.leases.len()
    }
    pub fn is_empty(&self) -> bool {
        self.leases.is_empty()
    }
    /// Receiving control truncation drops references that cannot be installed.
    pub fn truncate(&mut self, maximum: usize) {
        let keep = maximum.min(self.len());
        let removed = self.len() - keep;
        self.leases.truncate(keep);
        self.release_charge(removed);
    }
    /// Only after an IPC reply has acquired independent receiver references.
    /// On reply failure leave the entire prefix owned by this bundle instead.
    pub fn discard_delivered_prefix(&mut self, count: usize) -> Result<(), i32> {
        if count > self.len() {
            return Err(-22);
        }
        drop(self.leases.drain(..count));
        self.release_charge(count);
        Ok(())
    }
    fn release_charge(&mut self, count: usize) {
        self._charge
            .budget
            .0
            .used
            .fetch_sub(count, Ordering::Relaxed);
        self._charge.count -= count;
    }
}
