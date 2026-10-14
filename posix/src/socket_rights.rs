//! Owned ancillary references across multi-batch staging and queued messages.
//! Only the native adapter may adopt kernel-received references. Wire integers
//! and FD metadata never confer authority; native rights remain authoritative.

use mochios_posix_protocol::{InheritedFdMetadata, socket::MAX_TRANSFERRED_DESCRIPTORS};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

/// Exactly one owned receiver-local reference. Not Clone/Copy: duplicating a
/// Rust value must never imply duplicating native authority or a close duty.
pub struct Lease {
    handle: u32,
    rights: u64,
    metadata: InheritedFdMetadata,
    close: fn(u32),
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
        let lease = Self {
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
        Ok(lease)
    }
    pub fn handle(&self) -> u32 {
        self.handle
    }
    pub fn rights(&self) -> u64 {
        self.rights
    }
    /// Reporting/dispatch hints only. Every actual access is checked against
    /// the attached native object's type and kernel-enforced rights.
    pub fn metadata(&self) -> InheritedFdMetadata {
        self.metadata
    }
}
impl Drop for Lease {
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
    pub fn leases(&self) -> &[Lease] {
        &self.leases
    }
    pub fn len(&self) -> usize {
        self.leases.len()
    }
    pub fn is_empty(&self) -> bool {
        self.leases.is_empty()
    }
}
