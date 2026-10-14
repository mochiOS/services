//! Fallibly allocated, immutable shared ownership within one socket worker.
//! Never Send/Sync: local owner counts and queue graph observations are serialized.
use std::{cell::Cell, marker::PhantomData, ptr::NonNull, rc::Rc};

struct Inner<T> {
    owners: Cell<usize>,
    capacity: usize,
    value: T,
}

pub(crate) struct Shared<T> {
    pointer: NonNull<Inner<T>>,
    _local: PhantomData<Rc<Inner<T>>>,
}
impl<T> Shared<T> {
    /// Vec supplies stable fallible allocation. Its exact allocation capacity
    /// is saved so the final owner reconstructs and drops that same allocation.
    /// Failure consumes/drops value, just as successful final release does.
    pub(crate) fn try_new(value: T) -> Result<Self, i32> {
        let mut allocation = Vec::new();
        allocation.try_reserve_exact(1).map_err(|_| -12)?;
        let capacity = allocation.capacity();
        allocation.push(Inner {
            owners: Cell::new(1),
            capacity,
            value,
        });
        let pointer = NonNull::new(allocation.as_mut_ptr()).unwrap();
        std::mem::forget(allocation);
        Ok(Self {
            pointer,
            _local: PhantomData,
        })
    }
    fn inner(&self) -> &Inner<T> {
        // SAFETY: construction owns one initialized element; each retained
        // owner increments before publication and final Drop alone deallocates.
        // PhantomData<Rc<_>> prevents use from another thread.
        unsafe { self.pointer.as_ref() }
    }
    pub(crate) fn get(&self) -> &T {
        &self.inner().value
    }
    pub(crate) fn owners(&self) -> usize {
        self.inner().owners.get()
    }
    pub(crate) fn retain(&self) -> Result<Self, i32> {
        let count = self.owners().checked_add(1).ok_or(-75)?;
        self.inner().owners.set(count);
        Ok(Self {
            pointer: self.pointer,
            _local: PhantomData,
        })
    }
}
impl<T> Drop for Shared<T> {
    fn drop(&mut self) {
        let count = self.owners();
        if count == 1 {
            let capacity = self.inner().capacity;
            // SAFETY: this is the final local owner. The element and original
            // Vec allocation remain initialized, with precisely this capacity.
            // No borrow from get() can outlive its owning Shared reference.
            unsafe { drop(Vec::from_raw_parts(self.pointer.as_ptr(), 1, capacity)) };
        } else {
            self.inner().owners.set(count - 1);
        }
    }
}
