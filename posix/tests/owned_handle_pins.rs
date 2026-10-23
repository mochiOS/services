use mochios_posix_client::handle_borrow::{Book, Pin, PinError};
use std::collections::BTreeMap;

#[test]
fn ownership_changes_only_with_pin_lifetimes_not_descriptor_owner_count() {
    let mut book = Book::<4>::new();
    let own = book.pin_owned(1, 71).unwrap();
    assert!(!book.has_foreign_pins(71));
    assert!(book.has_foreign_pins(72));
    let foreign = book.pin_owned(1, 72).unwrap();
    let own_again = book.pin_owned(1, 71).unwrap();
    assert!(book.has_foreign_pins(71));
    book.retain(1).unwrap();
    assert_eq!(book.retire(1), Some(false));
    assert_eq!(book.retire(1), Some(false));
    assert_eq!(book.pin_owned(1, 71).err(), Some(PinError::Retired));
    assert!(!book.release(foreign));
    assert!(!book.has_foreign_pins(71));
    assert!(!book.release(own_again));
    assert!(book.release(own));
    assert!(!book.has_foreign_pins(71));
    let unknown = book.pin(1).unwrap();
    assert!(book.has_foreign_pins(71));
    assert!(book.has_foreign_pins(0));
    assert!(!book.release(unknown));
}

#[test]
fn full_pair_accounting_does_not_corrupt_existing_pins_or_prevent_existing_pair_reuse() {
    let mut book = Book::<2>::new();
    assert_eq!(book.pin_owned(0, 71).err(), Some(PinError::InvalidLabel));
    let a = book.pin_owned(1, 71).unwrap();
    let b = book.pin_owned(1, 72).unwrap();
    assert_eq!(book.pin_owned(2, 73).err(), Some(PinError::Capacity));
    let duplicate = book.pin_owned(1, 71).unwrap();
    assert_eq!(book.retire(1), Some(false));
    assert!(!book.release(a));
    assert!(!book.release(b));
    assert!(book.release(duplicate)); // exactly one final close
    let fresh = book.pin_owned(2, 73).unwrap();
    assert!(!book.has_foreign_pins(73));
    assert!(!book.release(fresh));
    assert!(Book::<0>::new().pin_owned(1, 71).is_err());
}

#[test]
fn collision_wraparound_and_group_relocation_preserve_all_outstanding_pin_keys() {
    // Dense, repeatedly filled tables exercise wraparound and backwards
    // compaction. A simple independent multiset checks actual live ownership.
    const N: usize = 17;
    let mut book = Book::<N>::new();
    let mut live: Vec<(u64, u64, Pin)> = Vec::new();
    let mut counts: BTreeMap<(u64, u64), usize> = BTreeMap::new();
    let mut seed = 19u64;
    for step in 0..12000 {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        if live.is_empty() || seed & 3 != 0 {
            let label = 1 + (seed >> 8) % N as u64;
            let owner = 1 + (seed >> 16) % 31;
            let result = book.pin_owned(label, owner);
            let expected = counts.contains_key(&(label, owner)) || counts.len() < N;
            assert_eq!(result.is_ok(), expected, "step {step}");
            if let Ok(pin) = result {
                *counts.entry((label, owner)).or_default() += 1;
                live.push((label, owner, pin));
            }
        } else {
            let index = (seed >> 32) as usize % live.len();
            let (label, owner, pin) = live.swap_remove(index);
            assert!(!book.release(pin));
            let count = counts.get_mut(&(label, owner)).unwrap();
            *count -= 1;
            if *count == 0 {
                counts.remove(&(label, owner));
            }
        }
        for owner in [1, 7, 19, 31] {
            assert_eq!(
                book.has_foreign_pins(owner),
                counts.keys().any(|(_, actual)| *actual != owner)
            );
        }
    }
    let mut pending = [0usize; N];
    for (label, _, _) in &live {
        pending[*label as usize - 1] += 1;
    }
    for label in 1..=N as u64 {
        assert_eq!(book.retire(label), Some(pending[label as usize - 1] == 0));
    }
    for (label, _, pin) in live {
        pending[label as usize - 1] -= 1;
        assert_eq!(book.release(pin), pending[label as usize - 1] == 0);
    }
    assert!(!book.has_foreign_pins(1));
    // Every bucket is reusable after repeated compaction, with no tombstones.
    let pins: Vec<_> = (1..=N as u64)
        .map(|label| book.pin_owned(label, 71).unwrap())
        .collect();
    for pin in pins {
        assert!(!book.release(pin));
    }
}

#[test]
fn snapshot_guard_is_userspace_only_and_freezes_the_book_before_owner_check() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let body = runtime
        .split("fn clone_registered_process_owned(")
        .nth(1)
        .unwrap()
        .split("let inherited_fds =")
        .next()
        .unwrap();
    assert!(
        body.find("fd_lease::BORROWS.lock()").unwrap()
            < body
                .find("has_foreign_pins(newlib_lock_identity())")
                .unwrap()
    );
    let lease = include_str!("../../../user/crates/newlib-runtime/src/fd_lease.rs");
    assert!(lease.contains("pin_owned(entry.handle.lower_handle, newlib_lock_identity())"));
    // No thread-by-Handle dense matrix: bookkeeping remains bounded by native
    // label capacity, not by label capacity times maximum pthread count.
    assert!(std::mem::size_of::<Book<{ mnu_abi::PROCESS_MAX_OBJECT_HANDLES }>>() <= 256 * 1024);
}
