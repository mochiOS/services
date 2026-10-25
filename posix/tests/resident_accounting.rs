#![feature(allocator_api)]
#![allow(dead_code)]
extern crate alloc;
#[path = "../../../core/src/mem/cow_access.rs"]
mod cow_access;
#[path = "../../../core/src/mem/residency_native.rs"]
mod native;
#[path = "../../../core/src/mem/residency.rs"]
mod residency;

mod interrupt {
    pub mod spinlock {
        pub struct SpinLock<T>(std::sync::Mutex<T>);
        impl<T> SpinLock<T> {
            pub const fn new(value: T) -> Self {
                Self(std::sync::Mutex::new(value))
            }
            pub fn lock(&self) -> std::sync::MutexGuard<'_, T> {
                self.0.lock().unwrap()
            }
        }
    }
}

const RAM: u64 = residency::RAM_LEAF | 4;

#[test]
fn process_observers_have_independent_peaks_and_follow_only_their_current_root() {
    let first = 0x300000;
    let second = 0x400000;
    native::register(first).unwrap();
    native::register(second).unwrap();
    for _ in 0..3 {
        native::transition(first, 0, RAM);
    }
    for _ in 0..2 {
        native::transition(first, RAM, 0);
    }
    let owner = native::ProcessStats::new();
    assert_eq!(owner.snapshot(), None);
    owner.bind_root(first);
    // A process joining a shared root starts with its current footprint, not
    // a peak produced before that process was associated with the root.
    assert_eq!(
        owner.snapshot().unwrap(),
        residency::Snapshot {
            current_bytes: 4096,
            peak_bytes: 4096
        }
    );
    native::transition(first, 0, RAM);
    let sharing = native::ProcessStats::new();
    sharing.bind_root(first);
    owner.bind_root(second);
    native::transition(first, 0, RAM);
    assert_eq!(
        owner.snapshot().unwrap(),
        residency::Snapshot {
            current_bytes: 0,
            peak_bytes: 8192
        }
    );
    assert_eq!(sharing.snapshot().unwrap().peak_bytes, 12288);
    native::transition(second, 0, RAM);
    assert_eq!(
        owner.snapshot().unwrap(),
        residency::Snapshot {
            current_bytes: 4096,
            peak_bytes: 8192
        }
    );
    native::retire(first);
    native::retire(second);
    assert_eq!(
        owner.snapshot().unwrap(),
        residency::Snapshot {
            current_bytes: 0,
            peak_bytes: 8192
        }
    );
    assert_eq!(
        sharing.snapshot().unwrap(),
        residency::Snapshot {
            current_bytes: 0,
            peak_bytes: 12288
        }
    );
    native::register(first).unwrap();
    native::transition(first, 0, RAM);
    assert_eq!(sharing.snapshot().unwrap().current_bytes, 0);
    native::retire(first);
}

#[test]
fn process_observation_remains_unavailable_after_missing_roots_or_invalid_counts() {
    let missing = native::ProcessStats::new();
    missing.bind_root(0);
    assert_eq!(missing.snapshot(), None);
    let root = 0x500000;
    native::register(root).unwrap();
    let owner = native::ProcessStats::new();
    owner.bind_root(root);
    native::transition(root, RAM, 0);
    assert_eq!(owner.snapshot(), None);
    native::retire(root);
    assert_eq!(owner.snapshot(), None);
}

#[test]
fn ended_process_detaches_from_a_root_retained_by_independent_owners() {
    let root = 0x600000;
    native::register(root).unwrap();
    let ended = native::ProcessStats::new();
    let live = native::ProcessStats::new();
    ended.bind_root(root);
    live.bind_root(root);
    native::transition(root, 0, RAM);
    ended.detach();
    assert_eq!(
        ended.snapshot().unwrap(),
        residency::Snapshot {
            current_bytes: 0,
            peak_bytes: 4096
        }
    );
    native::transition(root, 0, RAM);
    assert_eq!(ended.snapshot().unwrap().peak_bytes, 4096);
    assert_eq!(
        live.snapshot().unwrap(),
        residency::Snapshot {
            current_bytes: 8192,
            peak_bytes: 8192
        }
    );
    native::retire(root);
    assert_eq!(ended.snapshot().unwrap().peak_bytes, 4096);
    let unbound = native::ProcessStats::new();
    unbound.detach();
    assert_eq!(unbound.snapshot(), None);
}

#[test]
fn counters_match_independent_leaf_membership_across_access_changes_replacement_and_unmap() {
    assert_eq!(
        residency::RAM_LEAF & (cow_access::COPY_ON_WRITE | cow_access::WRITE_DISABLED),
        0
    );
    let mut counter = residency::Counter::new();
    let mut flags = [0u64; 64];
    let mut peak = 0;
    let mut random = 17u64;
    for step in 0..10000 {
        random = random.wrapping_mul(6364136223846793005).wrapping_add(1);
        let index = ((random >> 32) % 64) as usize;
        let after = [
            0,
            5,
            RAM,
            RAM | 1,
            RAM | 1 | cow_access::COPY_ON_WRITE,
            RAM | (1 << 63),
        ][step % 6];
        counter.transition(flags[index], after);
        flags[index] = after;
        let current = flags.iter().filter(|flags| **flags & RAM == RAM).count() as u64 * 4096;
        peak = peak.max(current);
        assert_eq!(
            counter.snapshot(),
            Some(residency::Snapshot {
                current_bytes: current,
                peak_bytes: peak
            })
        );
    }
    counter.retire();
    assert_eq!(
        counter.snapshot().unwrap(),
        residency::Snapshot {
            current_bytes: 0,
            peak_bytes: peak
        }
    );
}

#[test]
fn inconsistent_decrement_invalidates_metrics_instead_of_wrapping_or_faking_zero() {
    let mut counter = residency::Counter::new();
    counter.transition(RAM, 0);
    assert_eq!(counter.snapshot(), None);
    counter.transition(0, RAM);
    counter.retire();
    assert_eq!(counter.snapshot(), None);
}

#[test]
fn retained_statistics_do_not_own_tables_or_alias_reused_root_generations() {
    let root = 0x100000;
    for invalid in [0, 1, root + 1] {
        assert!(native::register(invalid).is_err());
    }
    assert!(native::get(root).is_none());
    native::register(root).unwrap();
    assert!(native::register(root).is_err());
    let old = native::get(root).unwrap();
    native::transition(root, 0, RAM | 1);
    native::transition(root, RAM | 1, RAM); // No access, same allocated RAM.
    assert_eq!(old.snapshot().unwrap().current_bytes, 4096);
    native::retire(root);
    assert!(native::get(root).is_none());
    assert_eq!(
        old.snapshot().unwrap(),
        residency::Snapshot {
            current_bytes: 0,
            peak_bytes: 4096
        }
    );
    native::register(root).unwrap();
    let new = native::get(root).unwrap();
    assert!(!alloc::sync::Arc::ptr_eq(&old, &new));
    assert_eq!(new.snapshot().unwrap(), Default::default());
    native::transition(root, 0, RAM);
    native::transition(root, 0, RAM);
    assert_eq!(new.snapshot().unwrap().peak_bytes, 8192);
    assert_eq!(old.snapshot().unwrap().peak_bytes, 4096);
    native::retire(root);
}

#[test]
fn concurrent_leaf_commits_preserve_exact_current_and_peak_counts() {
    let root = 0x200000;
    native::register(root).unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(9));
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let barrier = std::sync::Arc::clone(&barrier);
            std::thread::spawn(move || {
                for _ in 0..100 {
                    native::transition(root, 0, RAM);
                }
                barrier.wait();
                barrier.wait();
                for _ in 0..100 {
                    native::transition(root, RAM, 0);
                }
            })
        })
        .collect();
    barrier.wait();
    assert_eq!(
        native::get(root).unwrap().snapshot().unwrap(),
        residency::Snapshot {
            current_bytes: 800 * 4096,
            peak_bytes: 800 * 4096
        }
    );
    barrier.wait();
    for thread in threads {
        thread.join().unwrap();
    }
    assert_eq!(
        native::get(root).unwrap().snapshot().unwrap(),
        residency::Snapshot {
            current_bytes: 0,
            peak_bytes: 800 * 4096
        }
    );
    native::retire(root);
}
