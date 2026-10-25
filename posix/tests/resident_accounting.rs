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
