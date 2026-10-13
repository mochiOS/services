extern crate alloc;
use std::sync::{Mutex, OnceLock};
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
#[macro_export]
macro_rules! warn { ($($args:tt)*) => { let _ = format_args!($($args)*); }; }
mod task {
    pub struct Object(pub u64);
    impl Object {
        pub fn memory_identity(&self) -> Option<u64> {
            Some(self.0)
        }
    }
    pub struct MemoryRegion {
        pub object: Option<Object>,
        pub start: u64,
        pub length: u64,
        pub offset: u64,
    }
    impl MemoryRegion {
        pub fn backing(&self) -> &Self {
            self
        }
        pub fn file_object(&self) -> Option<&Object> {
            self.object.as_ref()
        }
        pub fn start(&self) -> u64 {
            self.start
        }
        pub fn len(&self) -> u64 {
            self.length
        }
        pub fn file_offset(&self) -> u64 {
            self.offset
        }
    }
}
fn destroyed() -> &'static Mutex<Vec<u64>> {
    static STATE: OnceLock<Mutex<Vec<u64>>> = OnceLock::new();
    STATE.get_or_init(Default::default)
}
mod paging {
    pub fn destroy_user_page_table(table: u64) -> Result<(), ()> {
        let mut destroyed = super::destroyed().lock().unwrap();
        assert!(!destroyed.contains(&table), "double page-table destruction");
        destroyed.push(table);
        Ok(())
    }
}
#[path = "../../../core/src/mem/detached_roots.rs"]
mod detached_roots;

#[test]
fn weak_discovery_pins_physical_ownership_until_revocation_and_hands_off_at_publication() {
    use detached_roots::{snapshot, Root};
    let region = task::MemoryRegion {
        object: Some(task::Object(7)),
        start: 0x5000,
        length: 4096,
        offset: 8192,
    };
    let root = Root::new(0x1000, &[region]).unwrap();
    let mapping = &root.mappings()[0];
    assert_eq!(
        (
            mapping.identity,
            mapping.start,
            mapping.length,
            mapping.offset
        ),
        (7, 0x5000, 4096, 8192)
    );
    let alias = root.clone();
    let pins = snapshot().unwrap();
    assert_eq!(pins.len(), 1);
    drop(root);
    drop(alias);
    assert!(destroyed().lock().unwrap().is_empty());
    drop(pins);
    assert_eq!(&*destroyed().lock().unwrap(), &[0x1000]);
    assert!(snapshot().unwrap().is_empty());

    let image = Root::new(0x2000, &[]).unwrap();
    // Taking an image from its Handle and installing it into an unpublished
    // process transfers an owning reference without a gap in discovery.
    let staged_process = image.clone();
    drop(image);
    assert_eq!(snapshot().unwrap().len(), 1);
    staged_process.publish();
    assert!(snapshot().unwrap().is_empty());
    drop(staged_process);
    assert_eq!(&*destroyed().lock().unwrap(), &[0x1000]);
    // The published process/creation-failure guard now owns raw-table cleanup.
    paging::destroy_user_page_table(0x2000).unwrap();
    assert_eq!(&*destroyed().lock().unwrap(), &[0x1000, 0x2000]);
}
