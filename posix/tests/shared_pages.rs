extern crate alloc;

#[path = "../../../core/src/mem/shared_pages.rs"]
mod shared_pages;

use shared_pages::{PageError, SharedPages, SizeError};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

struct Page {
    bytes: Mutex<[u8; 4096]>,
    freed: Arc<AtomicUsize>,
}

impl Drop for Page {
    fn drop(&mut self) {
        self.freed.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn invalid_sizes_and_ranges_fail_without_allocating_storage() {
    for (length, page_size) in [(0, 4096), (1, 4096), (4096, 0), (4096, 3)] {
        assert!(matches!(
            SharedPages::<()>::new(length, page_size, 8),
            Err(SizeError::Invalid)
        ));
    }
    assert!(matches!(
        SharedPages::<()>::new(4096 * 9, 4096, 8),
        Err(SizeError::LimitExceeded)
    ));
    let mut pages = SharedPages::<()>::new(8192, 4096, 2).unwrap();
    assert_eq!(pages.length(), 8192);
    assert!(pages.contains_range(0, 8192));
    assert!(pages.contains_range(8192, 0));
    assert!(!pages.contains_range(8192, 1));
    assert!(!pages.contains_range(u64::MAX, 2));
    assert!(!pages.contains_range(u64::MAX, 0));
    assert_eq!(
        pages.page_or_try_insert(2, || -> Result<(), ()> {
            panic!("bounds before allocation")
        }),
        Err(PageError::OutOfBounds)
    );
}

#[test]
fn failed_population_can_retry_and_all_aliases_retain_the_same_owned_page() {
    let freed = Arc::new(AtomicUsize::new(0));
    let mut pages = SharedPages::new(8192, 4096, 2).unwrap();
    assert!(matches!(
        pages.page_or_try_insert(0, || -> Result<Page, u8> { Err(7) }),
        Err(PageError::Allocation(7))
    ));
    let page = pages
        .page_or_try_insert(0, || -> Result<Page, u8> {
            Ok(Page {
                bytes: Mutex::new([0; 4096]),
                freed: freed.clone(),
            })
        })
        .unwrap();
    assert!(page.bytes.lock().unwrap().iter().all(|byte| *byte == 0));
    let alias = pages
        .page_or_try_insert(0, || -> Result<Page, u8> { panic!("allocate only once") })
        .unwrap();
    assert!(Arc::ptr_eq(&page, &alias));
    page.bytes.lock().unwrap()[17] = 42;
    assert_eq!(alias.bytes.lock().unwrap()[17], 42);
    let independent = pages
        .page_or_try_insert(1, || -> Result<Page, u8> {
            Ok(Page {
                bytes: Mutex::new([0; 4096]),
                freed: freed.clone(),
            })
        })
        .unwrap();
    assert_eq!(independent.bytes.lock().unwrap()[17], 0);
    drop(pages);
    assert_eq!(freed.load(Ordering::SeqCst), 0);
    drop(page);
    assert_eq!(freed.load(Ordering::SeqCst), 0);
    drop(alias);
    assert_eq!(freed.load(Ordering::SeqCst), 1);
    drop(independent);
    assert_eq!(freed.load(Ordering::SeqCst), 2);
}

#[test]
fn concurrent_faults_allocate_one_page_when_the_object_serializes_population() {
    let object = Mutex::new(SharedPages::new(4096, 4096, 1).unwrap());
    let allocations = AtomicUsize::new(0);
    let freed = Arc::new(AtomicUsize::new(0));
    let retained = std::thread::scope(|scope| {
        let mut workers = Vec::new();
        for _ in 0..8 {
            let object = &object;
            let allocations = &allocations;
            let freed = freed.clone();
            workers.push(scope.spawn(move || {
                object
                    .lock()
                    .unwrap()
                    .page_or_try_insert(0, || -> Result<Page, ()> {
                        allocations.fetch_add(1, Ordering::SeqCst);
                        std::thread::yield_now();
                        Ok(Page {
                            bytes: Mutex::new([0; 4096]),
                            freed,
                        })
                    })
                    .unwrap()
            }));
        }
        workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(allocations.load(Ordering::SeqCst), 1);
    assert!(retained.iter().all(|page| Arc::ptr_eq(page, &retained[0])));
    drop(object);
    assert_eq!(freed.load(Ordering::SeqCst), 0);
    drop(retained);
    assert_eq!(freed.load(Ordering::SeqCst), 1);
}
