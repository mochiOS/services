extern crate alloc;

#[path = "../../../core/src/mem/byte_extent.rs"]
mod byte_extent;

#[path = "../../../core/src/mem/shared_pages.rs"]
mod shared_pages;

use shared_pages::{PageError, ResizeError, SharedPages, SizeError};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

#[test]
fn byte_resize_prepares_then_revokes_then_zeros_without_replacing_prefix() {
    let mut pages = SharedPages::new_resizable(8192, 4096, 2).unwrap();
    let low = pages
        .page_or_try_insert(0, || Ok::<_, u8>(Mutex::new([7u8; 4096])))
        .unwrap();
    let high = pages
        .page_or_try_insert(1, || Ok::<_, u8>(Mutex::new([9u8; 4096])))
        .unwrap();
    let events = std::cell::RefCell::new(Vec::new());
    pages
        .resize_bytes_with(
            5000,
            |_, range| {
                events.borrow_mut().push("prepare");
                assert_eq!(range, 904..4096);
                Ok::<_, u8>(range)
            },
            |start, end| {
                events.borrow_mut().push("revoke");
                assert_eq!((start, end), (4096, 8192));
                assert_eq!(high.lock().unwrap()[904], 9);
                Ok(())
            },
            |page, range| {
                events.borrow_mut().push("zero");
                page.lock().unwrap()[range.start as usize..range.end as usize].fill(0);
            },
        )
        .unwrap();
    assert_eq!(*events.borrow(), ["prepare", "revoke", "zero"]);
    assert_eq!(pages.length(), 5000);
    assert!(!pages.contains_range(5000, 1));
    assert_eq!(low.lock().unwrap()[4095], 7);
    assert_eq!(high.lock().unwrap()[903], 9);
    assert_eq!(high.lock().unwrap()[904], 0);
    high.lock().unwrap()[1000] = 42; // A mapped write into padding.
    pages
        .resize_bytes_with(
            6000,
            |_, range| Ok::<_, u8>(range),
            |_, _| Ok(()),
            |page, range| page.lock().unwrap()[range.start as usize..range.end as usize].fill(0),
        )
        .unwrap();
    assert_eq!(high.lock().unwrap()[1000], 0);
    assert!(Arc::ptr_eq(
        &high,
        &pages
            .page_or_try_insert(1, || -> Result<_, u8> { panic!("retain boundary") })
            .unwrap()
    ));
    assert_eq!(
        pages
            .page_or_try_insert(2, || Ok::<_, u8>(Mutex::new([0; 4096])))
            .unwrap_err(),
        PageError::OutOfBounds
    );
}

#[test]
fn byte_resize_failures_leave_size_and_bytes_unchanged() {
    let mut pages = SharedPages::new_resizable(4096, 4096, 1).unwrap();
    let page = pages
        .page_or_try_insert(0, || Ok::<_, u8>(Mutex::new([8u8; 4096])))
        .unwrap();
    assert_eq!(
        pages.resize_bytes_with(
            1,
            |_, _| Err::<(), _>(3u8),
            |_, _| -> Result<(), u8> { panic!("no revoke") },
            |_, _| panic!("no zero")
        ),
        Err(ResizeError::Preparation(3))
    );
    assert_eq!(
        pages.resize_bytes_with(1, |_, _| Ok(()), |_, _| Err(5u8), |_, _| panic!("no zero")),
        Err(ResizeError::Revocation(5))
    );
    assert_eq!(pages.length(), 4096);
    assert!(page.lock().unwrap().iter().all(|b| *b == 8));
    let mut absent = SharedPages::<()>::new_resizable(4096, 4096, 1).unwrap();
    absent
        .resize_bytes_with(
            1,
            |_, _| -> Result<(), u8> { panic!("no allocated boundary") },
            |_, _| Ok(()),
            |_, _| panic!("no zero"),
        )
        .unwrap();
    assert_eq!(absent.length(), 1);
    assert_eq!(
        absent.resize_with(4096, |_, _| Ok::<_, u8>(())),
        Err(ResizeError::Size(SizeError::Invalid))
    );
}

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

#[test]
fn resizable_empty_backing_grows_lazily_and_preserves_retained_page_identity() {
    let mut pages = SharedPages::<u64>::new_resizable(0, 4096, 2).unwrap();
    assert_eq!(pages.length(), 0);
    assert!(pages.contains_range(0, 0));
    assert!(!pages.contains_range(0, 1));
    assert_eq!(
        pages.page_or_try_insert(0, || Ok::<_, ()>(7)),
        Err(PageError::OutOfBounds)
    );
    pages
        .resize_with(4096, |_, _| -> Result<(), ()> {
            panic!("growth never revokes")
        })
        .unwrap();
    let page = pages.page_or_try_insert(0, || Ok::<_, ()>(7)).unwrap();
    pages
        .resize_with(8192, |_, _| -> Result<(), ()> {
            panic!("growth never revokes")
        })
        .unwrap();
    let alias = pages
        .page_or_try_insert(0, || -> Result<u64, ()> {
            panic!("do not replace live page")
        })
        .unwrap();
    assert!(Arc::ptr_eq(&page, &alias));
    assert_eq!(*pages.page_or_try_insert(1, || Ok::<_, ()>(0)).unwrap(), 0);
}

#[test]
fn invalid_growth_and_failed_revocation_leave_size_and_population_unchanged() {
    let mut pages = SharedPages::<u64>::new_resizable(8192, 4096, 2).unwrap();
    let page = pages.page_or_try_insert(1, || Ok::<_, ()>(42)).unwrap();
    for (size, error) in [(1, SizeError::Invalid), (12288, SizeError::LimitExceeded)] {
        assert_eq!(
            pages.resize_with(size, |_, _| -> Result<(), u8> {
                panic!("validate before revocation")
            }),
            Err(ResizeError::Size(error))
        );
        assert_eq!(pages.length(), 8192);
    }
    assert_eq!(
        pages.resize_with(4096, |start, end| {
            assert_eq!((start, end), (4096, 8192));
            Err(5u8)
        }),
        Err(ResizeError::Revocation(5))
    );
    assert_eq!(pages.length(), 8192);
    assert!(Arc::ptr_eq(
        &page,
        &pages
            .page_or_try_insert(1, || -> Result<u64, ()> {
                panic!("failed shrink preserves backing")
            })
            .unwrap()
    ));
}

#[test]
fn shrink_revokes_before_release_and_regrowth_does_not_resurrect_old_storage() {
    let freed = Arc::new(AtomicUsize::new(0));
    let mut pages = SharedPages::new_resizable(8192, 4096, 2).unwrap();
    let low = pages
        .page_or_try_insert(0, || {
            Ok::<_, ()>(Page {
                bytes: Mutex::new([1; 4096]),
                freed: freed.clone(),
            })
        })
        .unwrap();
    let high = pages
        .page_or_try_insert(1, || {
            Ok::<_, ()>(Page {
                bytes: Mutex::new([2; 4096]),
                freed: freed.clone(),
            })
        })
        .unwrap();
    drop(high);
    pages
        .resize_with(4096, |start, end| -> Result<(), ()> {
            assert_eq!((start, end), (4096, 8192));
            assert_eq!(freed.load(Ordering::SeqCst), 0);
            Ok(())
        })
        .unwrap();
    assert_eq!(freed.load(Ordering::SeqCst), 1);
    assert!(Arc::ptr_eq(
        &low,
        &pages
            .page_or_try_insert(0, || -> Result<Page, ()> {
                panic!("shrink keeps lower pages")
            })
            .unwrap()
    ));
    pages
        .resize_with(0, |start, end| -> Result<(), ()> {
            assert_eq!((start, end), (0, 4096));
            Ok(())
        })
        .unwrap();
    assert_eq!(freed.load(Ordering::SeqCst), 1); // Retained caller reference.
    pages
        .resize_with(4096, |_, _| -> Result<(), ()> { panic!("growth") })
        .unwrap();
    let fresh = pages
        .page_or_try_insert(0, || {
            Ok::<_, ()>(Page {
                bytes: Mutex::new([0; 4096]),
                freed: freed.clone(),
            })
        })
        .unwrap();
    assert!(!Arc::ptr_eq(&low, &fresh));
    assert!(fresh.bytes.lock().unwrap().iter().all(|byte| *byte == 0));
    drop(low);
    drop(fresh);
    drop(pages);
    assert_eq!(freed.load(Ordering::SeqCst), 3);
}
