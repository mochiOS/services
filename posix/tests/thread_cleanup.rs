#[path = "../../../user/crates/newlib-runtime/src/thread_cleanup.rs"]
mod cleanup;

use std::ffi::c_void;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicUsize, Ordering};

static ORDER: std::sync::Mutex<Vec<usize>> = std::sync::Mutex::new(Vec::new());
static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
unsafe extern "C" fn record(argument: *mut c_void) {
    ORDER.lock().unwrap().push(argument as usize);
}

#[test]
fn sdk_layout_matches_and_pop_detaches_without_executing_discarded_handlers() {
    let _test = TEST_LOCK.lock().unwrap();
    ORDER.lock().unwrap().clear();
    assert_eq!(std::mem::size_of::<cleanup::Context>(), 32);
    assert_eq!(std::mem::align_of::<cleanup::Context>(), 8);
    let head = AtomicUsize::new(0);
    let mut first = MaybeUninit::<cleanup::Context>::uninit();
    let mut second = MaybeUninit::<cleanup::Context>::uninit();
    unsafe {
        cleanup::push(
            &head,
            first.as_mut_ptr(),
            Some(record),
            1usize as *mut c_void,
            0,
        );
        cleanup::push(
            &head,
            second.as_mut_ptr(),
            Some(record),
            2usize as *mut c_void,
            0,
        );
        assert_eq!(cleanup::pop(&head, first.as_mut_ptr(), true), None);
        assert_eq!(cleanup::pop(&head, second.as_mut_ptr(), true), Some(0));
        assert_eq!(head.load(Ordering::Acquire), first.as_mut_ptr() as usize);
        assert_eq!(cleanup::pop(&head, first.as_mut_ptr(), false), Some(0));
    }
    assert_eq!(*ORDER.lock().unwrap(), vec![2]);
    assert_eq!(head.load(Ordering::Acquire), 0);
}

#[test]
fn exit_drains_in_lifo_order_once_and_stacks_are_thread_owned() {
    let _test = TEST_LOCK.lock().unwrap();
    ORDER.lock().unwrap().clear();
    let first_head = AtomicUsize::new(0);
    let other_head = AtomicUsize::new(0);
    let mut first = MaybeUninit::<cleanup::Context>::uninit();
    let mut second = MaybeUninit::<cleanup::Context>::uninit();
    let mut other = MaybeUninit::<cleanup::Context>::uninit();
    unsafe {
        cleanup::push(
            &first_head,
            first.as_mut_ptr(),
            Some(record),
            1usize as *mut c_void,
            0,
        );
        cleanup::push(
            &first_head,
            second.as_mut_ptr(),
            Some(record),
            2usize as *mut c_void,
            0,
        );
        cleanup::push(
            &other_head,
            other.as_mut_ptr(),
            Some(record),
            3usize as *mut c_void,
            0,
        );
        cleanup::drain(&first_head);
        cleanup::drain(&first_head);
        assert_eq!(*ORDER.lock().unwrap(), vec![2, 1]);
        assert_ne!(other_head.load(Ordering::Acquire), 0);
        cleanup::drain(&other_head);
    }
    assert_eq!(*ORDER.lock().unwrap(), vec![2, 1, 3]);
}

#[test]
fn runtime_drains_before_tls_destructors_and_resets_on_slot_reuse() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let finish = runtime
        .split("fn finish_thread(")
        .nth(1)
        .unwrap()
        .split("fn native_thread_retired(")
        .next()
        .unwrap();
    assert!(
        finish.find("PTHREAD_CANCEL_DISABLE").unwrap()
            < finish.find("thread_cleanup::drain").unwrap()
    );
    assert!(
        finish.find("thread_cleanup::drain").unwrap()
            < finish.find("run_thread_specific_destructors").unwrap()
    );
    let reserve = runtime
        .split("fn reserve_thread_control(")
        .nth(1)
        .unwrap()
        .split("fn release_thread_control(")
        .next()
        .unwrap();
    assert!(reserve.contains("control.cleanup_head.store(0"));
    let release = runtime
        .split("fn release_thread_control(")
        .nth(1)
        .unwrap()
        .split("fn allocate_thread_reent(")
        .next()
        .unwrap();
    assert!(release.contains("control.cleanup_head.store(0"));
    let header = include_str!("../../../libraries/newlib/newlib/libc/include/pthread.h");
    assert!(header.contains("struct _pthread_cleanup_context *_previous"));
}
