use mochios_posix_client::fd::{FdReservation, FdTable};
use mochios_posix_client::handle_borrow::{Book, Pin as HandlePin};
use std::cell::RefCell;
use std::rc::Rc;

#[path = "../../../user/crates/newlib-runtime/src/callback_resources.rs"]
mod production;
use production::{Chain, Scope};

fn wait_for_thaw(word: &std::sync::atomic::AtomicU32, expected: u32) {
    use std::sync::atomic::Ordering;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while word.load(Ordering::Acquire) == expected {
        assert!(
            std::time::Instant::now() < deadline,
            "resource capture stranded its owner"
        );
        std::thread::yield_now();
    }
}

#[test]
fn snapshot_capture_excludes_unpublished_active_and_deferred_resources() {
    let chain = Chain::new();
    let mut scope = core::pin::pin!(Scope::new(&chain, 0, ()));
    assert!(chain.is_empty());
    assert!(
        chain.capture_empty().is_none(),
        "unpublished construction is not quiescent"
    );
    assert!(!chain.reset_empty());
    unsafe {
        scope.as_mut().activate();
    }
    assert!(chain.capture_empty().is_none());
    unsafe {
        scope.as_mut().retire();
    }
    let deferred = chain.defer_callbacks().unwrap();
    assert!(chain.capture_empty().is_none());
    drop(deferred);
    let capture = chain.capture_empty().unwrap();
    assert!(chain.capture_empty().is_none());
    drop(capture);
    assert!(chain.reset_empty());
}

#[test]
fn frozen_empty_chain_parks_publication_until_native_capture_finishes() {
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::sync::{Arc, mpsc};
    static PARKED: AtomicBool = AtomicBool::new(false);
    static WAKES: AtomicU32 = AtomicU32::new(0);
    fn park(word: &AtomicU32, expected: u32) {
        PARKED.store(true, Ordering::Release);
        wait_for_thaw(word, expected);
    }
    fn wake(_: &AtomicU32) {
        WAKES.fetch_add(1, Ordering::AcqRel);
    }
    let chain = Arc::new(Chain::with_wait(park, wake));
    drop(chain.capture_empty().unwrap());
    assert_eq!(
        WAKES.load(Ordering::Acquire),
        0,
        "idle chains need no native wake syscall"
    );
    let capture = chain.capture_empty().unwrap();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (published_tx, published_rx) = mpsc::channel();
    let worker_chain = chain.clone();
    let worker = std::thread::spawn(move || {
        entered_tx.send(()).unwrap();
        let mut scope = core::pin::pin!(Scope::new(&worker_chain, 0, ()));
        unsafe {
            scope.as_mut().activate();
        }
        published_tx.send(()).unwrap();
        unsafe {
            scope.as_mut().retire();
        }
    });
    entered_rx.recv().unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !PARKED.load(Ordering::Acquire) {
        assert!(std::time::Instant::now() < deadline);
        std::thread::yield_now();
    }
    assert!(chain.is_empty());
    assert!(published_rx.try_recv().is_err());
    drop(capture);
    assert_eq!(WAKES.load(Ordering::Acquire), 1);
    published_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    worker.join().unwrap();
    assert!(chain.capture_empty().is_some());
}

#[test]
fn unlinking_the_last_scope_does_not_expose_a_partial_resource_destructor_to_fork() {
    use std::sync::{Arc, mpsc};
    struct Retiring {
        entered: mpsc::Sender<()>,
        finish: mpsc::Receiver<()>,
    }
    impl Drop for Retiring {
        fn drop(&mut self) {
            self.entered.send(()).unwrap();
            self.finish
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap();
        }
    }
    for abandon in [false, true] {
        let chain = Arc::new(Chain::with_wait(wait_for_thaw, |_| {}));
        let (entered_tx, entered_rx) = mpsc::channel();
        let (finish_tx, finish_rx) = mpsc::channel();
        let worker_chain = chain.clone();
        let worker = std::thread::spawn(move || {
            let mut scope = core::pin::pin!(Scope::new(
                &worker_chain,
                0,
                Retiring {
                    entered: entered_tx,
                    finish: finish_rx
                }
            ));
            unsafe {
                scope.as_mut().activate();
            }
            unsafe {
                if abandon {
                    worker_chain.abandon_from(0);
                } else {
                    scope.as_mut().retire();
                }
            }
        });
        entered_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        assert!(chain.is_empty());
        assert!(
            chain.capture_empty().is_none(),
            "empty head still has an in-flight destructor"
        );
        finish_tx.send(()).unwrap();
        worker.join().unwrap();
        assert!(chain.capture_empty().is_some());
    }
}

struct Tracked {
    name: u32,
    dropped: Rc<RefCell<Vec<u32>>>,
}
impl Drop for Tracked {
    fn drop(&mut self) {
        self.dropped.borrow_mut().push(self.name);
    }
}
fn tracked(name: u32, dropped: &Rc<RefCell<Vec<u32>>>) -> Tracked {
    Tracked {
        name,
        dropped: dropped.clone(),
    }
}

#[test]
fn unpublished_construction_and_normal_retirement_release_once() {
    let chain = Chain::new();
    let drops = Rc::new(RefCell::new(vec![]));
    drop(Scope::new(&chain, 0, tracked(1, &drops)));
    assert!(chain.is_empty());
    {
        let mut scope = core::pin::pin!(Scope::new(&chain, 0, tracked(2, &drops)));
        unsafe {
            scope.as_mut().activate();
        }
        assert!(!chain.is_empty());
        assert_eq!(scope.as_ref().get_ref().resource().unwrap().name, 2);
        scope.as_mut().resource_mut().unwrap().name = 3;
        unsafe {
            scope.as_mut().retire();
        }
        assert!(chain.is_empty());
        assert_eq!(*drops.borrow(), [1, 3]);
    }
    assert_eq!(*drops.borrow(), [1, 3]);
}

#[test]
fn nested_escape_preserves_the_waiting_parent_and_retires_selected_contexts_lifo() {
    let chain = Chain::new();
    let drops = Rc::new(RefCell::new(vec![]));
    let mut parent = core::pin::pin!(Scope::new(&chain, 0, tracked(0, &drops)));
    let mut handler_operation = core::pin::pin!(Scope::new(&chain, 7, tracked(7, &drops)));
    let mut nested_operation = core::pin::pin!(Scope::new(&chain, 9, tracked(9, &drops)));
    unsafe {
        parent.as_mut().activate();
        handler_operation.as_mut().activate();
        nested_operation.as_mut().activate();
        // Jump back into callback 7: its interrupted operation and callback 9
        // are abandoned, but the operation that callback 7 interrupted lives.
        chain.abandon_from(7);
    }
    // Do not resume or access the abandoned operations' resource values.
    assert_eq!(*drops.borrow(), [9, 7]);
    assert!(!chain.is_empty());
    assert_eq!(parent.as_ref().get_ref().resource().unwrap().name, 0);
    unsafe {
        parent.as_mut().retire();
    }
    assert!(chain.is_empty());
    assert_eq!(*drops.borrow(), [9, 7, 0]);
}

#[test]
fn a_local_handler_jump_does_not_consume_its_parents_operation() {
    let chain = Chain::new();
    let drops = Rc::new(RefCell::new(vec![]));
    let mut parent = core::pin::pin!(Scope::new(&chain, 0, tracked(0, &drops)));
    unsafe {
        parent.as_mut().activate();
        chain.abandon_from(7);
    }
    assert!(drops.borrow().is_empty());
    assert!(!chain.is_empty());
    unsafe {
        parent.as_mut().retire();
    }
    assert_eq!(*drops.borrow(), [0]);
}

#[test]
fn repeated_empty_cleanup_and_origin_escape_cannot_double_drop() {
    let chain = Chain::new();
    let drops = Rc::new(RefCell::new(vec![]));
    {
        let mut scope = core::pin::pin!(Scope::new(&chain, 0, tracked(1, &drops)));
        unsafe {
            chain.abandon_from(0);
            scope.as_mut().activate();
            chain.abandon_from(0);
            chain.abandon_from(0);
        }
        assert!(chain.is_empty());
        assert_eq!(*drops.borrow(), [1]);
        // The disarmed Rust shell can be destroyed without another release.
    }
    assert_eq!(*drops.borrow(), [1]);
}

#[test]
fn nonlocal_escape_releases_the_last_retired_fd_pin_before_label_reuse() {
    struct Lease {
        book: Rc<RefCell<Book<4>>>,
        pin: Option<HandlePin>,
        closes: Rc<RefCell<usize>>,
    }
    impl Drop for Lease {
        fn drop(&mut self) {
            if self.book.borrow_mut().release(self.pin.take().unwrap()) {
                *self.closes.borrow_mut() += 1;
            }
        }
    }
    let chain = Chain::new();
    let book = Rc::new(RefCell::new(Book::new()));
    let closes = Rc::new(RefCell::new(0));
    {
        let pin = book.borrow_mut().pin(1).unwrap();
        let mut scope = core::pin::pin!(Scope::new(
            &chain,
            0,
            Lease {
                book: book.clone(),
                pin: Some(pin),
                closes: closes.clone()
            }
        ));
        unsafe {
            scope.as_mut().activate();
        }
        assert_eq!(book.borrow_mut().retire(1), Some(false));
        unsafe {
            chain.abandon_from(0);
        }
        assert_eq!(*closes.borrow(), 1);
        let reused = book.borrow_mut().pin(1).unwrap();
        assert!(!book.borrow_mut().release(reused));
    }
    assert_eq!(*closes.borrow(), 1);
    assert!(chain.is_empty());
}

#[test]
fn abandoned_open_reservation_is_reusable_without_cancelling_a_new_generation() {
    struct Pending {
        table: Rc<RefCell<FdTable<u32>>>,
        reservation: FdReservation,
    }
    impl Drop for Pending {
        fn drop(&mut self) {
            assert!(
                self.table
                    .borrow_mut()
                    .cancel_reservation(&self.reservation)
            );
        }
    }
    let chain = Chain::new();
    let table = Rc::new(RefCell::new(FdTable::new()));
    let next;
    {
        let reservation = table.borrow_mut().reserve_from(0, 1).unwrap();
        let mut scope = core::pin::pin!(Scope::new(
            &chain,
            0,
            Pending {
                table: table.clone(),
                reservation
            }
        ));
        unsafe {
            scope.as_mut().activate();
        }
        assert!(table.borrow_mut().reserve_from(0, 1).is_err());
        unsafe {
            chain.abandon_from(0);
        }
        next = table.borrow_mut().reserve_from(0, 1).unwrap();
    }
    assert!(table.borrow_mut().reserve_from(0, 1).is_err());
    assert!(table.borrow_mut().cancel_reservation(&next));
}

#[test]
fn jump_cleanup_follows_destination_validation_and_thread_exit_precedes_user_cleanup() {
    let jump = include_str!("../../../user/crates/newlib-runtime/src/signal_jump.rs");
    let preparation = jump
        .split("unsafe fn prepare_jump(")
        .nth(1)
        .unwrap()
        .split("#[unsafe(no_mangle)]")
        .next()
        .unwrap();
    assert!(
        preparation.find("signal_scope::unwind_to").unwrap()
            < preparation.find("callback_resources.abandon_from").unwrap()
    );
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let exit = runtime
        .split("fn finish_thread(")
        .nth(1)
        .unwrap()
        .split("// THREAD_EXITED")
        .next()
        .unwrap();
    assert!(
        exit.find("callback_resources.abandon_from(0)").unwrap()
            < exit.find("thread_cleanup::drain").unwrap()
    );
    assert!(runtime.contains("if !control.callback_resources.reset_empty()"));
    assert!(jump.contains("size_of::<JumpBuffer>() == 120"));
}

#[test]
fn callbacks_are_deferred_without_losing_native_notifications() {
    let chain = Chain::new();
    assert!(!chain.record_notification());
    assert!(!chain.notification_pending());
    let outer = chain.defer_callbacks().unwrap();
    let inner = chain.defer_callbacks().unwrap();
    assert!(chain.record_notification());
    assert!(chain.notification_pending());
    assert!(!chain.take_notification());
    assert!(
        !chain.reset_empty(),
        "cannot recycle a thread with a live guard"
    );
    drop(inner);
    assert!(chain.is_deferred());
    drop(outer);
    assert!(!chain.is_deferred());
    assert!(chain.take_notification());
    assert!(!chain.take_notification());
    assert!(chain.reset_empty());
}

#[test]
fn nonreturning_cleanup_detaches_before_destruction_and_reopens_callbacks_last() {
    struct Protected<'a> {
        chain: &'a Chain,
        closed: &'a RefCell<bool>,
        _guard: mochios_posix_client::upcall_guard::Guard<'a>,
    }
    impl Drop for Protected<'_> {
        fn drop(&mut self) {
            assert!(self.chain.is_empty(), "detach before running destructors");
            assert!(
                self.chain.is_deferred(),
                "release the capability before C can run"
            );
            *self.closed.borrow_mut() = true;
        }
    }
    let chain = Chain::new();
    let closed = RefCell::new(false);
    let resource = Protected {
        chain: &chain,
        closed: &closed,
        _guard: chain.defer_callbacks().unwrap(),
    };
    let mut scope = core::pin::pin!(Scope::new(&chain, 0, resource));
    unsafe {
        scope.as_mut().activate();
    }
    assert!(chain.record_notification());
    unsafe {
        chain.abandon_from(0);
    }
    assert!(*closed.borrow());
    assert!(!chain.is_deferred());
    assert!(chain.take_notification());
    assert!(chain.reset_empty());
}

#[test]
fn runtime_notifications_do_not_dequeue_c_signals_while_the_owner_is_deferred() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let callback = source
        .split("extern \"C\" fn posix_signal_upcall(")
        .nth(1)
        .unwrap()
        .split("#[unsafe(no_mangle)]")
        .next()
        .unwrap();
    assert!(
        callback.find("record_notification()").unwrap()
            < callback.find("drain_pending_signals_with_context").unwrap()
    );
    assert!(callback.contains("notify_thread_waiter(control)"));
    let delivery = include_str!("../../../user/crates/newlib-runtime/src/signal_delivery.rs");
    let drain = delivery.split("pub(super) fn drain()").nth(1).unwrap();
    assert!(
        drain.find("callback_resources.is_deferred()").unwrap() < drain.find("run_with(").unwrap()
    );
}

#[test]
fn libc_ftruncate_tracks_the_source_and_returns_from_wait_before_dispatch() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let exported = runtime
        .split("fn _ftruncate(")
        .nth(1)
        .unwrap()
        .split("#[unsafe(no_mangle)]")
        .next()
        .unwrap();
    assert!(exported.contains("file_mutation::ftruncate("));
    assert!(!exported.contains("client.ftruncate("));
    let mutation = include_str!("../../../user/crates/newlib-runtime/src/file_mutation.rs");
    let wait = mutation
        .split("fn wait(")
        .nth(1)
        .unwrap()
        .split("fn execute")
        .next()
        .unwrap();
    assert!(wait.contains("HandleWaitManyGuarded"));
    assert!(wait.contains("notification_pending()"));
    assert!(!wait.contains("drain_pending_signals"));
    assert!(!wait.contains("ThreadYield"));
    let operation = mutation.split("pub(super) fn ftruncate(").nth(1).unwrap();
    assert!(
        operation.find("let native = delivery(control)").unwrap()
            < operation.find("source: with_fd_entry(fd)?").unwrap()
    );
    assert!(operation.find("activate()").unwrap() < operation.find("drop(native)").unwrap());
    assert!(
        operation.find("retire()").unwrap() < operation.find("drain_pending_signals()").unwrap()
    );
}

#[test]
fn libc_path_truncate_encodes_before_callbacks_reopen() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let exported = runtime
        .split("fn truncate(")
        .nth(1)
        .unwrap()
        .split("#[unsafe(no_mangle)]")
        .next()
        .unwrap();
    assert!(exported.contains("file_mutation::truncate("));
    assert!(!exported.contains("client.truncate_at("));
    let source = include_str!("../../../user/crates/newlib-runtime/src/file_mutation.rs");
    let operation = source
        .split("pub(super) fn truncate(")
        .nth(1)
        .unwrap()
        .split("struct OpenResources")
        .next()
        .unwrap();
    let snapshot = operation.find("prepare_truncate_at(").unwrap();
    assert!(operation.find("let native = delivery(control)").unwrap() < snapshot);
    assert!(snapshot < operation.find("drop(native)").unwrap());
    assert!(
        operation.find("retire()").unwrap() < operation.find("drain_pending_signals()").unwrap()
    );
    assert!(!operation.contains("c_bytes(path)"));
    assert_eq!(operation.matches("path_io::capture(path,").count(), 1);
    assert!(operation.find("path_io::capture(path,").unwrap() < snapshot);
}

#[test]
fn libc_open_owns_the_reply_until_dispatch_then_installs_without_a_callback_gap() {
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let exported = runtime
        .split("fn _open(")
        .nth(1)
        .unwrap()
        .split("#[unsafe(no_mangle)]")
        .next()
        .unwrap();
    assert!(exported.contains("file_mutation::open(path, flags, mode)"));
    assert!(!runtime.contains("fn open_posix_object("));
    let source = include_str!("../../../user/crates/newlib-runtime/src/file_mutation.rs");
    let operation = source.split("pub(super) fn open(").nth(1).unwrap();
    assert!(
        operation.find("let native = delivery(control)").unwrap()
            < operation.find("PendingFdReservation(").unwrap()
    );
    assert!(operation.find("activate()").unwrap() < operation.find("drop(native)").unwrap());
    assert!(
        operation.find("source.opened = Some(opened)").unwrap()
            < operation.find("client.fstat(opened)").unwrap()
    );
    assert!(
        operation.find("drain_pending_signals()?").unwrap()
            < operation.find("commit_reservation(").unwrap()
    );
    assert!(
        operation
            .find("completion_delivery = Some(native)")
            .unwrap()
            < operation.find("commit_reservation(").unwrap()
    );
    assert!(operation.find("source.opened = None").unwrap() < operation.find("retire()").unwrap());
    assert!(
        operation.find("retire()").unwrap() < operation.find("drop(completion_delivery)").unwrap()
    );
    assert!(source.contains("if let Some(opened) = self.opened.take()"));
    assert!(source.contains("close_object_handle(opened.handle)"));
}
