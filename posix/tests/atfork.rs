use mochios_posix_client::atfork::{Handlers, Registry};
use std::cell::RefCell;

thread_local! { static EVENTS: RefCell<Vec<char>> = const { RefCell::new(Vec::new()) }; }
unsafe extern "C" fn prepare_a() {
    EVENTS.with(|events| events.borrow_mut().push('a'));
}
unsafe extern "C" fn prepare_b() {
    EVENTS.with(|events| events.borrow_mut().push('b'));
}
unsafe extern "C" fn parent_a() {
    EVENTS.with(|events| events.borrow_mut().push('A'));
}
unsafe extern "C" fn parent_b() {
    EVENTS.with(|events| events.borrow_mut().push('B'));
}
unsafe extern "C" fn child_a() {
    EVENTS.with(|events| events.borrow_mut().push('x'));
}
unsafe extern "C" fn child_b() {
    EVENTS.with(|events| events.borrow_mut().push('y'));
}

fn first() -> Handlers {
    Handlers {
        prepare: Some(prepare_a),
        parent: Some(parent_a),
        child: Some(child_a),
    }
}
fn second() -> Handlers {
    Handlers {
        prepare: Some(prepare_b),
        parent: Some(parent_b),
        child: Some(child_b),
    }
}
fn register(registry: &mut Registry, handlers: Handlers) {
    // Registrations intentionally live until the test process exits.
    unsafe { registry.register(handlers, |layout| std::alloc::alloc(layout)) }.unwrap();
}
fn events() -> String {
    EVENTS.with(|events| events.borrow_mut().drain(..).collect())
}

#[test]
fn captured_prefix_has_reverse_prepare_forward_parent_and_child_order() {
    let mut registry = Registry::new();
    let empty = registry.snapshot();
    unsafe {
        empty.prepare();
        empty.parent();
        empty.child();
    }
    assert_eq!(events(), "");
    register(&mut registry, first());
    register(&mut registry, Handlers::default());
    // Storage can be obtained before taking the registry's external mutex.
    let layout = Registry::registration_layout();
    let allocation = unsafe { std::alloc::alloc(layout) };
    unsafe {
        registry.register(second(), |requested| {
            assert_eq!(requested, layout);
            allocation
        })
    }
    .unwrap();
    let snapshot = registry.snapshot();
    unsafe {
        snapshot.prepare();
        snapshot.parent();
        snapshot.child();
    }
    assert_eq!(events(), "baABxy");
}

#[test]
fn failed_registration_and_later_append_do_not_change_an_existing_snapshot() {
    let mut registry = Registry::new();
    register(&mut registry, first());
    let snapshot = registry.snapshot();
    assert!(unsafe { registry.register(second(), |_| std::ptr::null_mut()) }.is_err());
    unsafe {
        registry.snapshot().prepare();
    }
    assert_eq!(events(), "a");
    register(&mut registry, second());
    unsafe {
        snapshot.prepare();
        snapshot.parent();
        snapshot.child();
    }
    assert_eq!(events(), "aAx");
    unsafe {
        registry.snapshot().prepare();
        registry.snapshot().parent();
    }
    assert_eq!(events(), "baAB");
}

#[test]
fn snapshot_dispatch_remains_valid_while_another_thread_appends() {
    let mut registry = Registry::new();
    register(&mut registry, first());
    let snapshot = registry.snapshot();
    let registry = std::sync::Arc::new(std::sync::Mutex::new(registry));
    let writer = registry.clone();
    let thread = std::thread::spawn(move || {
        for _ in 0..1024 {
            register(&mut writer.lock().unwrap(), second());
        }
    });
    for _ in 0..1024 {
        unsafe {
            snapshot.prepare();
            snapshot.parent();
            snapshot.child();
        }
    }
    thread.join().unwrap();
    assert_eq!(events(), "aAx".repeat(1024));
}
