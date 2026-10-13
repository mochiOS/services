#[path = "../../../user/crates/posix-client/src/pthread_cond.rs"]
mod implementation;
use implementation::{Condition, Error};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn notifications_are_not_saved_for_future_waiters() {
    let cond = Condition::new(1);
    cond.notify(false, |_, _| panic!("no admitted waiter"))
        .unwrap();
    let before = cond.begin().unwrap();
    assert_eq!(before, 0);
    assert_eq!(cond.word().load(Ordering::Acquire), before);
    assert_eq!(cond.destroy(), Err(Error::Busy));
    cond.end(before, false, |_, _| panic!());
    cond.destroy().unwrap();
    assert_eq!(cond.begin(), Err(Error::Invalid));
    assert_eq!(cond.notify(true, |_, _| panic!()), Err(Error::Invalid));
}

#[test]
fn signal_and_broadcast_publish_the_generation_and_choose_wake_counts() {
    let cond = Condition::new(4);
    assert_eq!(cond.clock(), Ok(4));
    let first = cond.begin().unwrap();
    let second = cond.begin().unwrap();
    cond.notify(false, |word, count| {
        assert_eq!(word.load(Ordering::Acquire), 1);
        assert_eq!(count, 1);
    })
    .unwrap();
    cond.notify(true, |word, count| {
        assert_eq!(word.load(Ordering::Acquire), 2);
        assert_eq!(count, usize::MAX);
    })
    .unwrap();
    cond.end(first, false, |_, _| panic!());
    cond.end(second, false, |_, _| panic!());
    cond.destroy().unwrap();
}

#[test]
fn cancellation_hands_a_concurrent_signal_to_another_admitted_waiter() {
    let cond = Condition::new(1);
    let first = cond.begin().unwrap();
    let second = cond.begin().unwrap();
    cond.notify(false, |_, _| {}).unwrap();
    let newer = cond.begin().unwrap();
    assert_eq!(newer, 1);
    let replacements = AtomicUsize::new(0);
    cond.end(first, true, |word, count| {
        assert_eq!(word.load(Ordering::Acquire), 1);
        assert_eq!(count, usize::MAX); // A new-generation waiter cannot steal the replacement.
        replacements.fetch_add(1, Ordering::Relaxed);
    });
    assert_eq!(replacements.load(Ordering::Relaxed), 1);
    assert_eq!(cond.destroy(), Err(Error::Busy));
    cond.end(second, false, |_, _| panic!());
    cond.end(newer, false, |_, _| panic!());
    cond.destroy().unwrap();
}

#[test]
fn cancellation_without_a_signal_or_without_other_waiters_does_not_create_one() {
    let cond = Condition::new(1);
    let before = cond.begin().unwrap();
    cond.end(before, true, |_, _| panic!());
    let before = cond.begin().unwrap();
    cond.notify(false, |_, _| {}).unwrap();
    cond.end(before, true, |_, _| panic!());
    cond.destroy().unwrap();
    assert_eq!(Condition::new(99).begin(), Err(Error::Invalid));
}

#[test]
fn new_registration_cannot_steal_a_notification_in_the_wake_window() {
    let cond = Arc::new(Condition::new(1));
    let old = cond.begin().unwrap();
    let (entered, entering) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel();
    let notify = Arc::clone(&cond);
    let notifier = std::thread::spawn(move || {
        notify
            .notify(false, |_, _| {
                entered.send(()).unwrap();
                released.recv().unwrap();
            })
            .unwrap()
    });
    entering.recv().unwrap();
    let (admitted, admission) = std::sync::mpsc::channel();
    let waiter = Arc::clone(&cond);
    let started = Arc::new(AtomicUsize::new(0));
    let running = Arc::clone(&started);
    let registering = std::thread::spawn(move || {
        running.store(1, Ordering::Release);
        let before = waiter.begin().unwrap();
        admitted.send(before).unwrap();
        waiter.end(before, false, |_, _| panic!());
    });
    while started.load(Ordering::Acquire) == 0 {
        std::thread::yield_now();
    }
    for _ in 0..100 {
        std::thread::yield_now();
    }
    assert!(matches!(
        admission.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));
    release.send(()).unwrap();
    notifier.join().unwrap();
    assert_eq!(admission.recv().unwrap(), 1);
    registering.join().unwrap();
    cond.end(old, false, |_, _| panic!());
    cond.destroy().unwrap();
}

#[test]
fn runtime_completes_registration_and_reacquisition_before_the_same_cancel_decision() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/pthread_cond.rs");
    let completing = &source[source.find("let reacquired =").unwrap()
        ..source
            .find("result.err().unwrap_or(replacement_error)")
            .unwrap()];
    let reacquire = completing.find("pthread_mutex_lock(mutex)").unwrap();
    let decision = completing.find("let canceled = pending();").unwrap();
    let remove = completing.find("condition.end(before, canceled").unwrap();
    let restore = completing.find("cancel_state.store(previous").unwrap();
    let finish = completing.find("finish_thread(control,").unwrap();
    assert!(reacquire < decision && decision < remove && remove < restore && restore < finish);
    assert!(!completing.contains("pthread_testcancel();"));
}

#[test]
fn actual_libc_generator_updates_every_matching_sync_size_branch() {
    let directory = std::env::temp_dir().join(format!(
        "mochios-cond-bindings-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(directory.join(".generated")).unwrap();
    std::fs::create_dir(directory.join("out")).unwrap();
    // The generator transforms text; this fixture exercises all its required
    // anchors and duplicate size branches without a staged upstream checkout.
    let fixture = r#"
mod generic;
pub type pthread_t = c_ulong;
if #[cfg(target_os = "espidf")] {
        pub const O_CLOEXEC: c_int = 0x40000;
    } else if #[cfg(target_arch = "arm")] {
pub struct pthread_mutex_t {
pub struct pthread_mutexattr_t {
pub struct pthread_cond_t {
pub struct pthread_condattr_t {
pub struct sem_t {
pub struct pthread_rwlock_t {
pub struct pthread_rwlockattr_t {
pub const PTHREAD_MUTEX_INITIALIZER: pthread_mutex_t =
pub const PTHREAD_COND_INITIALIZER: pthread_cond_t =
pub const PTHREAD_RWLOCK_INITIALIZER: pthread_rwlock_t =
pub const __SIZEOF_PTHREAD_RWLOCK_T: usize = 56;
pub const __SIZEOF_PTHREAD_RWLOCK_T: usize = 32;
pub const __SIZEOF_PTHREAD_RWLOCKATTR_T: usize = 4;
pub const __SIZEOF_PTHREAD_RWLOCKATTR_T: usize = 12;
pub const __SIZEOF_PTHREAD_BARRIER_T: usize = 4;
pub const __SIZEOF_PTHREAD_MUTEX_T: usize = 40;
pub const __SIZEOF_PTHREAD_MUTEXATTR_T: usize = 4;
pub const __SIZEOF_PTHREAD_MUTEXATTR_T: usize = 4;
pub const __SIZEOF_PTHREAD_COND_T: usize = 48;
pub const __SIZEOF_PTHREAD_CONDATTR_T: usize = 4;
pub const __SIZEOF_PTHREAD_CONDATTR_T: usize = 4;
"#;
    std::fs::write(directory.join(".generated/upstream-newlib-mod.rs"), fixture).unwrap();
    let executable = directory.join("generator");
    let compiled = std::process::Command::new("rustc")
        .args(["--edition=2021", "../../../libraries/libc/build.rs", "-o"])
        .arg(&executable)
        .current_dir(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests"))
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let generated = std::process::Command::new(&executable)
        .env("CARGO_MANIFEST_DIR", &directory)
        .env("OUT_DIR", directory.join("out"))
        .output()
        .unwrap();
    assert!(
        generated.status.success(),
        "{}",
        String::from_utf8_lossy(&generated.stderr)
    );
    let output = std::fs::read_to_string(directory.join("out/newlib_mod.rs")).unwrap();
    for declaration in [
        "__SIZEOF_PTHREAD_MUTEXATTR_T",
        "__SIZEOF_PTHREAD_CONDATTR_T",
    ] {
        let lines: Vec<_> = output
            .lines()
            .filter(|line| line.contains(declaration))
            .collect();
        assert_eq!(lines.len(), 2);
        assert!(lines.iter().all(|line| line.contains("{ 12 } else { 4 }")));
    }
    assert!(output.contains("{ 24 } else { 48 }"));
    assert!(output.contains("{ 32 } else { 40 }"));
    assert!(output.contains("{ 4 } else { 56 }"));
    assert!(output.contains("{ 4 } else { 32 }"));
    assert!(output.contains("{ 8 } else { 4 }"));
    assert!(output.contains("{ 8 } else { 12 }"));
    assert_eq!(
        output
            .matches("#[cfg(not(target_os = \"mochios\"))]")
            .count(),
        11
    ); // Types, initializers, pthread_t.
    std::fs::remove_dir_all(directory).unwrap();
}
