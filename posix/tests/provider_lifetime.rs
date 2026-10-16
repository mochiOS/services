extern crate alloc;
use std::collections::BTreeMap;
use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpcEndpoint {
    thread_id: u64,
    slot: u16,
    generation: u64,
}
static LIVE: Mutex<BTreeMap<u64, IpcEndpoint>> = Mutex::new(BTreeMap::new());
static SLOTS: Mutex<BTreeMap<u64, usize>> = Mutex::new(BTreeMap::new());
static WOKEN: Mutex<Vec<u64>> = Mutex::new(Vec::new());
static LOCKED: AtomicUsize = AtomicUsize::new(0);
thread_local! { static HELD: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }
fn endpoint_is_valid(endpoint: IpcEndpoint) -> bool {
    LIVE.lock().unwrap().get(&endpoint.thread_id) == Some(&endpoint)
}
mod interrupt {
    pub mod spinlock {
        pub struct SpinLock<T>(std::sync::Mutex<T>);
        impl<T> SpinLock<T> {
            pub const fn new(value: T) -> Self {
                Self(std::sync::Mutex::new(value))
            }
            pub fn lock(&self) -> Guard<'_, T> {
                let guard = self.0.lock().unwrap();
                crate::LOCKED.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                crate::HELD.with(|held| held.set(held.get() + 1));
                Guard(guard)
            }
        }
        pub struct Guard<'a, T>(std::sync::MutexGuard<'a, T>);
        impl<T> std::ops::Deref for Guard<'_, T> {
            type Target = T;
            fn deref(&self) -> &T {
                &self.0
            }
        }
        impl<T> std::ops::DerefMut for Guard<'_, T> {
            fn deref_mut(&mut self) -> &mut T {
                &mut self.0
            }
        }
        impl<T> Drop for Guard<'_, T> {
            fn drop(&mut self) {
                crate::LOCKED.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                crate::HELD.with(|held| held.set(held.get() - 1));
            }
        }
    }
}
mod task {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct ThreadId(pub u64);
    impl ThreadId {
        pub fn as_u64(self) -> u64 {
            self.0
        }
    }
    pub struct ThreadQueue;
    impl ThreadQueue {
        pub const MAX_THREADS: usize = 64;
    }
    pub fn thread_slot_index_by_u64(id: u64) -> Option<usize> {
        crate::SLOTS.lock().unwrap().get(&id).copied()
    }
    pub fn wake_registered_waiter(id: ThreadId) {
        // Retirement must drop its registry guard before calling scheduling.
        crate::HELD.with(|held| assert_eq!(held.get(), 0));
        crate::WOKEN.lock().unwrap().push(id.0);
    }
}
#[path = "../../../core/src/syscall/ipc/lifetime.rs"]
mod lifetime;

fn endpoint(id: u64, generation: u64) -> IpcEndpoint {
    IpcEndpoint {
        thread_id: id,
        slot: id as u16 % 64,
        generation,
    }
}
fn publish(endpoint: IpcEndpoint) {
    LIVE.lock().unwrap().insert(endpoint.thread_id, endpoint);
}
fn retire(endpoint: IpcEndpoint) {
    LIVE.lock().unwrap().remove(&endpoint.thread_id);
    lifetime::retire(endpoint);
}

#[test]
fn production_subscriptions_close_retirement_races_and_preserve_generation_identity() {
    use lifetime::{observe, remove_waiter};
    use mnu_abi::status::Error;
    use task::ThreadId;
    let owner = endpoint(10, 1);
    let unrelated = endpoint(11, 1);
    publish(owner);
    publish(unrelated);
    SLOTS.lock().unwrap().extend([(1, 0), (2, 1)]);
    assert!(
        matches!(observe(owner, ThreadId(999)), Err(error) if error==Error::NotReady.into_raw())
    );
    SLOTS
        .lock()
        .unwrap()
        .insert(999, task::ThreadQueue::MAX_THREADS);
    assert!(
        matches!(observe(owner, ThreadId(999)), Err(error) if error==Error::NotReady.into_raw())
    );
    SLOTS.lock().unwrap().remove(&999);
    let first = observe(owner, ThreadId(1)).unwrap();
    let duplicate = observe(owner, ThreadId(1)).unwrap();
    let second = observe(owner, ThreadId(2)).unwrap();
    let other = observe(unrelated, ThreadId(2)).unwrap();
    drop(first); // another guard still owns the subscription
    retire(owner);
    assert_eq!(*WOKEN.lock().unwrap(), [1, 2]);
    assert!(matches!(observe(owner, ThreadId(1)), Err(e) if e == Error::NotFound.into_raw()));
    drop(duplicate);
    drop(second);
    WOKEN.lock().unwrap().clear();
    retire(unrelated);
    assert_eq!(*WOKEN.lock().unwrap(), [2]);
    drop(other);

    // Same thread/slot, new endpoint generation. Delayed retirement of the old
    // identity must not wake a new endpoint or let an old guard remove it.
    let old = endpoint(10, 2);
    publish(old);
    let old_guard = observe(old, ThreadId(1)).unwrap();
    retire(old);
    let new = endpoint(10, 3);
    publish(new);
    let new_guard = observe(new, ThreadId(1)).unwrap();
    drop(old_guard);
    WOKEN.lock().unwrap().clear();
    lifetime::retire(old);
    assert!(WOKEN.lock().unwrap().is_empty());
    retire(new);
    assert_eq!(*WOKEN.lock().unwrap(), [1]);
    drop(new_guard);

    // Removal of a parked thread cannot depend on destructors running on its
    // discarded kernel stack. Reuse the slot while the old guard still exists.
    let owner = endpoint(20, 1);
    publish(owner);
    let discarded = observe(owner, ThreadId(1)).unwrap();
    remove_waiter(ThreadId(1));
    SLOTS.lock().unwrap().remove(&1);
    SLOTS.lock().unwrap().insert(3, 0);
    let reused = observe(owner, ThreadId(3)).unwrap();
    drop(discarded);
    WOKEN.lock().unwrap().clear();
    retire(owner);
    assert_eq!(*WOKEN.lock().unwrap(), [3]);
    drop(reused);

    // A native wait can hold 64 distinct object endpoints. Capacity failure
    // must leave existing registrations intact, and all space must be reusable.
    let mut guards = Vec::new();
    for id in 100..164 {
        let endpoint = endpoint(id, 1);
        publish(endpoint);
        guards.push(observe(endpoint, ThreadId(2)).unwrap());
    }
    let extra = endpoint(164, 1);
    publish(extra);
    assert!(
        matches!(observe(extra, ThreadId(2)), Err(e) if e == Error::ResourceUnavailable.into_raw())
    );
    drop(guards);
    drop(observe(extra, ThreadId(2)).unwrap());

    // Saturating the explicit duplicate-reference field must not wrap it or
    // consume existing references. Releasing one reference admits another.
    let mut duplicates = Vec::with_capacity(usize::from(u16::MAX));
    for _ in 0..u16::MAX {
        duplicates.push(observe(extra, ThreadId(2)).unwrap());
    }
    assert!(matches!(observe(extra, ThreadId(2)), Err(error)
        if error==Error::ResourceUnavailable.into_raw()));
    drop(duplicates.pop().unwrap());
    duplicates.push(observe(extra, ThreadId(2)).unwrap());
    WOKEN.lock().unwrap().clear();
    retire(extra);
    assert_eq!(*WOKEN.lock().unwrap(), [2]);
    drop(duplicates);

    // Race actual production subscribe against published retirement repeatedly.
    // Either registration fails closed, or retirement wakes the subscribed thread.
    for generation in 10..138 {
        let owner = endpoint(30, generation);
        publish(owner);
        WOKEN.lock().unwrap().clear();
        let barrier = std::sync::Barrier::new(2);
        std::thread::scope(|scope| {
            let registrar = scope.spawn(|| {
                barrier.wait();
                observe(owner, ThreadId(2))
            });
            barrier.wait();
            retire(owner);
            match registrar.join().unwrap() {
                Ok(guard) => {
                    assert_eq!(*WOKEN.lock().unwrap(), [2]);
                    drop(guard);
                }
                Err(error) => assert_eq!(error, Error::NotFound.into_raw()),
            }
        });
    }
    assert_eq!(LOCKED.load(Ordering::SeqCst), 0);
}

#[test]
fn production_reply_authority_cannot_cross_thread_slot_reuse() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let source = include_str!("../../../core/src/syscall/ipc.rs");
    let start = source.find("    fn add_reply_target(").unwrap();
    let end = source[start..].find("    fn reserve_slot(").unwrap() + start;
    let mut program = String::from(
        r#"
#[derive(Clone,Copy,Debug,PartialEq,Eq)] struct ReplyTarget{endpoint:u64,call_id:u64}
struct Mailbox{reply_owner:Option<(u64,u64)>,reply_targets:Vec<ReplyTarget>}
impl Mailbox {
"#,
    );
    program.push_str(&source[start..end]);
    program.push_str(
        r#"
}
fn main(){
 let mut mailbox=Mailbox{reply_owner:None,reply_targets:Vec::new()};
 let old=(7,3);let new=(8,4);
 mailbox.add_reply_target(11,101,old);
 mailbox.add_reply_target(22,102,old);
 assert_eq!(mailbox.reply_target(11,old).unwrap().call_id,101);
 assert!(mailbox.reply_target(11,new).is_none());
 assert!(mailbox.reply_target(11,(7,4)).is_none());
 assert!(mailbox.reply_target(11,(8,3)).is_none());
 // Same client endpoint, different native receiver: the old abandoned call
 // must not intercept the next receiver's reply to its current transaction.
 mailbox.add_reply_target(11,202,new);
 assert_eq!(mailbox.reply_target(11,new).unwrap().call_id,202);
 assert!(mailbox.reply_target(22,new).is_none());
 assert!(mailbox.reply_target(11,old).is_none());
 mailbox.add_reply_target(22,203,new);
 mailbox.add_reply_target(11,202,new);
 assert_eq!(mailbox.reply_targets.len(),2);
 mailbox.remove_reply_target(ReplyTarget{endpoint:11,call_id:101});
 assert_eq!(mailbox.reply_target(11,new).unwrap().call_id,202);
 mailbox.remove_reply_target(ReplyTarget{endpoint:11,call_id:202});
 assert!(mailbox.reply_target(11,new).is_none());
 assert_eq!(mailbox.reply_target(22,new).unwrap().call_id,203);
 for generation in 5..2000 {
   let owner=(8,generation);mailbox.add_reply_target(11,generation,owner);
   assert_eq!(mailbox.reply_targets.len(),1);
   assert_eq!(mailbox.reply_target(11,owner).unwrap().call_id,generation);
 }
}
"#,
    );
    let directory = std::env::temp_dir().join(format!(
        "mochios-reply-owner-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).unwrap();
    let binary = directory.join("probe");
    let mut compiler = Command::new("rustc")
        .args(["--edition=2024", "-Awarnings", "-"])
        .arg("-o")
        .arg(&binary)
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    compiler
        .stdin
        .take()
        .unwrap()
        .write_all(program.as_bytes())
        .unwrap();
    let compiled = compiler.wait_with_output().unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let executed = Command::new(&binary).output().unwrap();
    std::fs::remove_dir_all(directory).unwrap();
    assert!(
        executed.status.success(),
        "{}",
        String::from_utf8_lossy(&executed.stderr)
    );
}
