//! Execute the production runtime cache with controlled native operations.
use core::ffi::c_int;
use mochios_posix_protocol as posix_protocol;
use posix_protocol::resource_policy::{READER_RIGHTS, ResourcePolicy};
use posix_protocol::{RLIMIT_COUNT, RLIMIT_NOFILE, ResourceLimit};
use std::sync::{Mutex, MutexGuard};

const PAGE_SIZE: usize = 4096;
const EACCES: i32 = 13;
const EIO: i32 = 5;
const EINVAL: i32 = 22;
const EAGAIN: i32 = 11;
const ENOTSUP: i32 = 95;
type RuntimeMutexGuard<'a, T> = MutexGuard<'a, T>;
struct RuntimeMutex<T>(Mutex<T>);
impl<T> RuntimeMutex<T> {
    const fn new(value: T) -> Self {
        Self(Mutex::new(value))
    }
    fn lock(&self) -> RuntimeMutexGuard<'_, T> {
        self.0.lock().unwrap()
    }
}

#[repr(C, align(4096))]
struct Page {
    policy: ResourcePolicy,
}
struct Backend {
    pages: Vec<Box<Page>>,
    selected: usize,
    requests: usize,
    closes: usize,
    maps: usize,
    unmaps: usize,
    yields: usize,
    rights: u64,
    length: u64,
    fail: Option<syscall::SyscallNumber>,
    request_error: bool,
}
impl Backend {
    fn new() -> Self {
        Self {
            pages: vec![page(9), page(3)],
            selected: 0,
            requests: 0,
            closes: 0,
            maps: 0,
            unmaps: 0,
            yields: 0,
            rights: READER_RIGHTS,
            length: PAGE_SIZE as u64,
            fail: None,
            request_error: false,
        }
    }
}
fn page(soft: u64) -> Box<Page> {
    let mut limits = [ResourceLimit::INFINITY; RLIMIT_COUNT as usize];
    limits[RLIMIT_NOFILE as usize] = ResourceLimit { soft, hard: 99 };
    Box::new(Page {
        policy: ResourcePolicy::new(limits).unwrap(),
    })
}
static BACKEND: Mutex<Option<Backend>> = Mutex::new(None);
static SERIAL: Mutex<()> = Mutex::new(());
struct Client;
struct Attachment {
    handle: u32,
}
fn posix_client() -> Result<Client, i32> {
    Ok(Client)
}
fn map_posix_client_error(error: i32) -> i32 {
    error
}
fn syscall_errno(value: Result<u64, i32>) -> Result<u64, i32> {
    value
}
fn close_object_handle(handle: u32) {
    assert_eq!(handle, 7);
    BACKEND.lock().unwrap().as_mut().unwrap().closes += 1;
}
impl Client {
    fn resource_policy_handle(&self) -> Result<Attachment, i32> {
        let mut backend = BACKEND.lock().unwrap();
        let backend = backend.as_mut().unwrap();
        backend.requests += 1;
        if backend.request_error {
            Err(EIO)
        } else {
            Ok(Attachment { handle: 7 })
        }
    }
}
mod syscall {
    use super::*;
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SyscallNumber {
        HandleRightsGet,
        MemoryObjectLength,
        MemoryMap,
        MemoryUnmap,
        ThreadYield,
    }
    pub fn raw_syscall1(number: SyscallNumber, handle: u64) -> Result<u64, i32> {
        assert_eq!(handle, 7);
        let mut backend = BACKEND.lock().unwrap();
        let backend = backend.as_mut().unwrap();
        if backend.fail == Some(number) {
            return Err(EIO);
        }
        match number {
            SyscallNumber::HandleRightsGet => Ok(backend.rights),
            SyscallNumber::MemoryObjectLength => Ok(backend.length),
            _ => panic!("unexpected {number:?}"),
        }
    }
    pub fn raw_syscall6(
        number: SyscallNumber,
        address: u64,
        length: u64,
        access: u64,
        options: u64,
        handle: u64,
        offset: u64,
    ) -> Result<u64, i32> {
        assert_eq!(number, SyscallNumber::MemoryMap);
        assert_eq!(
            (address, length, access, options, handle, offset),
            (
                0,
                4096,
                mnu_abi::MEMORY_ACCESS_READ,
                mnu_abi::MEMORY_MAP_SHARED,
                7,
                0
            )
        );
        let mut backend = BACKEND.lock().unwrap();
        let backend = backend.as_mut().unwrap();
        if backend.fail == Some(number) {
            return Err(EIO);
        }
        backend.maps += 1;
        Ok(std::ptr::from_ref(&backend.pages[backend.selected].policy) as u64)
    }
    pub fn raw_syscall2(number: SyscallNumber, address: u64, length: u64) -> Result<u64, i32> {
        assert_eq!(number, SyscallNumber::MemoryUnmap);
        assert_eq!(length, 4096);
        let mut backend = BACKEND.lock().unwrap();
        let backend = backend.as_mut().unwrap();
        assert!(
            backend
                .pages
                .iter()
                .any(|page| std::ptr::from_ref(&page.policy) as u64 == address)
        );
        backend.unmaps += 1;
        Ok(0)
    }
    pub fn raw_syscall0(number: SyscallNumber) -> Result<u64, i32> {
        assert_eq!(number, SyscallNumber::ThreadYield);
        let mut backend = BACKEND.lock().unwrap();
        let backend = backend.as_mut().unwrap();
        backend.yields += 1;
        // Complete the deliberately interrupted publication, outside POLICY.
        let policy = &backend.pages[backend.selected].policy;
        unsafe {
            (&*(std::ptr::from_ref(policy)
                .cast::<std::sync::atomic::AtomicU64>()
                .add(2)))
                .store(2, std::sync::atomic::Ordering::SeqCst);
        }
        Ok(0)
    }
}
#[path = "../../../user/crates/newlib-runtime/src/resource_policy.rs"]
mod resource_policy;

fn reset() {
    resource_policy::reset_child(&mut resource_policy::freeze_for_clone());
}
fn start() -> MutexGuard<'static, ()> {
    let serial = SERIAL.lock().unwrap();
    reset();
    *BACKEND.lock().unwrap() = Some(Backend::new());
    serial
}
fn read() -> u64 {
    resource_policy::read(RLIMIT_NOFILE).unwrap().soft
}

#[test]
fn discovery_once_live_updates_and_child_reset_drop_only_the_copied_view() {
    let _serial = start();
    assert_eq!(read(), 9);
    for _ in 0..100 {
        assert_eq!(read(), 9);
    }
    {
        let backend = BACKEND.lock().unwrap();
        let backend = backend.as_ref().unwrap();
        assert_eq!(
            (
                backend.requests,
                backend.closes,
                backend.maps,
                backend.unmaps
            ),
            (1, 1, 1, 0)
        );
        backend.pages[0]
            .policy
            .publish(RLIMIT_NOFILE, ResourceLimit { soft: 7, hard: 99 })
            .unwrap();
    }
    assert_eq!(read(), 7);
    reset();
    BACKEND.lock().unwrap().as_mut().unwrap().selected = 1;
    assert_eq!(read(), 3);
    {
        let backend = BACKEND.lock().unwrap();
        let backend = backend.as_ref().unwrap();
        assert_eq!(backend.pages[0].policy.read(RLIMIT_NOFILE).unwrap().soft, 7);
        assert_eq!(
            (
                backend.requests,
                backend.closes,
                backend.maps,
                backend.unmaps
            ),
            (2, 2, 2, 1)
        );
    }
    reset();
    assert_eq!(BACKEND.lock().unwrap().as_ref().unwrap().unmaps, 2);
}

#[test]
fn concurrent_readers_discover_once_and_clone_freeze_excludes_reads() {
    let _serial = start();
    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| {
                for _ in 0..100 {
                    assert_eq!(read(), 9);
                }
            });
        }
    });
    assert_eq!(BACKEND.lock().unwrap().as_ref().unwrap().requests, 1);
    let mut frozen = resource_policy::freeze_for_clone();
    let (started, awaiting) = std::sync::mpsc::channel();
    let (finished, result) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        started.send(()).unwrap();
        finished.send(read()).unwrap();
    });
    awaiting.recv().unwrap();
    assert_eq!(result.try_recv(), Err(std::sync::mpsc::TryRecvError::Empty));
    resource_policy::reset_child(&mut frozen);
    BACKEND.lock().unwrap().as_mut().unwrap().selected = 1;
    drop(frozen);
    assert_eq!(result.recv().unwrap(), 3);
    reader.join().unwrap();
    reset();
}

#[test]
fn all_discovery_failures_release_received_handles_and_allow_retry() {
    let _serial = start();
    for failure in [
        syscall::SyscallNumber::HandleRightsGet,
        syscall::SyscallNumber::MemoryObjectLength,
        syscall::SyscallNumber::MemoryMap,
    ] {
        *BACKEND.lock().unwrap() = Some(Backend::new());
        BACKEND.lock().unwrap().as_mut().unwrap().fail = Some(failure);
        assert_eq!(resource_policy::read(RLIMIT_NOFILE), Err(EIO));
        assert_eq!(BACKEND.lock().unwrap().as_ref().unwrap().closes, 1);
        BACKEND.lock().unwrap().as_mut().unwrap().fail = None;
        assert_eq!(read(), 9);
        reset();
    }
    *BACKEND.lock().unwrap() = Some(Backend::new());
    BACKEND.lock().unwrap().as_mut().unwrap().request_error = true;
    assert_eq!(resource_policy::read(RLIMIT_NOFILE), Err(EIO));
    assert_eq!(BACKEND.lock().unwrap().as_ref().unwrap().closes, 0);
    BACKEND.lock().unwrap().as_mut().unwrap().request_error = false;
    assert_eq!(read(), 9);
    reset();
}

#[test]
fn native_rights_extent_and_header_are_checked_before_caching() {
    let _serial = start();
    for (rights, length, expected) in [
        (READER_RIGHTS | 2, 4096, EACCES),
        (READER_RIGHTS, 8, EIO),
        (READER_RIGHTS, 8192, EIO),
    ] {
        *BACKEND.lock().unwrap() = Some(Backend::new());
        {
            let mut backend = BACKEND.lock().unwrap();
            let backend = backend.as_mut().unwrap();
            backend.rights = rights;
            backend.length = length;
        }
        assert_eq!(resource_policy::read(RLIMIT_NOFILE), Err(expected));
        let backend = BACKEND.lock().unwrap();
        let backend = backend.as_ref().unwrap();
        assert_eq!(
            (
                backend.requests,
                backend.closes,
                backend.maps,
                backend.unmaps
            ),
            (1, 1, 0, 0)
        );
    }
    *BACKEND.lock().unwrap() = Some(Backend::new());
    {
        let backend = BACKEND.lock().unwrap();
        let policy = &backend.as_ref().unwrap().pages[0].policy;
        unsafe {
            (&*std::ptr::from_ref(policy).cast::<std::sync::atomic::AtomicU64>())
                .store(0, std::sync::atomic::Ordering::SeqCst);
        }
    }
    assert_eq!(resource_policy::read(RLIMIT_NOFILE), Err(EIO));
    let backend = BACKEND.lock().unwrap();
    let backend = backend.as_ref().unwrap();
    assert_eq!((backend.closes, backend.maps, backend.unmaps), (1, 1, 1));
}

#[test]
fn invalid_resource_never_discovers_and_busy_reader_retries_after_unlock() {
    let _serial = start();
    assert_eq!(resource_policy::read(RLIMIT_COUNT), Err(EINVAL));
    assert_eq!(BACKEND.lock().unwrap().as_ref().unwrap().requests, 0);
    {
        let backend = BACKEND.lock().unwrap();
        let policy = &backend.as_ref().unwrap().pages[0].policy;
        unsafe {
            (&*(std::ptr::from_ref(policy)
                .cast::<std::sync::atomic::AtomicU64>()
                .add(2)))
                .store(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
    assert_eq!(read(), 9);
    assert_eq!(BACKEND.lock().unwrap().as_ref().unwrap().yields, 1);
    reset();
}

#[test]
fn runtime_routes_own_reads_to_page_and_freezes_after_allocator_before_state() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    let clone = source
        .split("fn clone_registered_process()")
        .nth(1)
        .unwrap()
        .split("fn create_spawn_status_stream()")
        .next()
        .unwrap();
    assert!(
        clone.find("atfork::freeze_allocator()").unwrap()
            < clone.find("resource_policy::freeze_for_clone()").unwrap()
    );
    assert!(clone.find("resource_policy::freeze_for_clone()").unwrap()
        < clone.find("let guard = state()").unwrap());
    assert!(clone.find("drop(policy_guard)").unwrap()
        < clone.find("drop(allocator_guard)").unwrap());
    assert!(
        clone
            .find("resource_policy::reset_child(&mut policy_guard)")
            .unwrap()
            < clone.find("drop(policy_guard)").unwrap()
    );
    assert!(source.contains("resource_policy::read(posix_protocol::RLIMIT_NOFILE)?"));
    assert!(source.contains("if process_id == 0 && replacement.is_none()"));
    // FD duplication must not acquire POLICY while already holding STATE.
    let duplicate = source
        .split("fn duplicate_live_fd(")
        .nth(1)
        .unwrap()
        .split("fn duplicate_fd_from(")
        .next()
        .unwrap();
    assert!(
        duplicate.find("process_fd_limit()").unwrap()
            < duplicate.find("let mut state = state()").unwrap()
    );
}
