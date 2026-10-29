#![allow(dead_code)]
use mochios_posix_client::{
    internet::{AF_INET, AF_INET6, Address},
    netdb::{self as n, Backend, Configuration, Error, Host, Reverse, ScopedAddress, Transport},
};
use mochios_posix_protocol as posix_protocol;
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    ffi::{CStr, c_char, c_int, c_void},
    ptr,
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
    },
};
#[path = "../../../user/crates/newlib-runtime/src/netdb_abi.rs"]
mod abi;
#[path = "../../../user/crates/newlib-runtime/src/callback_resources.rs"]
mod callback_resources;
#[path = "../../../user/crates/newlib-runtime/src/io_resources.rs"]
mod io_resources;
#[path = "../../../user/crates/newlib-runtime/src/netdb_memory.rs"]
mod memory;
#[path = "../../../user/crates/newlib-runtime/src/user_copy.rs"]
mod user_copy;
#[path = "support/user_copy_native.rs"]
mod user_copy_native;
use memory as netdb_memory;
use memory::{AddrInfo, List};
use user_copy_native::{syscall, syscall_errno};
const PAGE_SIZE: usize = 4096;
const EFAULT: c_int = 14;
const EIO: c_int = 5;
const EAGAIN: c_int = 11;
const EINVAL: c_int = 22;
const EFAULT_STATUS: i32 = -14;
const ENOENT: c_int = 2;
const ENAMETOOLONG: c_int = 91;
struct ThreadControl {
    callback_resources: callback_resources::Chain,
    active_signal_scope_id: AtomicU64,
    native_delivery_defer: AtomicU32,
}
static CONTROL: ThreadControl = ThreadControl {
    callback_resources: callback_resources::Chain::new(),
    active_signal_scope_id: AtomicU64::new(0),
    native_delivery_defer: AtomicU32::new(0),
};
static REGISTER_FAIL: AtomicBool = AtomicBool::new(false);
static SERIAL: Mutex<()> = Mutex::new(());
fn register_current_thread() -> Option<(u32, &'static ThreadControl)> {
    (!REGISTER_FAIL.load(Ordering::Acquire)).then_some((1, &CONTROL))
}
fn defer_native_delivery() -> Option<mochios_posix_client::upcall_guard::Guard<'static>> {
    mochios_posix_client::upcall_guard::Guard::enter(&CONTROL.native_delivery_defer)
}
thread_local! {
    static ALLOCATIONS:RefCell<BTreeMap<usize,usize>>=const {RefCell::new(BTreeMap::new())};
    static ATTEMPTS:Cell<usize>=const {Cell::new(0)};
    static FAIL_AT:Cell<Option<usize>>=const {Cell::new(None)};
    static ERRNO:Cell<i32>=const {Cell::new(0)};
    static BACKENDS:Cell<usize>=const {Cell::new(0)};
}
fn set_errno(errno: c_int) {
    ERRNO.set(errno);
}
unsafe fn malloc(length: usize) -> *mut c_void {
    assert_ne!(
        CONTROL.native_delivery_defer.load(Ordering::Acquire),
        0,
        "allocation must be atomically registered"
    );
    let attempt = ATTEMPTS.get();
    ATTEMPTS.set(attempt + 1);
    if FAIL_AT.get() == Some(attempt) {
        return ptr::null_mut();
    }
    let pointer = unsafe { libc::malloc(length) };
    if !pointer.is_null() {
        ALLOCATIONS.with_borrow_mut(|a| assert!(a.insert(pointer as usize, length).is_none()));
    }
    pointer
}
unsafe fn free(pointer: *mut c_void) {
    assert_ne!(
        CONTROL.native_delivery_defer.load(Ordering::Acquire),
        0,
        "release must be guarded"
    );
    ALLOCATIONS.with_borrow_mut(|a| {
        assert!(
            a.remove(&(pointer as usize)).is_some(),
            "duplicate or foreign allocation"
        )
    });
    unsafe { libc::free(pointer) };
    set_errno(999); // Cleanup must not overwrite an eventual EAI_SYSTEM errno.
}
struct TestGuard(std::sync::MutexGuard<'static, ()>);
fn setup() -> TestGuard {
    let lock = SERIAL.lock().unwrap();
    assert!(CONTROL.callback_resources.reset_empty());
    assert_eq!(CONTROL.native_delivery_defer.load(Ordering::Acquire), 0);
    assert!(ALLOCATIONS.with_borrow(|a| a.is_empty()));
    assert_eq!(BACKENDS.get(), 0);
    ATTEMPTS.set(0);
    FAIL_AT.set(None);
    ERRNO.set(0);
    REGISTER_FAIL.store(false, Ordering::Release);
    TestGuard(lock)
}
impl Drop for TestGuard {
    fn drop(&mut self) {
        assert!(ALLOCATIONS.with_borrow(|a| a.is_empty()));
        assert_eq!(BACKENDS.get(), 0);
        assert!(CONTROL.callback_resources.reset_empty());
        assert_eq!(CONTROL.native_delivery_defer.load(Ordering::Acquire), 0);
    }
}
struct Fixture {
    rows: usize,
    error: Option<Error>,
    before_return: Option<Box<dyn FnMut()>>,
}
impl Fixture {
    fn new(rows: usize) -> Self {
        BACKENDS.set(BACKENDS.get() + 1);
        Self {
            rows,
            error: None,
            before_return: None,
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        BACKENDS.set(BACKENDS.get() - 1);
        set_errno(999);
    }
}
impl Backend for Fixture {
    fn configuration(&mut self) -> Result<Configuration, Error> {
        Ok(Configuration {
            ipv4: true,
            ipv6: true,
        })
    }
    fn scope(&mut self, _: &[u8]) -> Result<Option<u32>, Error> {
        Ok(None)
    }
    fn host(
        &mut self,
        name: &[u8],
        family: i32,
        emit: &mut dyn FnMut(Host<'_>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        assert_eq!(name, b"alias.example");
        for i in 0..self.rows {
            let address = if family == AF_INET {
                Address::V4((i as u32).to_be_bytes())
            } else {
                let mut a = [0; 16];
                a[..4].copy_from_slice(&[0x20, 1, 0xd, 0xb8]);
                a[12..].copy_from_slice(&(i as u32).to_be_bytes());
                Address::V6(a)
            };
            emit(Host {
                address: address.into(),
                canonical: Some(b"canonical.example"),
            })?;
        }
        if let Some(call) = self.before_return.as_mut() {
            call();
        }
        self.error.map_or(Ok(()), Err)
    }
    fn service(&mut self, _: &[u8], _: Transport) -> Result<Option<u16>, Error> {
        panic!("numeric service must not use names")
    }
    fn reverse(&mut self, _: ScopedAddress, out: &mut [u8]) -> Result<Option<Reverse>, Error> {
        out[..12].copy_from_slice(b"host.example");
        Ok(Some(Reverse {
            length: 12,
            local: false,
        }))
    }
    fn service_name(&mut self, _: u16, _: Transport, _: &mut [u8]) -> Result<Option<usize>, Error> {
        Ok(None)
    }
}
fn hints(flags: i32, family: i32, kind: i32) -> AddrInfo {
    AddrInfo {
        flags,
        family,
        socktype: kind,
        protocol: 0,
        address_length: 0,
        address: ptr::null_mut(),
        canonical: ptr::null_mut(),
        next: ptr::null_mut(),
    }
}
fn numeric_result() -> *mut AddrInfo {
    let mut result = ptr::null_mut();
    let h = hints(
        n::AI_NUMERICHOST | n::AI_NUMERICSERV | n::AI_CANONNAME,
        AF_INET,
        1,
    );
    assert_eq!(
        abi::getaddrinfo(
            Fixture::new(0),
            c"192.0.2.1".as_ptr(),
            c"32100".as_ptr(),
            &h,
            &mut result
        ),
        0
    );
    assert!(!result.is_null());
    result
}

#[test]
fn numeric_transaction_returns_native_c_layout_without_name_service_or_extra_lifetimes() {
    let _test = setup();
    let result = numeric_result();
    assert_eq!(BACKENDS.get(), 0);
    assert_eq!(ALLOCATIONS.with_borrow(|a| a.len()), 1);
    let info = unsafe { &*result };
    assert_eq!(
        (
            info.flags,
            info.family,
            info.socktype,
            info.protocol,
            info.address_length
        ),
        (0, 2, 1, 6, 16)
    );
    assert!(info.next.is_null());
    let address = unsafe { std::slice::from_raw_parts(info.address.cast::<u8>(), 16) };
    assert_eq!(&address[..2], &2u16.to_ne_bytes());
    assert_eq!(&address[2..4], &32100u16.to_be_bytes());
    assert_eq!(&address[4..8], &[192, 0, 2, 1]);
    assert_eq!(&address[8..], [0; 8]);
    assert_eq!(
        unsafe { CStr::from_ptr(info.canonical) }.to_bytes(),
        b"192.0.2.1"
    );
    assert_eq!(
        std::mem::size_of::<AddrInfo>(),
        std::mem::size_of::<libc::addrinfo>()
    );
    assert_eq!(
        std::mem::offset_of!(AddrInfo, address),
        std::mem::offset_of!(libc::addrinfo, ai_addr)
    );
    unsafe { memory::release(result) }.unwrap();
}
#[test]
fn full_ipv6_results_are_zero_padded_scoped_and_can_release_a_split_sublist() {
    let _test = setup();
    let mut result = ptr::null_mut();
    let h = hints(n::AI_CANONNAME, AF_INET6, 0);
    assert_eq!(
        abi::getaddrinfo(
            Fixture::new(1024),
            c"alias.example".as_ptr(),
            c"53".as_ptr(),
            &h,
            &mut result
        ),
        0
    );
    assert_eq!(ALLOCATIONS.with_borrow(|a| a.len()), 2048);
    let mut count = 0;
    let mut cursor = result;
    while !cursor.is_null() {
        let info = unsafe { &*cursor };
        assert_eq!(info.family, 10);
        assert_eq!(info.address_length, 28);
        let address = unsafe { std::slice::from_raw_parts(info.address.cast::<u8>(), 28) };
        assert_eq!(&address[4..8], [0; 4]);
        assert_eq!(&address[24..], [0; 4]);
        assert_eq!(info.canonical.is_null(), count != 0);
        count += 1;
        cursor = info.next;
    }
    assert_eq!(count, 2048);
    let suffix = unsafe { (*result).next };
    unsafe { (*result).next = ptr::null_mut() };
    unsafe { memory::release(suffix) }.unwrap();
    assert_eq!(ALLOCATIONS.with_borrow(|a| a.len()), 1);
    unsafe { memory::release(result) }.unwrap();
    let mut result = ptr::null_mut();
    let h = hints(n::AI_NUMERICHOST, AF_INET6, 1);
    assert_eq!(
        abi::getaddrinfo(
            Fixture::new(0),
            c"fe80::1%7".as_ptr(),
            c"0".as_ptr(),
            &h,
            &mut result
        ),
        0
    );
    let info = unsafe { &*result };
    let bytes = unsafe { std::slice::from_raw_parts(info.address.cast::<u8>(), 28) };
    assert_eq!(&bytes[24..], &7u32.to_ne_bytes());
    unsafe { memory::release(result) }.unwrap();
}
#[test]
fn allocation_failures_discard_every_prefix_and_leave_result_null() {
    let _test = setup();
    let h = hints(n::AI_CANONNAME, AF_INET6, 1);
    for fail in 0..8 {
        ATTEMPTS.set(0);
        FAIL_AT.set(Some(fail));
        let mut result = 1usize as *mut AddrInfo;
        assert_eq!(
            abi::getaddrinfo(
                Fixture::new(8),
                c"alias.example".as_ptr(),
                c"80".as_ptr(),
                &h,
                &mut result
            ),
            Error::Memory.code()
        );
        assert!(result.is_null());
        assert!(ALLOCATIONS.with_borrow(|a| a.is_empty()));
        assert_eq!(BACKENDS.get(), 0);
    }
    FAIL_AT.set(None);
}
#[test]
fn late_backend_failure_frees_results_before_publishing_system_errno() {
    let _test = setup();
    let h = hints(0, AF_INET6, 1);
    let mut result = 1usize as *mut AddrInfo;
    let mut backend = Fixture::new(3);
    backend.error = Some(Error::System(-13));
    assert_eq!(
        abi::getaddrinfo(
            backend,
            c"alias.example".as_ptr(),
            c"80".as_ptr(),
            &h,
            &mut result
        ),
        Error::System(-13).code()
    );
    assert_eq!(ERRNO.get(), 13);
    assert!(result.is_null());
    assert!(ALLOCATIONS.with_borrow(|a| a.is_empty()));
}
#[test]
fn invalid_inputs_are_faultable_and_hints_padding_is_not_a_reserved_wire_field() {
    let _test = setup();
    for address in [1usize, usize::MAX] {
        let mut result = 1usize as *mut AddrInfo;
        assert_eq!(
            abi::getaddrinfo(
                Fixture::new(0),
                address as *const _,
                ptr::null(),
                ptr::null(),
                &mut result
            ),
            -11
        );
        assert_eq!(ERRNO.get(), EFAULT);
        assert!(result.is_null());
        assert_eq!(
            abi::getaddrinfo(
                Fixture::new(0),
                c"192.0.2.1".as_ptr(),
                ptr::null(),
                address as *const _,
                &mut result
            ),
            -11
        );
        assert_eq!(ERRNO.get(), EFAULT);
        assert_eq!(
            abi::getaddrinfo(
                Fixture::new(0),
                c"192.0.2.1".as_ptr(),
                ptr::null(),
                ptr::null(),
                address as *mut _
            ),
            -11
        );
        assert_eq!(ERRNO.get(), EFAULT);
    }
    assert_eq!(ATTEMPTS.get(), 0);
    let mut bytes = [0u8; 49];
    bytes[1..5].copy_from_slice(&n::AI_NUMERICHOST.to_ne_bytes());
    bytes[5..9].copy_from_slice(&AF_INET.to_ne_bytes());
    bytes[9..13].copy_from_slice(&1i32.to_ne_bytes());
    bytes[21..25].fill(0xa5);
    let h = memory::hints(bytes.as_ptr().wrapping_add(1).cast()).unwrap();
    assert_eq!(h.family, AF_INET);
    bytes[17] = 1;
    assert_eq!(
        memory::hints(bytes.as_ptr().wrapping_add(1).cast()),
        Err(Error::BadFlags)
    );
}
#[test]
fn input_strings_and_hints_are_snapshots_and_limits_are_reported_without_allocation() {
    let _test = setup();
    let mut input = memory::Inputs::new();
    let mut result = 1usize as *mut AddrInfo;
    let mut node = b"alias.example\0".to_vec();
    let mut h = hints(n::AI_CANONNAME, AF_INET6, 1);
    input
        .capture(node.as_ptr().cast(), c"80".as_ptr(), &h, &mut result)
        .unwrap();
    node.fill(b'x');
    h.family = 1;
    assert_eq!(h.family, 1);
    assert_eq!(input.node(), Some(b"alias.example".as_slice()));
    assert_eq!(input.service(), Some(b"80".as_slice()));
    assert_eq!(input.hints.family, AF_INET6);
    let long = std::ffi::CString::new(vec![b'a'; 1025]).unwrap();
    assert_eq!(
        input.capture(long.as_ptr(), ptr::null(), ptr::null(), &mut result),
        Err(Error::NoName)
    );
    assert_eq!(
        input.capture(ptr::null(), long.as_ptr(), ptr::null(), &mut result),
        Err(Error::Service)
    );
    assert_eq!(ATTEMPTS.get(), 0);
}
#[test]
fn caller_output_becoming_read_only_during_lookup_rolls_back_owned_results() {
    let _test = setup();
    let page = unsafe {
        libc::mmap(
            ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(page, libc::MAP_FAILED);
    let address = page as usize;
    let mut backend = Fixture::new(2);
    backend.before_return = Some(Box::new(move || {
        assert_eq!(
            unsafe { libc::mprotect(address as *mut _, 4096, libc::PROT_READ) },
            0
        )
    }));
    let h = hints(0, AF_INET6, 1);
    assert_eq!(
        abi::getaddrinfo(
            backend,
            c"alias.example".as_ptr(),
            c"80".as_ptr(),
            &h,
            page.cast()
        ),
        -11
    );
    assert_eq!(ERRNO.get(), EFAULT);
    assert!(ALLOCATIONS.with_borrow(|a| a.is_empty()));
    assert_eq!(unsafe { libc::munmap(page, 4096) }, 0);
}
#[test]
fn tracked_list_and_backend_are_reclaimed_once_when_the_callback_frame_is_abandoned() {
    let _test = setup();
    let chain = &CONTROL.callback_resources;
    let mut scope = core::pin::pin!(callback_resources::Scope::new(
        chain,
        0,
        (List::new(), Fixture::new(0))
    ));
    unsafe { scope.as_mut().activate() };
    for _ in 0..3 {
        scope
            .as_mut()
            .resource_mut()
            .unwrap()
            .0
            .append(n::Entry {
                address: Address::V4([192, 0, 2, 1]).into(),
                port: 80,
                transport: Transport::Tcp,
                canonical: None,
            })
            .unwrap();
    }
    assert!(chain.capture_for_fork().is_none());
    assert_eq!(ALLOCATIONS.with_borrow(|a| a.len()), 3);
    unsafe { chain.abandon_from(0) };
    assert!(ALLOCATIONS.with_borrow(|a| a.is_empty()));
    assert_eq!(BACKENDS.get(), 0);
    unsafe { scope.as_mut().retire() };
}
#[test]
fn getnameinfo_validates_sockaddr_and_commits_both_bounded_c_strings() {
    let _test = setup();
    let result = numeric_result();
    let info = unsafe { &*result };
    let mut host = [0xa5; 64];
    let mut service = [0xa5; 16];
    assert_eq!(
        abi::getnameinfo(
            Fixture::new(0),
            info.address,
            16,
            host.as_mut_ptr().cast(),
            64,
            service.as_mut_ptr().cast(),
            16,
            n::NI_NUMERICHOST | n::NI_NUMERICSERV
        ),
        0
    );
    assert_eq!(&host[..10], b"192.0.2.1\0");
    assert_eq!(&service[..6], b"32100\0");
    assert_eq!(host[10], 0xa5);
    assert_eq!(service[6], 0xa5);
    host.fill(0xa5);
    service.fill(0xa5);
    assert_eq!(
        abi::getnameinfo(
            Fixture::new(0),
            info.address,
            16,
            host.as_mut_ptr().cast(),
            64,
            service.as_mut_ptr().cast(),
            5,
            n::NI_NUMERICHOST | n::NI_NUMERICSERV
        ),
        Error::Overflow.code()
    );
    assert_eq!(host, [0xa5; 64]);
    assert_eq!(service, [0xa5; 16]);
    assert_eq!(
        abi::getnameinfo(
            Fixture::new(0),
            info.address,
            16,
            host.as_mut_ptr().cast(),
            64,
            1usize as *mut _,
            0,
            0
        ),
        0
    );
    assert_eq!(&host[..13], b"host.example\0");
    unsafe { memory::release(result) }.unwrap();
}
#[test]
fn sockaddr_lengths_families_unaligned_storage_and_invalid_outputs_are_checked() {
    let _test = setup();
    let result = numeric_result();
    let info = unsafe { &*result };
    let mut bytes = [0xa5; 30];
    user_copy::read(info.address.cast(), &mut bytes[1..17]).unwrap();
    assert_eq!(
        memory::sockaddr(bytes.as_ptr().wrapping_add(1).cast(), 16)
            .unwrap()
            .1,
        32100
    );
    for length in 0..16 {
        assert_eq!(memory::sockaddr(info.address, length), Err(Error::Family));
    }
    bytes[1..3].copy_from_slice(&1u16.to_ne_bytes());
    assert_eq!(
        memory::sockaddr(bytes.as_ptr().wrapping_add(1).cast(), 16),
        Err(Error::Family)
    );
    for address in [1usize, usize::MAX] {
        assert_eq!(
            memory::sockaddr(address as *const _, 28),
            Err(Error::System(EFAULT_STATUS))
        );
    }
    let mut service = [0u8; 32];
    assert_eq!(
        abi::getnameinfo(
            Fixture::new(0),
            info.address,
            16,
            1usize as *mut _,
            32,
            service.as_mut_ptr().cast(),
            32,
            n::NI_NUMERICHOST | n::NI_NUMERICSERV
        ),
        -11
    );
    assert_eq!(ERRNO.get(), EFAULT);
    unsafe { memory::release(result) }.unwrap();
}
#[test]
fn owner_publication_failure_empty_results_and_thread_registration_failure_do_not_leak() {
    let _test = setup();
    let mut list = List::new();
    assert_eq!(list.publish(ptr::null_mut()), Err(Error::NoName));
    list.append(n::Entry {
        address: Address::V4([0; 4]).into(),
        port: 0,
        transport: Transport::Tcp,
        canonical: None,
    })
    .unwrap();
    assert_eq!(list.publish(1usize as *mut _), Err(Error::System(-14)));
    drop(list);
    assert!(ALLOCATIONS.with_borrow(|a| a.is_empty()));
    REGISTER_FAIL.store(true, Ordering::Release);
    let mut result = ptr::null_mut();
    assert_eq!(
        abi::getaddrinfo(
            Fixture::new(0),
            c"192.0.2.1".as_ptr(),
            ptr::null(),
            ptr::null(),
            &mut result
        ),
        -11
    );
    assert_eq!(ERRNO.get(), EAGAIN);
    REGISTER_FAIL.store(false, Ordering::Release);
}
#[test]
fn resolver_error_strings_are_stable_terminated_and_cover_every_error_code() {
    let _test = setup();
    for code in [0, -1, -2, -3, -4, -6, -7, -8, -10, -11, -12] {
        let message = memory::error_text(code);
        assert_eq!(message.last(), Some(&0));
        assert!(!message[..message.len() - 1].contains(&0));
        assert!(!message.starts_with(b"Unknown"));
    }
    assert_eq!(memory::error_text(77), memory::error_text(i32::MIN));
    assert_eq!(unsafe { memory::release(ptr::null_mut()) }, Ok(()));
}
