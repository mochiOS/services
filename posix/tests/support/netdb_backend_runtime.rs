//! Real resolver transaction/backend/storage. Only native file, IPC and clock
//! mechanisms are substituted; DNS/interface replies use the production wire.
use super::*;
use mochios_net_device_protocol::{interfaces as iw, resolver as rw};
use mochios_posix_client::interfaces;
use std::{collections::VecDeque, ffi::CString, rc::Rc};

#[derive(Default)]
struct Plan {
    status: i32,
    values: Vec<Vec<u8>>,
    canonical: Option<Vec<u8>>,
    pending: bool,
    timeout: bool,
    wait_error: Option<Error>,
    snapshot_error: Option<Error>,
}
enum Owned {
    Endpoint,
    Factory,
    File(Vec<u8>),
    Job(rw::Kind, Vec<u8>, Plan),
}
#[derive(Default)]
struct State {
    next: u32,
    live: BTreeMap<u32, Owned>,
    opened: Vec<Vec<u8>>,
    files: BTreeMap<Vec<u8>, Result<Vec<u8>, Error>>,
    answers: VecDeque<Plan>,
    starts: Vec<(rw::Kind, u32)>,
    metadata: Vec<u8>,
    now: u64,
    quotas: usize,
    retries: usize,
    endpoint_error: Option<Error>,
    factory_error: Option<Error>,
    read_error: Option<Error>,
}
type Shared = Rc<RefCell<State>>;
struct Native(Shared);
fn guarded() {
    assert_ne!(CONTROL.native_delivery_defer.load(Ordering::Acquire), 0);
}
fn interruptible() {
    assert_eq!(CONTROL.native_delivery_defer.load(Ordering::Acquire), 0);
    assert!(!CONTROL.callback_resources.is_empty());
}
impl State {
    fn own(&mut self, value: Owned) -> u32 {
        guarded();
        self.next += 1;
        assert!(self.live.insert(self.next, value).is_none());
        self.next
    }
}
fn state() -> Shared {
    let mut metadata = vec![0; iw::MAX_REPLY];
    let n = iw::encode(
        [iw::Interface {
            index: 1,
            flags: iw::LOOPBACK | iw::UP,
            mtu: 1500,
            name: "lo",
            addresses: &[iw::Address::V4 {
                bytes: [127, 0, 0, 1],
                prefix: 8,
                flags: iw::USABLE,
            }],
        }]
        .into_iter(),
        &mut metadata,
    )
    .unwrap();
    metadata.truncate(n);
    Rc::new(RefCell::new(State {
        metadata,
        ..State::default()
    }))
}
impl netdb_backend::Io for Native {
    fn endpoint(&mut self) -> Result<u32, Error> {
        let mut s = self.0.borrow_mut();
        if let Some(e) = s.endpoint_error {
            return Err(e);
        }
        Ok(s.own(Owned::Endpoint))
    }
    fn factory(&mut self, endpoint: u32) -> Result<u32, Error> {
        let mut s = self.0.borrow_mut();
        assert!(matches!(s.live.get(&endpoint), Some(Owned::Endpoint)));
        if let Some(e) = s.factory_error {
            return Err(e);
        }
        Ok(s.own(Owned::Factory))
    }
    fn start(
        &mut self,
        endpoint: u32,
        factory: u32,
        kind: rw::Kind,
        name: rw::Name<'_>,
        timeout: u32,
    ) -> Result<Option<u32>, Error> {
        guarded();
        let mut s = self.0.borrow_mut();
        assert!(matches!(s.live.get(&endpoint), Some(Owned::Endpoint)));
        assert!(matches!(s.live.get(&factory), Some(Owned::Factory)));
        s.starts.push((kind, timeout));
        if s.quotas != 0 {
            s.quotas -= 1;
            return Ok(None);
        }
        let p = s.answers.pop_front().expect("unexpected DNS query");
        let mut wire = vec![0; rw::MAX_RESULT_LEN];
        let n = if p.status != 0 {
            rw::encode_failure(kind, p.status, name, &mut wire).unwrap()
        } else {
            rw::encode_result(
                kind,
                0,
                name,
                Some(
                    p.canonical
                        .as_deref()
                        .map(|n| rw::Name::decode(n).unwrap())
                        .unwrap_or(name),
                ),
                false,
                p.canonical
                    .as_deref()
                    .filter(|n| !name.matches(rw::Name::decode(n).unwrap()))
                    .map(|_| name.bytes())
                    .into_iter(),
                p.values.iter().map(Vec::as_slice),
                &mut wire,
            )
            .unwrap()
        };
        wire.truncate(n);
        Ok(Some(s.own(Owned::Job(kind, wire, p))))
    }
    fn observe(&mut self, job: u32) -> Result<rw::Observation, Error> {
        interruptible();
        let s = self.0.borrow();
        let Owned::Job(kind, bytes, p) = s.live.get(&job).unwrap() else {
            panic!()
        };
        Ok(rw::Observation {
            kind: *kind,
            ready: !p.pending,
            status: if p.pending { -11 } else { p.status },
            length: if p.pending { 0 } else { bytes.len() as u64 },
        })
    }
    fn snapshot<'a>(
        &mut self,
        job: u32,
        kind: rw::Kind,
        name: rw::Name<'_>,
        out: &'a mut [u8],
    ) -> Result<rw::ResultView<'a>, Error> {
        interruptible();
        let s = self.0.borrow();
        let Owned::Job(k, bytes, p) = s.live.get(&job).unwrap() else {
            panic!()
        };
        assert_eq!(*k, kind);
        assert!(!p.pending);
        if let Some(e) = p.snapshot_error {
            return Err(e);
        }
        out[..bytes.len()].copy_from_slice(bytes);
        let view = rw::decode_result(&out[..bytes.len()]).unwrap();
        assert_eq!(view.question, name);
        Ok(view)
    }
    fn wait(&mut self, job: u32, deadline: u64) -> Result<(), Error> {
        interruptible();
        let mut s = self.0.borrow_mut();
        let Owned::Job(_, _, p) = s.live.get_mut(&job).unwrap() else {
            panic!()
        };
        if let Some(e) = p.wait_error {
            return Err(e);
        }
        if p.timeout {
            s.now = deadline;
        } else {
            p.pending = false;
        }
        Ok(())
    }
    fn now(&mut self) -> Result<u64, Error> {
        Ok(self.0.borrow().now)
    }
    fn retry(&mut self) -> Result<(), Error> {
        interruptible();
        let mut s = self.0.borrow_mut();
        s.now += 1_000_000_000;
        s.retries += 1;
        Ok(())
    }
    fn interfaces<'a>(
        &mut self,
        endpoint: u32,
        out: &'a mut [u8],
    ) -> Result<interfaces::Snapshot<'a>, Error> {
        interruptible();
        let s = self.0.borrow();
        assert!(matches!(s.live.get(&endpoint), Some(Owned::Endpoint)));
        out[..s.metadata.len()].copy_from_slice(&s.metadata);
        iw::decode(&out[..s.metadata.len()]).map_err(|_| Error::Fail)
    }
    fn open(&mut self, path: &[u8]) -> Result<u32, Error> {
        let mut s = self.0.borrow_mut();
        s.opened.push(path.into());
        match s.files.get(path).cloned().unwrap_or(Err(Error::System(-2))) {
            Ok(bytes) => Ok(s.own(Owned::File(bytes))),
            Err(e) => Err(e),
        }
    }
    fn read(&mut self, file: u32, offset: u64, out: &mut [u8]) -> Result<usize, Error> {
        interruptible();
        let s = self.0.borrow();
        if let Some(e) = s.read_error {
            return Err(e);
        }
        let Owned::File(data) = s.live.get(&file).unwrap() else {
            panic!()
        };
        let source = &data[(offset as usize).min(data.len())..];
        let n = source.len().min(out.len()).min(37);
        out[..n].copy_from_slice(&source[..n]);
        Ok(n)
    }
    fn close(&mut self, handle: u32) {
        guarded();
        assert!(
            self.0.borrow_mut().live.remove(&handle).is_some(),
            "double/foreign close"
        );
    }
}
impl Drop for Native {
    fn drop(&mut self) {
        assert!(self.0.borrow().live.is_empty(), "native Handle leaked");
    }
}
#[derive(Debug, PartialEq, Eq)]
struct Row {
    family: i32,
    kind: i32,
    port: u16,
    scope: u32,
    bytes: Vec<u8>,
    canonical: Option<Vec<u8>>,
}
fn resolve(s: &Shared, node: &str, service: &str, h: AddrInfo) -> Result<Vec<Row>, i32> {
    let node = CString::new(node).unwrap();
    let service = CString::new(service).unwrap();
    let mut out = ptr::null_mut();
    let code = abi::getaddrinfo(
        netdb_backend::Backend::new(Native(s.clone())),
        node.as_ptr(),
        service.as_ptr(),
        &h,
        &mut out,
    );
    assert!(s.borrow().live.is_empty());
    if code != 0 {
        assert!(out.is_null());
        return Err(code);
    }
    let mut rows = Vec::new();
    let mut cursor = out;
    while !cursor.is_null() {
        // SAFETY: successful C transaction transferred a live, owned list.
        unsafe {
            let a = &*cursor;
            let bytes =
                std::slice::from_raw_parts(a.address.cast::<u8>(), a.address_length as usize);
            rows.push(Row {
                family: a.family,
                kind: a.socktype,
                port: u16::from_be_bytes(bytes[2..4].try_into().unwrap()),
                scope: if a.family == AF_INET6 {
                    u32::from_ne_bytes(bytes[24..28].try_into().unwrap())
                } else {
                    0
                },
                bytes: if a.family == AF_INET6 {
                    bytes[8..24].into()
                } else {
                    bytes[4..8].into()
                },
                canonical: (!a.canonical.is_null())
                    .then(|| CStr::from_ptr(a.canonical).to_bytes().to_vec()),
            });
            cursor = a.next;
        }
    }
    unsafe { memory::release(out).unwrap() };
    Ok(rows)
}
fn answer(s: &Shared, values: &[&[u8]]) {
    s.borrow_mut().answers.push_back(Plan {
        values: values.iter().map(|v| v.to_vec()).collect(),
        ..Plan::default()
    });
}
fn file(s: &Shared, path: &[u8], data: impl Into<Vec<u8>>) {
    s.borrow_mut().files.insert(path.into(), Ok(data.into()));
}

#[test]
fn numeric_names_skip_all_files_and_network_authority() {
    let _g = setup();
    let s = state();
    s.borrow_mut().endpoint_error = Some(Error::System(-13));
    s.borrow_mut().factory_error = Some(Error::System(-13));
    let rows = resolve(
        &s,
        "192.0.2.8",
        "73",
        hints(n::AI_NUMERICHOST | n::AI_NUMERICSERV, AF_INET, 1),
    )
    .unwrap();
    assert_eq!(rows[0].bytes, [192, 0, 2, 8]);
    assert_eq!(rows[0].port, 73);
    assert!(s.borrow().opened.is_empty());
    assert!(s.borrow().starts.is_empty());
}
#[test]
fn namespace_hosts_aliases_services_protocols_and_growth_use_real_transaction() {
    let _g = setup();
    let s = state();
    s.borrow_mut().factory_error = Some(Error::System(-13));
    let mut hosts = b"# ignored\n".repeat(600);
    hosts.extend_from_slice(b"192.0.2.1 host.example alias\n192.0.2.2 second.example alias\n");
    file(&s, b"/etc/hosts", hosts);
    file(
        &s,
        b"/etc/services",
        b"custom 43000/tcp alias-service\ncustom 43001/udp alias-service\n".to_vec(),
    );
    let rows = resolve(&s, "ALIAS", "alias-service", hints(n::AI_CANONNAME, 0, 0)).unwrap();
    assert_eq!(rows.len(), 4);
    assert_eq!(
        rows.iter().map(|r| r.port).collect::<Vec<_>>(),
        [43000, 43001, 43000, 43001]
    );
    assert_eq!(
        rows[0].canonical.as_deref(),
        Some(b"host.example".as_slice())
    );
    assert!(rows[1..].iter().all(|r| r.canonical.is_none()));
    assert!(s.borrow().starts.is_empty());
    assert_eq!(s.borrow().opened.len(), 2);
}
#[test]
fn full_dual_stack_dns_rrsets_and_canonical_name_are_not_reduced_to_one_address() {
    let _g = setup();
    let s = state();
    answer(&s, &[&[1; 16], &[2; 16]]);
    s.borrow_mut().answers[0].canonical = Some(b"\x05final\x07example\0".to_vec());
    answer(&s, &[&[192, 0, 2, 1], &[192, 0, 2, 2]]);
    let rows = resolve(&s, "alias.example", "9", hints(n::AI_CANONNAME, 0, 0)).unwrap();
    assert_eq!(rows.len(), 8);
    assert_eq!(
        rows[0].canonical.as_deref(),
        Some(b"final.example".as_slice())
    );
    assert!(rows[1..].iter().all(|r| r.canonical.is_none()));
    assert_eq!(s.borrow().opened.len(), 1);
    assert_eq!(
        s.borrow().starts,
        [
            (rw::Kind::Aaaa, rw::MAX_TIMEOUT),
            (rw::Kind::A, rw::MAX_TIMEOUT)
        ]
    );
}
#[test]
fn missing_or_denied_hosts_never_grants_dns_authority() {
    let _g = setup();
    for error in [Error::System(-2), Error::System(-13)] {
        let s = state();
        s.borrow_mut()
            .files
            .insert(b"/etc/hosts".to_vec(), Err(error));
        s.borrow_mut().factory_error = Some(Error::System(-13));
        assert_eq!(
            resolve(&s, "example.invalid", "80", hints(0, AF_INET, 1)),
            Err(n::Error::System(-13).code())
        );
        assert_eq!(ERRNO.get(), 13);
        assert!(s.borrow().starts.is_empty());
    }
}
#[test]
fn denied_service_and_interrupted_file_read_propagate_without_dns() {
    let _g = setup();
    let s = state();
    s.borrow_mut()
        .files
        .insert(b"/etc/services".to_vec(), Err(Error::System(-13)));
    assert_eq!(
        resolve(&s, "192.0.2.1", "private", hints(0, AF_INET, 1)),
        Err(Error::System(-13).code())
    );
    assert_eq!(ERRNO.get(), 13);
    let s = state();
    file(&s, b"/etc/hosts", b"127.0.0.1 local\n".to_vec());
    s.borrow_mut().read_error = Some(Error::System(-4));
    assert_eq!(
        resolve(&s, "local", "9", hints(0, AF_INET, 1)),
        Err(Error::System(-4).code())
    );
    assert_eq!(ERRNO.get(), 4);
    assert!(s.borrow().starts.is_empty());
}
#[test]
fn dns_negative_and_native_errors_remain_distinct() {
    let _g = setup();
    for (status, expected) in [
        (-2, Error::NoName),
        (-11, Error::Again),
        (-110, Error::Again),
        (-5, Error::System(-5)),
        (-13, Error::System(-13)),
    ] {
        let s = state();
        s.borrow_mut().answers.push_back(Plan {
            status,
            ..Plan::default()
        });
        assert_eq!(
            resolve(&s, "absent.example", "9", hints(0, AF_INET, 1)),
            Err(expected.code())
        );
        if let Error::System(status) = expected {
            assert_eq!(
                ERRNO.get(),
                mochios_posix_client::newlib_errno::from_status(i64::from(status))
            );
        }
    }
}
#[test]
fn wait_and_snapshot_failure_retire_job_and_do_not_publish_a_prefix() {
    let _g = setup();
    for snapshot in [false, true] {
        let s = state();
        answer(&s, &[&[192, 0, 2, 7]]);
        {
            let mut s = s.borrow_mut();
            let p = &mut s.answers[0];
            if snapshot {
                p.snapshot_error = Some(Error::System(-4));
            } else {
                p.pending = true;
                p.wait_error = Some(Error::System(-4));
            }
        }
        assert_eq!(
            resolve(&s, "interrupt.example", "9", hints(0, AF_INET, 1)),
            Err(Error::System(-4).code())
        );
        assert_eq!(ERRNO.get(), 4);
    }
}
#[test]
fn explicit_quota_retries_share_a_finite_deadline_and_waits_are_interruptible() {
    let _g = setup();
    let s = state();
    s.borrow_mut().quotas = 2;
    answer(&s, &[&[192, 0, 2, 5]]);
    s.borrow_mut().answers[0].pending = true;
    assert!(resolve(&s, "quota.example", "9", hints(0, AF_INET, 1)).is_ok());
    assert_eq!(s.borrow().retries, 2);
    assert_eq!(
        s.borrow().starts.iter().map(|v| v.1).collect::<Vec<_>>(),
        [30000, 29000, 28000]
    );
    let s = state();
    s.borrow_mut().quotas = usize::MAX;
    assert_eq!(
        resolve(&s, "quota.example", "9", hints(0, AF_INET, 1)),
        Err(Error::Again.code())
    );
    assert_eq!(s.borrow().retries, 30);
}
#[test]
fn failed_family_retires_job_before_following_family_and_timeout_is_not_restarted() {
    let _g = setup();
    let s = state();
    s.borrow_mut().answers.push_back(Plan {
        pending: true,
        wait_error: Some(Error::Again),
        ..Plan::default()
    });
    answer(&s, &[&[192, 0, 2, 8]]);
    let rows = resolve(&s, "fallback.example", "9", hints(0, 0, 1)).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].family, AF_INET);
    let s = state();
    s.borrow_mut().answers.push_back(Plan {
        pending: true,
        timeout: true,
        ..Plan::default()
    });
    assert_eq!(
        resolve(&s, "timeout.example", "9", hints(0, 0, 1)),
        Err(Error::Again.code())
    );
    assert_eq!(s.borrow().starts.len(), 1);
}
#[test]
fn interface_scope_and_addrconfig_use_the_current_snapshot() {
    let _g = setup();
    let s = state();
    let rows = resolve(&s, "fe80::1%lo", "9", hints(0, AF_INET6, 1)).unwrap();
    assert_eq!(rows[0].scope, 1);
    assert_eq!(
        resolve(&s, "fe80::1%missing", "9", hints(0, AF_INET6, 1)),
        Err(Error::NoName.code())
    );
    assert_eq!(
        resolve(&s, "127.0.0.1", "9", hints(n::AI_ADDRCONFIG, 0, 1)),
        Err(Error::NoName.code())
    );
    assert!(s.borrow().starts.is_empty());
}
#[test]
fn backend_allocation_failures_retire_files_endpoints_factories_and_jobs() {
    let _g = setup();
    let s = state();
    file(&s, b"/etc/hosts", b"# data\n".repeat(900));
    answer(&s, &[&[192, 0, 2, 5]]);
    ATTEMPTS.set(0);
    assert!(resolve(&s, "alloc.example", "9", hints(0, AF_INET, 1)).is_ok());
    let total = ATTEMPTS.get();
    assert!(total >= 4);
    for at in 0..total {
        let s = state();
        file(&s, b"/etc/hosts", b"# data\n".repeat(900));
        answer(&s, &[&[192, 0, 2, 5]]);
        ATTEMPTS.set(0);
        FAIL_AT.set(Some(at));
        assert_eq!(
            resolve(&s, "alloc.example", "9", hints(0, AF_INET, 1)),
            Err(Error::Memory.code())
        );
        FAIL_AT.set(None);
        assert!(ALLOCATIONS.with_borrow(|a| a.is_empty()));
    }
}
#[test]
fn reverse_hosts_dns_ptr_service_names_and_remote_fqdn_are_preserved() {
    let _g = setup();
    let s = state();
    file(
        &s,
        b"/etc/hosts",
        b"192.0.2.8 remote.example\n127.0.0.1 local.example\n".to_vec(),
    );
    file(
        &s,
        b"/etc/services",
        b"datagram 4567/udp\nstream 4567/tcp\n".to_vec(),
    );
    for (address, expected, flags) in [
        ([192, 0, 2, 8], "remote.example", n::NI_NOFQDN),
        ([127, 0, 0, 1], "local", n::NI_NOFQDN | n::NI_DGRAM),
    ] {
        let mut sock = [0u8; 16];
        sock[..2].copy_from_slice(&(AF_INET as u16).to_ne_bytes());
        sock[2..4].copy_from_slice(&4567u16.to_be_bytes());
        sock[4..8].copy_from_slice(&address);
        let mut host = [0i8; 128];
        let mut service = [0i8; 32];
        assert_eq!(
            abi::getnameinfo(
                netdb_backend::Backend::new(Native(s.clone())),
                sock.as_ptr().cast(),
                16,
                host.as_mut_ptr(),
                128,
                service.as_mut_ptr(),
                32,
                flags
            ),
            0
        );
        assert_eq!(
            unsafe { CStr::from_ptr(host.as_ptr()) }.to_str().unwrap(),
            expected
        );
        assert_eq!(
            unsafe { CStr::from_ptr(service.as_ptr()) }.to_bytes(),
            if flags & n::NI_DGRAM != 0 {
                b"datagram".as_slice()
            } else {
                b"stream".as_slice()
            }
        );
    }
    let s = state();
    answer(&s, &[b"\x03ptr\x07example\0"]);
    let mut sock = [0u8; 16];
    sock[..2].copy_from_slice(&(AF_INET as u16).to_ne_bytes());
    sock[4..8].copy_from_slice(&[192, 0, 2, 9]);
    let mut host = [0i8; 128];
    assert_eq!(
        abi::getnameinfo(
            netdb_backend::Backend::new(Native(s.clone())),
            sock.as_ptr().cast(),
            16,
            host.as_mut_ptr(),
            128,
            ptr::null_mut(),
            0,
            n::NI_NAMEREQD
        ),
        0
    );
    assert_eq!(
        unsafe { CStr::from_ptr(host.as_ptr()) }.to_bytes(),
        b"ptr.example"
    );
    assert_eq!(s.borrow().starts[0].0, rw::Kind::Ptr);
}
