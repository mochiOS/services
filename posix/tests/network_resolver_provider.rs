//! Production DNS Provider; only kernel operations and resolver job I/O are
//! fixtures. DNS result construction uses the real network-stack decoder.
#![allow(dead_code)]
extern crate alloc;
extern crate self as mochi_user_platform;
use mnu_abi::provider;
use mochios_net_device_protocol::resolver as w;
use mochios_network_stack::{
    DnsRecordName, DnsRecordType, decode_dns_records, encode_dns_record_query,
};
use std::{cell::RefCell, collections::BTreeMap};
#[path = "../../network/src/resolver.rs"]
mod resolver;
#[path = "../../network/src/resolver_backend.rs"]
mod resolver_backend;
#[path = "../../network/src/resolver_provider.rs"]
mod server;
#[derive(Default)]
struct State {
    allowed: bool,
    create_failed: bool,
    signal_failed: bool,
    reply_failed: bool,
    created: Vec<(u64, u32, u64)>,
    closed: Vec<u32>,
    checks: Vec<(u64, String)>,
    response: Vec<u8>,
    attached: Vec<mnu_abi::IpcObjectHandle>,
    signals: Vec<(u64, u64, u64)>,
}
thread_local! {static STATE:RefCell<State>=RefCell::new(State::default());}
pub mod capability {
    pub fn check_thread(sender: u64, name: &str) -> mochi_user_syscall::SysResult<u64> {
        crate::STATE.with_borrow_mut(|s| {
            s.checks.push((sender, name.into()));
            assert_eq!(name, "net.connect");
            Ok(u64::from(sender == 77 && s.allowed))
        })
    }
}
pub mod ipc {
    pub use mnu_abi::{IpcObjectHandle, IpcObjectHandles};
    pub fn reply(_: u64, bytes: &[u8]) -> mochi_user_syscall::SysResult<()> {
        crate::STATE.with_borrow_mut(|s| {
            s.response = bytes.into();
            s.attached.clear();
        });
        Ok(())
    }
    pub fn reply_object_handles(
        sender: u64,
        bytes: &[u8],
        handles: &IpcObjectHandles,
    ) -> mochi_user_syscall::SysResult<()> {
        reply(sender, bytes)?;
        crate::STATE.with_borrow_mut(|s| {
            if s.reply_failed {
                return Err(mochi_user_syscall::SysError::from_raw(-5));
            }
            s.attached = handles.handles[..handles.count as usize].into();
            Ok(())
        })
    }
}
pub mod handle {
    pub fn create_provider_object(
        endpoint: u32,
        id: u64,
        rights: u64,
    ) -> mochi_user_syscall::SysResult<u32> {
        assert_eq!(endpoint, 5);
        assert!(id <= i64::MAX as u64);
        crate::STATE.with_borrow_mut(|s| {
            if s.create_failed {
                return Err(mochi_user_syscall::SysError::from_raw(-12));
            }
            let h = 100 + s.created.len() as u32;
            s.created.push((id, h, rights));
            Ok(h)
        })
    }
    pub fn identify_provider_object(h: u32) -> mochi_user_syscall::SysResult<u64> {
        crate::STATE.with_borrow(|s| {
            s.created
                .iter()
                .find(|r| r.1 == h)
                .map(|r| r.0)
                .ok_or(mochi_user_syscall::SysError::from_raw(-13))
        })
    }
    pub fn close(h: u32) -> mochi_user_syscall::SysResult<()> {
        crate::STATE.with_borrow_mut(|s| s.closed.push(h));
        Ok(())
    }
    pub fn signal_provider_object(
        id: u64,
        set: u64,
        clear: u64,
    ) -> mochi_user_syscall::SysResult<()> {
        crate::STATE.with_borrow_mut(|s| {
            s.signals.push((id, set, clear));
            if s.signal_failed {
                Err(mochi_user_syscall::SysError::from_raw(-5))
            } else {
                Ok(())
            }
        })
    }
}
#[derive(Default)]
struct Backend {
    next: u32,
    live: BTreeMap<u32, Option<Result<resolver::Answer, resolver::Failure>>>,
    starts: Vec<(Vec<u8>, DnsRecordType, u64)>,
    cancelled: Vec<u32>,
    start_error: Option<i32>,
    take_error: Option<i32>,
}
impl resolver_backend::Backend for Backend {
    type Query = u32;
    fn start(
        &mut self,
        name: DnsRecordName,
        kind: DnsRecordType,
        _: u64,
        timeout: u64,
    ) -> Result<u32, i32> {
        self.starts.push((name.wire().into(), kind, timeout));
        if let Some(e) = self.start_error {
            return Err(e);
        }
        self.next += 1;
        self.live.insert(self.next, None);
        Ok(self.next)
    }
    fn take(
        &mut self,
        id: u32,
    ) -> Result<Option<Result<resolver::Answer, resolver::Failure>>, i32> {
        if let Some(e) = self.take_error {
            return Err(e);
        }
        let row = self.live.get_mut(&id).ok_or(-9)?;
        if row.is_none() {
            return Ok(None);
        }
        let answer = row.take();
        self.live.remove(&id);
        Ok(answer)
    }
    fn cancel(&mut self, id: u32, _: u64) -> Result<(), i32> {
        self.cancelled.push(id);
        self.live.remove(&id).map(|_| ()).ok_or(-9)
    }
}
fn name() -> w::Name<'static> {
    w::Name::decode(b"\x07example\x03com\0").unwrap()
}
fn limits() -> w::Limits {
    w::Limits {
        scopes: w::ALL_SCOPES,
        maximum_timeout: w::MAX_TIMEOUT,
    }
}
fn setup() -> (server::Server<u32>, Backend) {
    STATE.with_borrow_mut(|s| {
        *s = State {
            allowed: true,
            ..Default::default()
        }
    });
    (server::Server::new(Some(5)), Backend::default())
}
fn attachment(h: u32) -> ipc::IpcObjectHandles {
    let mut a = ipc::IpcObjectHandles::default();
    a.count = 1;
    a.handles[0] = ipc::IpcObjectHandle {
        handle: h,
        reserved: 0,
        rights: mnu_abi::HANDLE_RIGHT_CONTROL,
    };
    a
}
fn rpc(
    s: &mut server::Server<u32>,
    b: &mut Backend,
    sender: u64,
    op: u16,
    bytes: &[u8],
    a: &ipc::IpcObjectHandles,
) -> (i32, Option<u32>) {
    assert!(s.dispatch(sender, bytes, a, b, 0));
    STATE.with_borrow(|s| {
        (
            w::reply_status(op, &s.response).unwrap(),
            s.attached.first().map(|h| h.handle),
        )
    })
}
fn acquire(s: &mut server::Server<u32>, b: &mut Backend, l: w::Limits) -> u32 {
    let (status, h) = rpc(
        s,
        b,
        77,
        w::ACQUIRE,
        &w::scoped(w::ACQUIRE, l).unwrap(),
        &Default::default(),
    );
    assert_eq!(status, 0);
    h.unwrap()
}
fn request(kind: w::Kind, timeout: u32) -> Vec<u8> {
    let mut bytes = [0; 512];
    let n = w::Request {
        kind,
        timeout,
        name: name(),
    }
    .encode(&mut bytes)
    .unwrap();
    bytes[..n].into()
}
fn open(s: &mut server::Server<u32>, b: &mut Backend, f: u32, kind: w::Kind) -> u32 {
    let (status, h) = rpc(s, b, 77, w::OPEN, &request(kind, 100), &attachment(f));
    assert_eq!(status, 0);
    h.unwrap()
}
fn object_id(h: u32) -> u64 {
    STATE.with_borrow(|s| s.created.iter().find(|r| r.1 == h).unwrap().0)
}
fn native(
    s: &mut server::Server<u32>,
    b: &mut Backend,
    h: u32,
    op: u16,
    tag: u64,
    length: usize,
    trusted: bool,
) -> (i64, Vec<u8>) {
    let mut bytes = [0; provider::REQUEST_HEADER_LEN];
    provider::RequestHeader {
        opcode: op,
        object_id: object_id(h),
        argument: 0,
        basis: tag,
        length: length as u32,
        data_length: 0,
    }
    .encode(&[], &mut bytes)
    .unwrap();
    let mut flags = ipc::IpcObjectHandles::default();
    if trusted {
        flags.delivery_flags = mnu_abi::IPC_DELIVERY_NATIVE_OBJECT;
    }
    assert!(s.dispatch(77, &bytes, &flags, b, 0));
    STATE.with_borrow(|s| {
        let (header, bytes) = provider::ResponseHeader::decode(&s.response).unwrap();
        assert_eq!(header.object_id, object_id(h));
        (header.status, bytes.into())
    })
}
fn release(s: &mut server::Server<u32>, b: &mut Backend, h: u32) {
    let mut bytes = [0; provider::REQUEST_HEADER_LEN];
    provider::RequestHeader {
        opcode: provider::OP_RELEASE,
        object_id: object_id(h),
        argument: 0,
        basis: 0,
        length: 0,
        data_length: 0,
    }
    .encode(&[], &mut bytes)
    .unwrap();
    let mut flags = ipc::IpcObjectHandles::default();
    flags.delivery_flags = mnu_abi::IPC_DELIVERY_NATIVE_OBJECT;
    STATE.with_borrow_mut(|s| s.response.clear());
    assert!(s.dispatch(0, &bytes, &flags, b, 0));
    assert!(STATE.with_borrow(|s| s.response.is_empty()));
}
fn answer(kind: DnsRecordType, count: usize) -> resolver::Answer {
    let name = DnsRecordName::from_wire(name().bytes()).unwrap();
    let mut packet = vec![0; 65535];
    let mut n = encode_dns_record_query(17, &name, kind, &mut packet).unwrap();
    packet[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
    packet[6..8].copy_from_slice(&(count as u16).to_be_bytes());
    for i in 0..count {
        let mut data = vec![
            0;
            match kind {
                DnsRecordType::A => 4,
                DnsRecordType::Aaaa => 16,
                DnsRecordType::Ptr => name.wire().len(),
            }
        ];
        match kind {
            DnsRecordType::A | DnsRecordType::Aaaa => {
                let len = data.len();
                data[len - 2..].copy_from_slice(&(i as u16).to_be_bytes());
            }
            DnsRecordType::Ptr => data.copy_from_slice(name.wire()),
        }
        let record = &mut packet[n..n + 12 + data.len()];
        record[..2].copy_from_slice(&[0xc0, 12]);
        record[2..4].copy_from_slice(&(kind as u16).to_be_bytes());
        record[4..6].copy_from_slice(&1u16.to_be_bytes());
        record[6..10].copy_from_slice(&60u32.to_be_bytes());
        record[10..12].copy_from_slice(&(data.len() as u16).to_be_bytes());
        record[12..].copy_from_slice(&data);
        n += record.len();
    }
    resolver::Answer {
        records: decode_dns_records(&packet[..n], 17, &name, kind).unwrap(),
        from_cache: false,
    }
}

#[test]
fn acquisition_uses_native_sender_and_derivation_only_reduces_types_and_deadlines() {
    let (mut s, mut b) = setup();
    assert_eq!(
        rpc(
            &mut s,
            &mut b,
            88,
            w::ACQUIRE,
            &w::scoped(w::ACQUIRE, limits()).unwrap(),
            &Default::default()
        )
        .0,
        -13
    );
    let f = acquire(&mut s, &mut b, limits());
    STATE.with_borrow_mut(|s| s.allowed = false);
    let limited = w::Limits {
        scopes: w::A_SCOPE,
        maximum_timeout: 100,
    };
    let (status, derived) = rpc(
        &mut s,
        &mut b,
        88,
        w::DERIVE,
        &w::scoped(w::DERIVE, limited).unwrap(),
        &attachment(f),
    );
    assert_eq!(status, 0);
    let derived = derived.unwrap();
    assert_eq!(
        rpc(
            &mut s,
            &mut b,
            88,
            w::DERIVE,
            &w::scoped(w::DERIVE, limits()).unwrap(),
            &attachment(derived)
        )
        .0,
        -13
    );
    assert_eq!(
        rpc(
            &mut s,
            &mut b,
            88,
            w::OPEN,
            &request(w::Kind::Aaaa, 100),
            &attachment(derived)
        )
        .0,
        -13
    );
    assert_eq!(
        rpc(
            &mut s,
            &mut b,
            88,
            w::OPEN,
            &request(w::Kind::A, 101),
            &attachment(derived)
        )
        .0,
        -13
    );
    let job = open(&mut s, &mut b, derived, w::Kind::A);
    assert_eq!(b.starts.len(), 1);
    let (status, data) = native(
        &mut s,
        &mut b,
        derived,
        provider::OP_CONTROL,
        w::QUERY_LIMITS,
        w::LIMITS_LEN,
        true,
    );
    assert_eq!(status, 0);
    assert_eq!(w::Limits::decode(&data), Ok(limited));
    release(&mut s, &mut b, f);
    release(&mut s, &mut b, derived);
    assert!(b.cancelled.is_empty());
    release(&mut s, &mut b, job);
    assert_eq!(b.cancelled, [1]);
    STATE.with_borrow(|s| {
        assert_eq!(
            s.checks,
            [(88, "net.connect".into()), (77, "net.connect".into())]
        )
    });
}

#[test]
fn attachments_require_control_and_exact_native_factory_metadata() {
    let (mut s, mut b) = setup();
    let f = acquire(&mut s, &mut b, limits());
    for a in [
        ipc::IpcObjectHandles::default(),
        attachment(0),
        attachment(999),
    ] {
        assert_eq!(
            rpc(&mut s, &mut b, 77, w::OPEN, &request(w::Kind::A, 100), &a).0,
            -13
        );
    }
    for field in 0..3 {
        let mut a = attachment(f);
        match field {
            0 => a.handles[0].rights = mnu_abi::HANDLE_RIGHT_READ,
            1 => a.handles[0].reserved = 1,
            _ => a.delivery_flags = mnu_abi::IPC_DELIVERY_NATIVE_OBJECT,
        };
        assert_eq!(
            rpc(&mut s, &mut b, 77, w::OPEN, &request(w::Kind::A, 100), &a).0,
            -13
        );
    }
    let job = open(&mut s, &mut b, f, w::Kind::A);
    assert_eq!(
        rpc(
            &mut s,
            &mut b,
            77,
            w::VALIDATE,
            &w::header(w::VALIDATE),
            &attachment(job)
        )
        .0,
        -13
    );
    assert_eq!(b.starts.len(), 1);
    release(&mut s, &mut b, job);
}

#[test]
fn raw_provider_requests_cannot_read_cancel_or_release_owned_jobs() {
    let (mut s, mut b) = setup();
    let f = acquire(&mut s, &mut b, limits());
    let job = open(&mut s, &mut b, f, w::Kind::A);
    for (op, tag, n) in [
        (provider::OP_READ_AT, 0, 100),
        (provider::OP_CONTROL, w::CANCEL, 4),
        (provider::OP_RELEASE, 0, 0),
    ] {
        assert_eq!(native(&mut s, &mut b, job, op, tag, n, false).0, -13);
    }
    assert!(b.cancelled.is_empty());
    let (status, data) = native(
        &mut s,
        &mut b,
        job,
        provider::OP_QUERY,
        w::STATUS,
        w::OBSERVATION_LEN,
        true,
    );
    assert_eq!(status, 0);
    assert!(!w::Observation::decode(&data).unwrap().ready);
    assert_eq!(
        native(&mut s, &mut b, job, provider::OP_READ_AT, 0, 16, true).0,
        -11
    );
    release(&mut s, &mut b, job);
    assert_eq!(b.cancelled, [1]);
}

#[test]
fn committed_results_are_immutable_positioned_snapshots_and_cancel_preserves_them() {
    let (mut s, mut b) = setup();
    let f = acquire(&mut s, &mut b, limits());
    let job = open(&mut s, &mut b, f, w::Kind::Aaaa);
    assert_eq!(
        native(&mut s, &mut b, job, provider::OP_MEMORY_OBJECT, 0, 0, true),
        (0, vec![])
    );
    b.live
        .insert(1, Some(Ok(answer(DnsRecordType::Aaaa, 1024))));
    let (status, data) = native(
        &mut s,
        &mut b,
        job,
        provider::OP_CONTROL,
        w::CANCEL,
        4,
        true,
    );
    assert_eq!(status, 0);
    assert_eq!(data, [0; 4]);
    assert!(b.cancelled.is_empty());
    let (status, data) = native(
        &mut s,
        &mut b,
        job,
        provider::OP_QUERY,
        w::STATUS,
        w::OBSERVATION_LEN,
        true,
    );
    assert_eq!(status, 0);
    let obs = w::Observation::decode(&data).unwrap();
    assert!(obs.ready && obs.length > 4096);
    let mut result = Vec::new();
    while result.len() < obs.length as usize {
        let (status, data) = native(
            &mut s,
            &mut b,
            job,
            provider::OP_READ_AT,
            result.len() as u64,
            97,
            true,
        );
        assert_eq!(status, 0);
        assert!(!data.is_empty());
        result.extend(data);
    }
    let decoded = w::decode_result(&result).unwrap();
    assert_eq!(decoded.values().len(), 1024);
    assert_eq!(decoded.kind, w::Kind::Aaaa);
    let (_, again) = native(&mut s, &mut b, job, provider::OP_READ_AT, 0, 97, true);
    assert_eq!(again, result[..97]);
    assert_eq!(
        native(
            &mut s,
            &mut b,
            job,
            provider::OP_READ_AT,
            u64::MAX,
            97,
            true
        ),
        (0, vec![])
    );
    STATE.with_borrow(|state| {
        assert_eq!(
            provider::ResponseHeader::decode(&state.response)
                .unwrap()
                .0
                .value,
            0
        )
    });
    release(&mut s, &mut b, job);
    assert!(b.cancelled.is_empty());
}

#[test]
fn pending_cancel_and_final_release_clean_up_once_without_reviving_old_identifiers() {
    let (mut s, mut b) = setup();
    let f = acquire(&mut s, &mut b, limits());
    let job = open(&mut s, &mut b, f, w::Kind::A);
    let (status, data) = native(
        &mut s,
        &mut b,
        job,
        provider::OP_CONTROL,
        w::CANCEL,
        4,
        true,
    );
    assert_eq!((status, data), (0, 1u32.to_le_bytes().to_vec()));
    assert_eq!(b.cancelled, [1]);
    let (_, data) = native(
        &mut s,
        &mut b,
        job,
        provider::OP_QUERY,
        w::STATUS,
        w::OBSERVATION_LEN,
        true,
    );
    let obs = w::Observation::decode(&data).unwrap();
    assert_eq!(obs.status, -125);
    let (_, data) = native(&mut s, &mut b, job, provider::OP_READ_AT, 0, 4096, true);
    assert_eq!(w::decode_result(&data).unwrap().status, -125);
    release(&mut s, &mut b, job);
    assert_eq!(b.cancelled, [1]);
    assert_eq!(
        native(
            &mut s,
            &mut b,
            job,
            provider::OP_QUERY,
            w::STATUS,
            w::OBSERVATION_LEN,
            true
        )
        .0,
        -9
    );
    let next = open(&mut s, &mut b, f, w::Kind::A);
    assert_ne!(object_id(next), object_id(job));
    release(&mut s, &mut b, next);
    assert_eq!(b.cancelled, [1, 2]);
}

#[test]
fn native_creation_signal_reply_and_backend_failures_do_not_leak_queries() {
    for case in 0..5 {
        let (mut s, mut b) = setup();
        let f = acquire(&mut s, &mut b, limits());
        match case {
            0 => STATE.with_borrow_mut(|s| s.create_failed = true),
            1 => STATE.with_borrow_mut(|s| s.signal_failed = true),
            2 => STATE.with_borrow_mut(|s| s.reply_failed = true),
            3 => b.start_error = Some(-6),
            _ => b.take_error = Some(-5),
        }
        let (status, h) = rpc(
            &mut s,
            &mut b,
            77,
            w::OPEN,
            &request(w::Kind::A, 100),
            &attachment(f),
        );
        if case < 2 {
            assert_ne!(status, 0);
            assert!(h.is_none());
            assert!(b.starts.is_empty());
        } else if case == 2 {
            assert_eq!(status, -5);
            assert!(h.is_none());
            assert_eq!(b.cancelled, [1]);
        } else {
            let job = h.unwrap();
            let (_, data) = native(
                &mut s,
                &mut b,
                job,
                provider::OP_QUERY,
                w::STATUS,
                w::OBSERVATION_LEN,
                true,
            );
            assert_eq!(
                w::Observation::decode(&data).unwrap().status,
                if case == 3 { -6 } else { -5 }
            );
            release(&mut s, &mut b, job);
        }
        assert!(b.live.is_empty());
    }
}

#[test]
fn post_completion_signal_failure_reclaims_pending_backend_ownership() {
    let (mut s, mut b) = setup();
    let f = acquire(&mut s, &mut b, limits());
    let job = open(&mut s, &mut b, f, w::Kind::A);
    STATE.with_borrow_mut(|s| s.signal_failed = true);
    s.pump(&mut b, 1);
    assert_eq!(b.cancelled, [1]);
    STATE.with_borrow_mut(|s| s.signal_failed = false);
    assert_eq!(
        native(
            &mut s,
            &mut b,
            job,
            provider::OP_QUERY,
            w::STATUS,
            w::OBSERVATION_LEN,
            true
        )
        .0,
        -9
    );
}

#[test]
fn completed_error_handles_and_nodata_are_readable_without_fake_addresses() {
    for (outcome, expected_status) in [
        (Err(resolver::Failure::Transport(-6)), -6),
        (
            Err(resolver::Failure::Wire(
                mochios_network_stack::DnsError::NoData,
            )),
            -2,
        ),
        (
            Err(resolver::Failure::Wire(
                mochios_network_stack::DnsError::Response(
                    mochios_network_stack::DnsResponseCode::NameError,
                ),
            )),
            -2,
        ),
        (Ok(answer(DnsRecordType::A, 0)), -2),
    ] {
        let (mut s, mut b) = setup();
        let f = acquire(&mut s, &mut b, limits());
        let job = open(&mut s, &mut b, f, w::Kind::A);
        b.live.insert(1, Some(outcome));
        s.pump(&mut b, 0);
        let (_, data) = native(&mut s, &mut b, job, provider::OP_READ_AT, 0, 4096, true);
        assert_eq!(w::decode_result(&data).unwrap().values().len(), 0);
        assert_eq!(w::decode_result(&data).unwrap().status, expected_status);
        STATE.with_borrow(|s| {
            assert!(s.signals.iter().any(
                |(id, set, _)| *id == object_id(job) && *set == mnu_abi::HANDLE_SIGNAL_READABLE
            ))
        });
        release(&mut s, &mut b, job);
    }
}

#[test]
fn live_job_quota_is_recovered_only_by_the_final_release_event() {
    let (mut s, mut b) = setup();
    let f = acquire(&mut s, &mut b, limits());
    let mut jobs = Vec::new();
    for _ in 0..16 {
        jobs.push(open(&mut s, &mut b, f, w::Kind::A));
    }
    assert_eq!(
        rpc(
            &mut s,
            &mut b,
            77,
            w::OPEN,
            &request(w::Kind::A, 100),
            &attachment(f)
        )
        .0,
        -24
    );
    let old = jobs.pop().unwrap();
    release(&mut s, &mut b, old);
    let new = open(&mut s, &mut b, f, w::Kind::A);
    assert_ne!(object_id(old), object_id(new));
    for job in jobs.into_iter().chain([new]) {
        release(&mut s, &mut b, job);
    }
    assert_eq!(b.cancelled.len(), 17);
    assert!(b.live.is_empty());
}

#[test]
fn malformed_operations_never_consume_factory_or_pending_backend_resources() {
    let (mut s, mut b) = setup();
    let f = acquire(&mut s, &mut b, limits());
    assert_eq!(
        rpc(
            &mut s,
            &mut b,
            77,
            999,
            &w::header(999),
            &Default::default()
        )
        .0,
        -38
    );
    let mut bad = request(w::Kind::A, 100);
    bad[20] = 1;
    assert_eq!(
        rpc(&mut s, &mut b, 77, w::OPEN, &bad, &attachment(f)).0,
        -22
    );
    let job = open(&mut s, &mut b, f, w::Kind::A);
    for (op, tag, n) in [
        (provider::OP_CONTROL, w::CANCEL, 3),
        (provider::OP_QUERY, w::STATUS, w::OBSERVATION_LEN - 1),
        (provider::OP_CONTROL, 999, 0),
    ] {
        assert_ne!(native(&mut s, &mut b, job, op, tag, n, true).0, 0);
    }
    assert!(b.cancelled.is_empty());
    release(&mut s, &mut b, job);
}
