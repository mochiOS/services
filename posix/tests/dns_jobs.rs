//! Production DNS jobs with scripted nonblocking I/O and independent DNS bytes.
#![allow(dead_code)]
extern crate alloc;
#[path = "../../network/src/resolver.rs"]
mod resolver;
#[path = "../../network/src/resolver_rpc.rs"]
mod resolver_rpc;
use mochios_network_stack::{DnsError, DnsRecordName, DnsRecordType, DnsRecordValue, Ipv4Config};
use resolver::{Failure, Resolver, Transport};
use std::collections::{BTreeMap, VecDeque};
#[path = "support/dns_negative_jobs.rs"]
mod negative;

#[derive(Default)]
struct Udp {
    sent: Vec<Vec<u8>>,
    received: VecDeque<Vec<u8>>,
    closed: bool,
}
#[derive(Default)]
struct Tcp {
    sent: Vec<u8>,
    received: VecDeque<u8>,
    closed: bool,
    connected: bool,
    eof: bool,
    write_block: bool,
    read_block: bool,
}
struct Io {
    config: Result<Ipv4Config, i32>,
    udp: BTreeMap<usize, Udp>,
    tcp: BTreeMap<usize, Tcp>,
    next: usize,
    entropy: u64,
    entropy_error: bool,
    udp_full: bool,
    udp_block: bool,
    write_limit: usize,
    read_limit: usize,
    open_tcp_error: Option<i32>,
    wrong_count: bool,
    operations: usize,
}
impl Default for Io {
    fn default() -> Self {
        Self {
            config: Ok(Ipv4Config {
                address: [192, 0, 2, 1],
                subnet_mask: [255, 255, 255, 0],
                gateway: [0; 4],
                dns: [192, 0, 2, 53],
            }),
            udp: BTreeMap::new(),
            tcp: BTreeMap::new(),
            next: 1,
            entropy: 0x1234_5678_1234_5678,
            entropy_error: false,
            udp_full: false,
            udp_block: false,
            write_limit: usize::MAX,
            read_limit: usize::MAX,
            open_tcp_error: None,
            wrong_count: false,
            operations: 0,
        }
    }
}
impl Transport for Io {
    type Datagram = usize;
    type Stream = usize;
    fn context(&self) -> Result<Ipv4Config, i32> {
        self.config
    }
    fn entropy(&mut self) -> Result<u64, i32> {
        if self.entropy_error {
            Err(-5)
        } else {
            self.entropy = self.entropy.wrapping_add(0x1000_0001);
            Ok(self.entropy)
        }
    }
    fn open_datagram(&mut self, _: [u8; 4], _: u64) -> Result<usize, i32> {
        if self.udp_full {
            return Err(-11);
        }
        let id = self.next;
        self.next += 1;
        self.udp.insert(id, Udp::default());
        Ok(id)
    }
    fn send_datagram(&mut self, id: usize, data: &[u8], _: u64) -> Result<(), i32> {
        self.operations += 1;
        if self.udp_block {
            return Err(-11);
        }
        let u = self.udp.get_mut(&id).unwrap();
        assert!(!u.closed);
        u.sent.push(data.to_vec());
        Ok(())
    }
    fn receive_datagram(&mut self, id: usize) -> Result<Option<Vec<u8>>, i32> {
        self.operations += 1;
        let u = self.udp.get_mut(&id).unwrap();
        assert!(!u.closed);
        Ok(u.received.pop_front())
    }
    fn close_datagram(&mut self, id: usize) {
        let u = self.udp.get_mut(&id).unwrap();
        assert!(!u.closed, "double UDP release");
        u.closed = true;
    }
    fn open_stream(&mut self, _: [u8; 4], _: u64) -> Result<usize, i32> {
        if let Some(error) = self.open_tcp_error {
            return Err(error);
        }
        let id = self.next;
        self.next += 1;
        self.tcp.insert(id, Tcp::default());
        Ok(id)
    }
    fn stream_connected(&mut self, id: usize) -> Result<bool, i32> {
        self.operations += 1;
        Ok(self.tcp[&id].connected)
    }
    fn send_stream(&mut self, id: usize, data: &[u8]) -> Result<usize, i32> {
        self.operations += 1;
        let t = self.tcp.get_mut(&id).unwrap();
        assert!(!t.closed);
        if t.write_block {
            return Err(-11);
        }
        if self.wrong_count {
            return Ok(data.len() + 1);
        }
        let n = data.len().min(self.write_limit);
        t.sent.extend_from_slice(&data[..n]);
        Ok(n)
    }
    fn receive_stream(&mut self, id: usize, out: &mut [u8]) -> Result<usize, i32> {
        self.operations += 1;
        let t = self.tcp.get_mut(&id).unwrap();
        assert!(!t.closed);
        if t.read_block {
            return Err(-11);
        }
        if self.wrong_count {
            return Ok(out.len() + 1);
        }
        if t.received.is_empty() {
            return if t.eof { Ok(0) } else { Err(-11) };
        }
        let n = out.len().min(self.read_limit).min(t.received.len());
        for byte in &mut out[..n] {
            *byte = t.received.pop_front().unwrap();
        }
        Ok(n)
    }
    fn close_stream(&mut self, id: usize, _: u64) {
        let t = self.tcp.get_mut(&id).unwrap();
        assert!(!t.closed, "double TCP release");
        t.closed = true;
    }
}

fn name(text: &str) -> DnsRecordName {
    resolver::hostname(text).unwrap()
}
fn wire(text: &str) -> Vec<u8> {
    name(text).wire().to_vec()
}
fn reply(query: &[u8], records: &[(&str, u16, u32, Vec<u8>)]) -> Vec<u8> {
    let mut out = query.to_vec();
    out[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
    out[6..8].copy_from_slice(&(records.len() as u16).to_be_bytes());
    for (owner, kind, ttl, data) in records {
        out.extend(wire(owner));
        out.extend(kind.to_be_bytes());
        out.extend([0, 1]);
        out.extend(ttl.to_be_bytes());
        out.extend((data.len() as u16).to_be_bytes());
        out.extend_from_slice(data);
    }
    out
}
fn start(r: &mut Resolver<usize, usize>, io: &mut Io, text: &str) -> resolver::Query {
    let q = r.start(io, name(text), DnsRecordType::A, 0, 10000).unwrap();
    r.pump(io, 0);
    q
}
fn udp(io: &Io) -> usize {
    *io.udp.iter().rev().find(|(_, u)| !u.closed).unwrap().0
}
fn packet(io: &Io, id: usize) -> Vec<u8> {
    reply(
        io.udp[&id].sent.last().unwrap(),
        &[("example.com", 1, 60, vec![192, 0, 2, 1])],
    )
}
fn push(io: &mut Io, id: usize, p: Vec<u8>) {
    io.udp.get_mut(&id).unwrap().received.push_back(p);
}
fn tcp_fallback(r: &mut Resolver<usize, usize>, io: &mut Io) -> (resolver::Query, usize, Vec<u8>) {
    let q = start(r, io, "example.com");
    let id = udp(io);
    let mut truncated = packet(io, id);
    truncated[2] |= 2;
    push(io, id, truncated);
    r.pump(io, 1);
    assert!(io.udp[&id].closed);
    let id = *io.tcp.keys().last().unwrap();
    let p = packet(io, *io.udp.keys().next_back().unwrap());
    (q, id, p)
}
fn framed(packet: &[u8]) -> Vec<u8> {
    let mut out = (packet.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(packet);
    out
}
fn drive(r: &mut Resolver<usize, usize>, io: &mut Io, now: u64) {
    for _ in 0..1024 {
        r.pump(io, now);
    }
}

#[test]
fn udp_completion_preserves_all_answers_and_cache_hit_uses_no_io_or_entropy() {
    let mut io = Io::default();
    let mut r = Resolver::new();
    let q = start(&mut r, &mut io, "example.com");
    let id = udp(&io);
    let p = reply(
        io.udp[&id].sent.last().unwrap(),
        &[
            ("example.com", 1, 60, vec![1; 4]),
            ("example.com", 1, 30, vec![2; 4]),
        ],
    );
    push(&mut io, id, p);
    r.pump(&mut io, 1);
    let answer = r.take(q).unwrap().unwrap().unwrap();
    assert_eq!(
        answer.records.values(),
        [DnsRecordValue::Ipv4([1; 4]), DnsRecordValue::Ipv4([2; 4])]
    );
    assert!(!answer.from_cache);
    assert!(io.udp[&id].closed);
    assert_eq!(r.take(q), Err(-9));
    io.entropy_error = true;
    let count = io.operations;
    let q = r
        .start(&mut io, name("example.com"), DnsRecordType::A, 1001, 0)
        .unwrap();
    let answer = r.take(q).unwrap().unwrap().unwrap();
    assert!(answer.from_cache);
    assert_eq!(answer.records.ttl_seconds(), 29);
    assert_eq!(io.operations, count);
    assert_eq!(r.statistics.cache_hits, 1);
}

#[test]
fn unanswered_or_flooded_query_cannot_stall_another_client() {
    let mut io = Io::default();
    let mut r = Resolver::new();
    let first = start(&mut r, &mut io, "waiting.test");
    let slow = udp(&io);
    let second = start(&mut r, &mut io, "example.com");
    let fast = udp(&io);
    let mut bad = packet(&io, slow);
    bad[0] ^= 1;
    for _ in 0..100 {
        push(&mut io, slow, bad.clone());
    }
    let good = packet(&io, fast);
    push(&mut io, fast, good);
    let before = io.operations;
    r.pump(&mut io, 1);
    assert!(io.operations - before <= 12);
    assert!(r.take(first).unwrap().is_none());
    assert!(r.take(second).unwrap().unwrap().is_ok());
    r.cancel(&mut io, first, 2).unwrap();
    assert!(io.udp[&slow].closed);
}

#[test]
fn tcp_framing_handles_split_length_partial_writes_and_fragmented_body() {
    for chunk in [1, 3, 7, 4096] {
        let mut io = Io::default();
        io.write_limit = chunk;
        io.read_limit = chunk;
        let mut r = Resolver::new();
        let (q, id, p) = tcp_fallback(&mut r, &mut io);
        assert!(r.take(q).unwrap().is_none());
        io.tcp.get_mut(&id).unwrap().connected = true;
        io.tcp.get_mut(&id).unwrap().received.extend(framed(&p));
        drive(&mut r, &mut io, 2);
        let answer = r.take(q).unwrap().unwrap().unwrap();
        assert_eq!(
            answer.records.values(),
            [DnsRecordValue::Ipv4([192, 0, 2, 1])]
        );
        let sent = &io.tcp[&id].sent;
        assert_eq!(
            usize::from(u16::from_be_bytes(sent[..2].try_into().unwrap())),
            sent.len() - 2
        );
        assert_eq!(&sent[2..], io.udp.values().next().unwrap().sent[0]);
        assert!(io.tcp[&id].closed);
        assert_eq!(r.statistics.queries, 2);
    }
}

#[test]
fn tcp_wrong_transaction_or_question_is_skipped_as_a_complete_frame() {
    let mut io = Io::default();
    let mut r = Resolver::new();
    let (q, id, p) = tcp_fallback(&mut r, &mut io);
    let mut wrong = p.clone();
    wrong[0] ^= 1;
    let mut wrong_question = p.clone();
    wrong_question[13] = b'z';
    let t = io.tcp.get_mut(&id).unwrap();
    t.connected = true;
    t.received.extend(framed(&wrong));
    t.received.extend(framed(&wrong_question));
    t.received.extend(framed(&p));
    drive(&mut r, &mut io, 2);
    assert!(r.take(q).unwrap().unwrap().is_ok());
    assert!(io.tcp[&id].closed);
}

#[test]
fn tcp_can_receive_a_message_larger_than_the_udp_limit() {
    let mut io = Io::default();
    let mut r = Resolver::new();
    let (q, id, _) = tcp_fallback(&mut r, &mut io);
    let records = (0..200)
        .map(|n| ("example.com", 1, 60, vec![192, 0, 2, n]))
        .collect::<Vec<_>>();
    let p = reply(&io.udp.values().next().unwrap().sent[0], &records);
    assert!(p.len() > 512);
    let t = io.tcp.get_mut(&id).unwrap();
    t.connected = true;
    t.received.extend(framed(&p));
    drive(&mut r, &mut io, 2);
    assert_eq!(
        r.take(q).unwrap().unwrap().unwrap().records.values().len(),
        200
    );
}

#[test]
fn deadline_cancel_and_config_loss_release_each_channel_once() {
    for stage in 0..5 {
        let mut io = Io::default();
        let mut r = Resolver::new();
        let (q, id, p) = tcp_fallback(&mut r, &mut io);
        if stage >= 1 {
            io.tcp.get_mut(&id).unwrap().connected = true;
            r.pump(&mut io, 2);
        }
        if stage >= 2 {
            io.tcp
                .get_mut(&id)
                .unwrap()
                .received
                .push_back((p.len() >> 8) as u8);
            r.pump(&mut io, 3);
        }
        if stage >= 3 {
            io.tcp
                .get_mut(&id)
                .unwrap()
                .received
                .extend([(p.len() & 255) as u8, p[0]]);
            r.pump(&mut io, 4);
        }
        if stage == 4 {
            io.config = Err(-100);
            r.pump(&mut io, 5);
            assert_eq!(r.take(q).unwrap().unwrap(), Err(Failure::Transport(-100)));
        } else {
            r.cancel(&mut io, q, 5).unwrap();
            assert_eq!(r.take(q), Err(-9));
        }
        assert!(io.tcp[&id].closed);
        r.pump(&mut io, 20000);
        assert!(io.tcp[&id].closed);
    }
    let mut io = Io::default();
    let mut r = Resolver::new();
    let q = start(&mut r, &mut io, "example.com");
    let id = udp(&io);
    r.pump(&mut io, 10000);
    assert_eq!(
        r.take(q).unwrap().unwrap(),
        Err(Failure::Wire(DnsError::Timeout))
    );
    assert!(io.udp[&id].closed);
    assert_eq!(r.statistics.timeouts, 1);
}

#[test]
fn tcp_eof_invalid_length_and_truncation_are_terminal_not_partial_answers() {
    for case in 0..5 {
        let mut io = Io::default();
        let mut r = Resolver::new();
        let (q, id, mut p) = tcp_fallback(&mut r, &mut io);
        let t = io.tcp.get_mut(&id).unwrap();
        t.connected = true;
        match case {
            0 => t.eof = true,
            1 => {
                t.received.extend([0, 11]);
            }
            2 => {
                t.received.extend(framed(&p)[..3].iter().copied());
                t.eof = true;
            }
            3 => {
                p[2] |= 2;
                t.received.extend(framed(&p));
            }
            _ => {
                p.push(0);
                t.received.extend(framed(&p));
            }
        }
        drive(&mut r, &mut io, 2);
        assert!(r.take(q).unwrap().unwrap().is_err());
        assert!(io.tcp[&id].closed);
    }
}

#[test]
fn udp_retry_backoff_and_backpressure_do_not_consume_unsent_attempts() {
    let mut io = Io::default();
    io.udp_block = true;
    let mut r = Resolver::new();
    let q = start(&mut r, &mut io, "example.com");
    let id = udp(&io);
    for now in 1..100 {
        r.pump(&mut io, now);
    }
    assert_eq!(r.statistics.queries, 0);
    assert!(io.tcp.is_empty());
    io.udp_block = false;
    for (now, count) in [
        (100, 1),
        (599, 1),
        (600, 2),
        (1599, 2),
        (1600, 3),
        (3599, 3),
    ] {
        r.pump(&mut io, now);
        assert_eq!(io.udp[&id].sent.len(), count);
    }
    r.pump(&mut io, 3600);
    assert!(io.udp[&id].closed);
    assert_eq!(io.tcp.len(), 1);
    assert!(r.take(q).unwrap().is_none());
    r.cancel(&mut io, q, 3601).unwrap();
}

#[test]
fn cross_message_cname_ages_alias_ttl_and_retains_original_question() {
    let mut io = Io::default();
    let mut r = Resolver::new();
    let q = start(&mut r, &mut io, "alias.test");
    let id = udp(&io);
    let p = reply(
        &io.udp[&id].sent[0],
        &[("alias.test", 5, 3, wire("example.com"))],
    );
    push(&mut io, id, p);
    r.pump(&mut io, 0);
    r.pump(&mut io, 1000);
    let second = udp(&io);
    assert_ne!(id, second);
    assert!(io.udp[&id].closed);
    let p = packet(&io, second);
    push(&mut io, second, p);
    r.pump(&mut io, 2000);
    let answer = r.take(q).unwrap().unwrap().unwrap();
    assert_eq!(answer.records.question(), &name("alias.test"));
    assert_eq!(answer.records.canonical_name(), &name("example.com"));
    assert_eq!(answer.records.ttl_seconds(), 1);
    assert_eq!(answer.records.aliases(), [name("alias.test")]);
    let cache = r
        .start(&mut io, name("alias.test"), DnsRecordType::A, 3000, 100)
        .unwrap();
    assert!(r.take(cache).unwrap().is_none());
    r.cancel(&mut io, cache, 3000).unwrap();
}

#[test]
fn cross_message_cycles_and_global_alias_depth_cannot_restart_forever() {
    let mut io = Io::default();
    let mut r = Resolver::new();
    let q = start(&mut r, &mut io, "alias.test");
    for (from, to) in [("alias.test", "example.com"), ("example.com", "alias.test")] {
        r.pump(&mut io, 0);
        let id = udp(&io);
        let p = reply(&io.udp[&id].sent[0], &[(from, 5, 60, wire(to))]);
        push(&mut io, id, p);
        r.pump(&mut io, 0);
    }
    assert_eq!(
        r.take(q).unwrap().unwrap(),
        Err(Failure::Wire(DnsError::AliasLoop))
    );
    let q = start(&mut r, &mut io, "a0.test");
    for n in 0..17 {
        r.pump(&mut io, 1);
        let id = udp(&io);
        let p = reply(
            &io.udp[&id].sent[0],
            &[(
                &format!("a{n}.test"),
                5,
                60,
                wire(&format!("a{}.test", n + 1)),
            )],
        );
        push(&mut io, id, p);
        r.pump(&mut io, 1);
    }
    assert_eq!(
        r.take(q).unwrap().unwrap(),
        Err(Failure::Wire(DnsError::AliasDepth))
    );
    assert!(io.udp.values().all(|u| u.closed));
}

#[test]
fn context_change_invalidates_cache_and_pending_jobs_without_retargeting() {
    let mut io = Io::default();
    let mut r = Resolver::new();
    let q = start(&mut r, &mut io, "example.com");
    let id = udp(&io);
    let p = packet(&io, id);
    push(&mut io, id, p);
    r.pump(&mut io, 0);
    r.take(q).unwrap().unwrap().unwrap();
    let pending = start(&mut r, &mut io, "other.test");
    let live = udp(&io);
    io.config.as_mut().unwrap().dns = [198, 51, 100, 53];
    r.pump(&mut io, 1);
    assert_eq!(
        r.take(pending).unwrap().unwrap(),
        Err(Failure::Transport(-99))
    );
    assert!(io.udp[&live].closed);
    let q = r
        .start(&mut io, name("example.com"), DnsRecordType::A, 1, 100)
        .unwrap();
    assert!(r.take(q).unwrap().is_none());
    r.cancel(&mut io, q, 1).unwrap();
}

#[test]
fn entropy_failure_zero_timeout_and_resource_pressure_fail_without_leaks() {
    let mut io = Io::default();
    io.entropy_error = true;
    let mut r = Resolver::new();
    let q = start(&mut r, &mut io, "example.com");
    assert_eq!(r.take(q).unwrap().unwrap(), Err(Failure::Transport(-5)));
    assert!(io.udp.is_empty());
    io.entropy_error = false;
    let q = r
        .start(&mut io, name("example.com"), DnsRecordType::A, 0, 0)
        .unwrap();
    r.pump(&mut io, 0);
    assert_eq!(
        r.take(q).unwrap().unwrap(),
        Err(Failure::Wire(DnsError::Timeout))
    );
    assert!(io.udp.is_empty());
    io.udp_full = true;
    let q = start(&mut r, &mut io, "example.com");
    assert!(r.take(q).unwrap().is_none());
    io.udp_full = false;
    r.pump(&mut io, 1);
    let id = udp(&io);
    assert_eq!(io.udp[&id].sent.len(), 1);
    r.cancel(&mut io, q, 1).unwrap();
    assert!(io.udp[&id].closed);
}

#[test]
fn backend_overcounts_or_failed_tcp_open_never_become_success() {
    for writing in [true, false] {
        let mut io = Io::default();
        let mut r = Resolver::new();
        let (q, id, p) = tcp_fallback(&mut r, &mut io);
        io.tcp.get_mut(&id).unwrap().connected = true;
        if !writing {
            r.pump(&mut io, 2);
            io.tcp.get_mut(&id).unwrap().received.extend(framed(&p));
        }
        io.wrong_count = true;
        r.pump(&mut io, 3);
        assert_eq!(r.take(q).unwrap().unwrap(), Err(Failure::Transport(-5)));
        assert!(io.tcp[&id].closed);
    }
    let mut io = Io::default();
    io.open_tcp_error = Some(-24);
    let mut r = Resolver::new();
    let q = start(&mut r, &mut io, "example.com");
    let id = udp(&io);
    let mut p = packet(&io, id);
    p[2] |= 2;
    push(&mut io, id, p);
    r.pump(&mut io, 1);
    assert_eq!(r.take(q).unwrap().unwrap(), Err(Failure::Transport(-24)));
    assert!(io.udp[&id].closed);
    assert!(io.tcp.is_empty());
}

#[test]
fn aaaa_and_ptr_queries_use_the_same_nonblocking_transport() {
    for (kind, number, data) in [
        (DnsRecordType::Aaaa, 28, vec![1; 16]),
        (DnsRecordType::Ptr, 12, wire("host.test")),
    ] {
        let mut io = Io::default();
        let mut r = Resolver::new();
        let q = r.start(&mut io, name("example.com"), kind, 0, 100).unwrap();
        r.pump(&mut io, 0);
        let id = udp(&io);
        let sent = &io.udp[&id].sent[0];
        assert_eq!(
            &sent[sent.len() - 4..sent.len() - 2],
            &(number as u16).to_be_bytes()
        );
        let p = reply(sent, &[("example.com", number, 60, data)]);
        push(&mut io, id, p);
        r.pump(&mut io, 1);
        assert_eq!(
            r.take(q).unwrap().unwrap().unwrap().records.record_type(),
            kind
        );
    }
}

#[test]
fn job_quota_includes_unconsumed_completions_and_identifiers_never_reuse() {
    let mut io = Io::default();
    let mut r = Resolver::new();
    let mut jobs = Vec::new();
    for _ in 0..16 {
        jobs.push(
            r.start(&mut io, name("example.com"), DnsRecordType::A, 0, 0)
                .unwrap(),
        );
    }
    r.pump(&mut io, 0);
    assert_eq!(
        r.start(&mut io, name("example.com"), DnsRecordType::A, 0, 0),
        Err(-11)
    );
    let old = jobs.pop().unwrap();
    r.take(old).unwrap().unwrap().unwrap_err();
    let new = r
        .start(&mut io, name("example.com"), DnsRecordType::A, 0, 100)
        .unwrap();
    assert_ne!(new, old);
    assert_eq!(r.cancel(&mut io, old, 0), Err(-9));
    r.cancel(&mut io, new, 0).unwrap();
    for q in jobs {
        r.cancel(&mut io, q, 0).unwrap();
    }
    assert!(io.udp.is_empty());
}

struct RpcHost {
    resolver: Resolver<usize, usize>,
    io: Io,
}
impl RpcHost {
    fn new() -> Self {
        Self {
            resolver: Resolver::new(),
            io: Io::default(),
        }
    }
}
impl resolver_rpc::Backend for RpcHost {
    type Query = resolver::Query;
    fn start(&mut self, name: DnsRecordName, now: u64, timeout: u64) -> Result<Self::Query, i32> {
        self.resolver
            .start(&mut self.io, name, DnsRecordType::A, now, timeout)
    }
    fn take(&mut self, id: Self::Query) -> Result<Option<Result<resolver::Answer, Failure>>, i32> {
        self.resolver.take(id)
    }
}
fn request(id: u64, timeout: u32, host: &str) -> Vec<u8> {
    let mut out = vec![0; 512];
    let n = mochios_net_device_protocol::encode_resolve_ipv4(id, host, timeout, &mut out).unwrap();
    out.truncate(n);
    out
}
type Reply = (u64, u64, i32, [u8; 4], bool);
fn receive(replies: &mut Vec<Reply>, sender: u64, bytes: &[u8]) {
    let (id, status, address, cached) =
        mochios_net_device_protocol::decode_resolve_ipv4_result(bytes).unwrap();
    replies.push((sender, id, status, address, cached));
}

#[test]
fn rpc_replies_are_deferred_and_correlated_while_other_requests_continue() {
    let mut host = RpcHost::new();
    let mut rpc = resolver_rpc::Replies::new();
    let mut replies = Vec::new();
    assert!(rpc.dispatch(
        &mut host,
        41,
        &request(7, 10000, "example.com"),
        0,
        |sender| {
            assert_eq!(sender, 41);
            true
        },
        |s, b| receive(&mut replies, s, b)
    ));
    assert!(replies.is_empty());
    assert!(rpc.dispatch(
        &mut host,
        42,
        &request(8, 100, "192.0.2.2"),
        0,
        |_| true,
        |s, b| receive(&mut replies, s, b)
    ));
    assert_eq!(replies, [(42, 8, 0, [192, 0, 2, 2], false)]);
    host.resolver.pump(&mut host.io, 0);
    let id = udp(&host.io);
    let p = packet(&host.io, id);
    push(&mut host.io, id, p);
    host.resolver.pump(&mut host.io, 1);
    rpc.pump(&mut host, |s, b| receive(&mut replies, s, b));
    assert_eq!(replies[1], (41, 7, 0, [192, 0, 2, 1], false));
    assert!(host.io.udp[&id].closed);
    rpc.pump(&mut host, |_, _| panic!("duplicate reply"));
    rpc.dispatch(
        &mut host,
        99,
        &request(17, 100, "EXAMPLE.COM."),
        1001,
        |_| true,
        |_, _| panic!("DNS start must defer"),
    );
    rpc.pump(&mut host, |s, b| receive(&mut replies, s, b));
    assert_eq!(replies[2], (99, 17, 0, [192, 0, 2, 1], true));
}

#[test]
fn rpc_denies_before_starting_io_and_leaves_other_opcodes_to_their_handler() {
    let mut host = RpcHost::new();
    let mut rpc = resolver_rpc::Replies::new();
    let mut replies = Vec::new();
    rpc.dispatch(
        &mut host,
        88,
        &request(7, 10, "example.com"),
        0,
        |sender| {
            assert_eq!(sender, 88);
            false
        },
        |s, b| receive(&mut replies, s, b),
    );
    assert_eq!(replies, [(88, 7, -13, [0; 4], false)]);
    assert!(host.io.udp.is_empty());
    assert_eq!(host.resolver.statistics.cache_misses, 0);
    rpc.dispatch(
        &mut host,
        89,
        &request(8, 10, "bad..name"),
        0,
        |_| true,
        |s, b| receive(&mut replies, s, b),
    );
    assert_eq!(replies[1].2, -22);
    let mut other = [0; mochios_net_device_protocol::HEADER_LEN];
    mochios_net_device_protocol::encode_empty(
        mochios_net_device_protocol::Opcode::GetStackStatistics,
        9,
        &mut other,
    )
    .unwrap();
    assert!(!rpc.dispatch(
        &mut host,
        90,
        &other,
        0,
        |_| panic!("wrong authorization path"),
        |_, _| panic!("wrong reply path")
    ));
    let mut bad = request(10, 10, "example.com");
    *bad.last_mut().unwrap() = 0xff;
    rpc.dispatch(
        &mut host,
        90,
        &bad,
        0,
        |_| true,
        |s, b| receive(&mut replies, s, b),
    );
    assert_eq!(replies[2], (90, 10, -22, [0; 4], false));
}

#[test]
fn rpc_quotas_do_not_consume_other_senders_and_deadline_releases_every_job() {
    let mut host = RpcHost::new();
    let mut rpc = resolver_rpc::Replies::new();
    let mut replies = Vec::new();
    for id in 0..3 {
        rpc.dispatch(
            &mut host,
            1,
            &request(id, u32::MAX, "example.com"),
            0,
            |_| true,
            |s, b| receive(&mut replies, s, b),
        );
    }
    assert_eq!(replies, [(1, 2, -11, [0; 4], false)]);
    for sender in 2..9 {
        for id in 0..2 {
            rpc.dispatch(
                &mut host,
                sender,
                &request(id, u32::MAX, "example.com"),
                0,
                |_| true,
                |_, _| panic!("quota leaked across senders"),
            );
        }
    }
    rpc.dispatch(
        &mut host,
        9,
        &request(99, 100, "example.com"),
        0,
        |_| true,
        |s, b| receive(&mut replies, s, b),
    );
    assert_eq!(replies.last().unwrap().2, -11);
    host.resolver.pump(&mut host.io, 30000);
    rpc.pump(&mut host, |s, b| receive(&mut replies, s, b));
    assert_eq!(replies.len(), 18);
    assert!(replies[2..].iter().all(|r| r.2 == -11));
    assert!(host.io.udp.is_empty());
    rpc.dispatch(
        &mut host,
        9,
        &request(100, 100, "example.com"),
        30000,
        |_| true,
        |_, _| panic!("quota was not released"),
    );
}
