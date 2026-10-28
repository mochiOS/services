//! Actual TCP packet encoding/checksums and transport state, without IPC or NIC.
extern crate alloc;
use mochios_network_stack as tcp;
pub use tcp::PacketError;
// Keep the existing active-open, data, retransmit and close regression suite.
#[allow(dead_code)]
#[path = "../../../user/crates/network-stack/src/tcp.rs"]
mod active_regression;
use tcp::{
    TCP_FLAG_ACK as ACK, TCP_FLAG_FIN as FIN, TCP_FLAG_RST as RST, TCP_FLAG_SYN as SYN,
    TcpConnection as Connection, TcpConnectionError as Error, TcpConnectionTable as Table,
    TcpListenConfig as Config, TcpOptions, TcpReceiveResult as Event, TcpSegment,
    TcpState as State, TcpTransmit, TcpTuple as Tuple,
};
const OWNER: u64 = 77;
const LISTENER: u64 = 10;
fn config() -> Config {
    Config {
        backlog: 4,
        local_mss: 1200,
        send_capacity: 8192,
        receive_capacity: 8192,
        retransmit_timeout: 10,
        retry_limit: 2,
    }
}
fn tuple(port: u16) -> Tuple {
    Tuple {
        local_address: [10, 0, 2, 15],
        local_port: 8000,
        remote_address: [10, 0, 2, 2],
        remote_port: port,
    }
}
fn reverse(t: Tuple) -> Tuple {
    Tuple {
        local_address: t.remote_address,
        local_port: t.remote_port,
        remote_address: t.local_address,
        remote_port: t.local_port,
    }
}
struct Packet {
    bytes: Vec<u8>,
    source: [u8; 4],
    destination: [u8; 4],
}
impl Packet {
    fn new(t: Tuple, tx: TcpTransmit) -> Self {
        let mut bytes = vec![0; 60 + tx.payload.len()];
        let length = TcpSegment {
            source_port: t.local_port,
            destination_port: t.remote_port,
            sequence: tx.sequence,
            acknowledgment: tx.acknowledgment,
            flags: tx.flags,
            window: tx.window,
            urgent_pointer: 0,
            options: tx.options,
            payload: &tx.payload,
        }
        .encode(t.local_address, t.remote_address, &mut bytes)
        .unwrap();
        bytes.truncate(length);
        Self {
            bytes,
            source: t.local_address,
            destination: t.remote_address,
        }
    }
    fn segment(&self) -> TcpSegment<'_> {
        TcpSegment::decode(self.source, self.destination, &self.bytes).unwrap()
    }
}
fn packet(t: Tuple, seq: u32, ack: u32, flags: u16, payload: &[u8]) -> Packet {
    Packet::new(
        t,
        TcpTransmit {
            sequence: seq,
            acknowledgment: ack,
            flags,
            window: 8192,
            options: TcpOptions::default(),
            payload: payload.to_vec(),
            retransmission: false,
        },
    )
}
fn listening(capacity: usize, c: Config) -> Table {
    let mut table = Table::new(capacity);
    table.listen(LISTENER, OWNER, [0; 4], 8000, c).unwrap();
    table
}
fn client(t: Tuple, iss: u32) -> Connection {
    Connection::connect(90, 99, reverse(t), iss, 1400, 8192, 8192, 10, 2)
}
fn start(table: &mut Table, remote: u16, handle: u64, iss: u32, server_iss: u32) -> Connection {
    let t = tuple(remote);
    let mut c = client(t, iss);
    let syn = Packet::new(reverse(t), c.poll_transmit(0).unwrap().unwrap());
    assert_eq!(
        table.receive_syn(handle, t, &syn.segment(), server_iss),
        Ok(handle)
    );
    c
}
fn complete(table: &mut Table, handle: u64, c: &mut Connection) {
    let t = reverse(c.tuple);
    let syn_ack = Packet::new(
        t,
        table
            .get_mut(handle, OWNER)
            .unwrap()
            .poll_transmit(1)
            .unwrap()
            .unwrap(),
    );
    assert_eq!(c.on_segment(&syn_ack.segment(), 1), Ok(Event::Acknowledge));
    let ack = Packet::new(c.tuple, c.acknowledgment());
    table.receive_segment(t, &ack.segment(), 2).unwrap();
}

#[test]
fn passive_open_exchanges_data_both_ways_and_preserves_half_close() {
    let mut table = listening(8, config());
    let mut c = start(&mut table, 50000, 20, 100, 700);
    assert_eq!(table.accept(LISTENER, OWNER), Ok(None));
    complete(&mut table, 20, &mut c);
    assert_eq!(table.accept(LISTENER, OWNER), Ok(Some((20, tuple(50000)))));
    assert_eq!(table.accept(LISTENER, OWNER), Ok(None));
    c.queue_send(b"request").unwrap();
    let data = Packet::new(c.tuple, c.poll_transmit(3).unwrap().unwrap());
    assert_eq!(
        table.receive_segment(tuple(50000), &data.segment(), 3),
        Ok(Event::Acknowledge)
    );
    let s = table.get_mut(20, OWNER).unwrap();
    let mut bytes = [0; 32];
    let n = s.receive(&mut bytes);
    assert_eq!(&bytes[..n], b"request");
    let ack = Packet::new(s.tuple, s.acknowledgment());
    c.on_segment(&ack.segment(), 4).unwrap();
    s.queue_send(b"response").unwrap();
    let data = Packet::new(s.tuple, s.poll_transmit(4).unwrap().unwrap());
    c.on_segment(&data.segment(), 4).unwrap();
    let n = c.receive(&mut bytes);
    assert_eq!(&bytes[..n], b"response");
    let ack = Packet::new(c.tuple, c.acknowledgment());
    table
        .receive_segment(tuple(50000), &ack.segment(), 5)
        .unwrap();
    c.request_close().unwrap();
    let fin = Packet::new(c.tuple, c.poll_transmit(6).unwrap().unwrap());
    table
        .receive_segment(tuple(50000), &fin.segment(), 6)
        .unwrap();
    let s = table.get_mut(20, OWNER).unwrap();
    assert_eq!(s.state, State::CloseWait);
    let ack = Packet::new(s.tuple, s.acknowledgment());
    c.on_segment(&ack.segment(), 7).unwrap();
    assert_eq!(c.state, State::FinWait2);
    s.request_close().unwrap();
    let fin = Packet::new(s.tuple, s.poll_transmit(8).unwrap().unwrap());
    c.on_segment(&fin.segment(), 8).unwrap();
    assert_eq!(c.state, State::TimeWait);
    let ack = Packet::new(c.tuple, c.acknowledgment());
    table
        .receive_segment(tuple(50000), &ack.segment(), 9)
        .unwrap();
    assert_eq!(table.get_mut(20, OWNER).unwrap().state, State::Closed);
}

#[test]
fn duplicate_syn_preserves_iss_and_does_not_consume_a_second_backlog_slot() {
    let mut cfg = config();
    cfg.backlog = 1;
    let mut table = listening(2, cfg);
    let mut c = client(tuple(50000), 100);
    let syn = Packet::new(c.tuple, c.poll_transmit(0).unwrap().unwrap());
    table
        .receive_syn(20, tuple(50000), &syn.segment(), 700)
        .unwrap();
    let first = table
        .get_mut(20, OWNER)
        .unwrap()
        .poll_transmit(0)
        .unwrap()
        .unwrap();
    assert_eq!(
        table.receive_syn(21, tuple(50000), &syn.segment(), 900),
        Ok(20)
    );
    let repeated = table.get_mut(20, OWNER).unwrap().acknowledgment();
    assert_eq!(
        (repeated.sequence, repeated.acknowledgment, repeated.flags),
        (700, 101, SYN | ACK)
    );
    assert_eq!(first.sequence, repeated.sequence);
    assert_eq!(table.len(), 1);
    let other = packet(reverse(tuple(50001)), 200, 0, SYN, &[]);
    assert_eq!(
        table.receive_syn(21, tuple(50001), &other.segment(), 900),
        Err(Error::Capacity)
    );
    c.on_segment(&Packet::new(tuple(50000), repeated).segment(), 1)
        .unwrap();
    table
        .receive_segment(
            tuple(50000),
            &Packet::new(c.tuple, c.acknowledgment()).segment(),
            2,
        )
        .unwrap();
    assert_eq!(table.accept(LISTENER, OWNER), Ok(Some((20, tuple(50000)))));
}

#[test]
fn lost_syn_ack_and_lost_final_ack_recover_through_the_existing_active_engine() {
    let mut table = listening(4, config());
    let mut c = start(&mut table, 50000, 20, 100, 700);
    let first = table
        .get_mut(20, OWNER)
        .unwrap()
        .poll_transmit(0)
        .unwrap()
        .unwrap();
    assert!(!first.retransmission);
    assert!(
        table
            .get_mut(20, OWNER)
            .unwrap()
            .poll_transmit(9)
            .unwrap()
            .is_none()
    );
    let retry = table
        .get_mut(20, OWNER)
        .unwrap()
        .poll_transmit(10)
        .unwrap()
        .unwrap();
    assert!(retry.retransmission);
    c.on_segment(&Packet::new(tuple(50000), retry).segment(), 10)
        .unwrap();
    // Drop the first final ACK. A second SYN/ACK must elicit another ACK.
    let retry = table
        .get_mut(20, OWNER)
        .unwrap()
        .poll_transmit(30)
        .unwrap()
        .unwrap();
    assert_eq!(
        c.on_segment(&Packet::new(tuple(50000), retry).segment(), 30),
        Ok(Event::Acknowledge)
    );
    table
        .receive_segment(
            tuple(50000),
            &Packet::new(c.tuple, c.acknowledgment()).segment(),
            31,
        )
        .unwrap();
    assert_eq!(table.accept(LISTENER, OWNER), Ok(Some((20, tuple(50000)))));
}

#[test]
fn syn_text_is_queued_until_established_and_repeated_prefix_is_not_delivered_twice() {
    for (repeat, capacity) in [(false, 8192), (true, 8192), (false, 5)] {
        let mut cfg = config();
        cfg.receive_capacity = capacity;
        let mut table = listening(4, cfg);
        let t = tuple(50000);
        let syn = packet(reverse(t), 100, 0, SYN, b"early");
        table.receive_syn(20, t, &syn.segment(), 700).unwrap();
        table.receive_syn(21, t, &syn.segment(), 900).unwrap();
        let s = table.get_mut(20, OWNER).unwrap();
        assert_eq!(s.received_len(), 0);
        assert_eq!(s.receive(&mut [0; 32]), 0);
        let tx = s.poll_transmit(0).unwrap().unwrap();
        assert_eq!(tx.acknowledgment, 106);
        let ack = packet(
            reverse(t),
            if repeat { 101 } else { 106 },
            701,
            ACK,
            if repeat { b"early+new" } else { b"" },
        );
        table.receive_segment(t, &ack.segment(), 1).unwrap();
        table.accept(LISTENER, OWNER).unwrap().unwrap();
        let s = table.get_mut(20, OWNER).unwrap();
        let mut data = [0; 32];
        let n = s.receive(&mut data);
        assert_eq!(
            &data[..n],
            if repeat {
                b"early+new".as_slice()
            } else {
                b"early".as_slice()
            }
        );
        assert_eq!(s.receive_next, 101 + n as u32);
    }
}

#[test]
fn final_ack_may_carry_text_and_fin_before_the_connection_is_accepted() {
    let mut table = listening(4, config());
    let _c = start(&mut table, 50000, 20, 100, 700);
    table.get_mut(20, OWNER).unwrap().poll_transmit(0).unwrap();
    let ack = packet(reverse(tuple(50000)), 101, 701, ACK | FIN, b"bye");
    assert_eq!(
        table.receive_segment(tuple(50000), &ack.segment(), 1),
        Ok(Event::Acknowledge)
    );
    assert_eq!(table.accept(LISTENER, OWNER), Ok(Some((20, tuple(50000)))));
    let s = table.get_mut(20, OWNER).unwrap();
    assert_eq!(s.state, State::CloseWait);
    let mut data = [0; 8];
    assert_eq!(s.receive(&mut data), 3);
    assert_eq!(&data[..3], b"bye");
    assert_eq!(s.receive(&mut data), 0);
}

#[test]
fn invalid_ack_and_out_of_window_sequence_never_publish_a_completed_connection() {
    let mut table = listening(4, config());
    let _c = start(&mut table, 50000, 20, 100, 700);
    for ack in [0, 700, 702, u32::MAX] {
        let p = packet(reverse(tuple(50000)), 101, ack, ACK, &[]);
        assert_eq!(
            table.receive_segment(tuple(50000), &p.segment(), 1),
            Err(Error::InvalidAcknowledgment)
        );
        assert_eq!(table.get_mut(20, OWNER).unwrap().state, State::SynReceived);
        assert_eq!(table.accept(LISTENER, OWNER), Ok(None));
    }
    let p = packet(reverse(tuple(50000)), 101 + 8192, 701, ACK, &[]);
    assert_eq!(
        table.receive_segment(tuple(50000), &p.segment(), 1),
        Ok(Event::OutOfOrder)
    );
    assert_eq!(table.get_mut(20, OWNER).unwrap().state, State::SynReceived);
}

#[test]
fn reset_validation_and_retry_expiry_restore_pending_capacity_without_exposing_syn_text() {
    let mut cfg = config();
    cfg.backlog = 1;
    cfg.retry_limit = 0;
    let mut table = listening(2, cfg);
    let t = tuple(50000);
    let syn = packet(reverse(t), 100, 0, SYN, b"private");
    table.receive_syn(20, t, &syn.segment(), 700).unwrap();
    let forged = packet(reverse(t), 102, 0, RST, &[]);
    assert_eq!(
        table.receive_segment(t, &forged.segment(), 1),
        Err(Error::InvalidAcknowledgment)
    );
    assert_eq!(table.get_mut(20, OWNER).unwrap().state, State::SynReceived);
    let valid = packet(reverse(t), 108, 0, RST, &[]);
    assert_eq!(
        table.receive_segment(t, &valid.segment(), 1),
        Ok(Event::Reset)
    );
    assert_eq!(table.accept(LISTENER, OWNER), Ok(None));
    assert_eq!(table.len(), 0);
    table.receive_syn(21, t, &syn.segment(), 800).unwrap();
    let s = table.get_mut(21, OWNER).unwrap();
    s.poll_transmit(0).unwrap();
    assert_eq!(s.poll_transmit(10), Err(Error::RetryLimit));
    assert_eq!(s.received_len(), 0);
    assert_eq!(s.receive(&mut [0; 32]), 0);
    assert_eq!(table.accept(LISTENER, OWNER), Ok(None));
    assert_eq!(table.len(), 0);
    assert_eq!(table.receive_syn(22, t, &syn.segment(), 900), Ok(22));
}

#[test]
fn listener_ownership_wildcard_binding_and_close_preserve_accepted_connections() {
    let mut table = listening(8, config());
    assert_eq!(
        table.listen(11, OWNER, [10, 0, 2, 15], 8000, config()),
        Err(Error::PortUnavailable)
    );
    assert_eq!(
        table.listen(10, OWNER, [0; 4], 9000, config()),
        Err(Error::Capacity)
    );
    let mut c = start(&mut table, 50000, 20, 100, 700);
    complete(&mut table, 20, &mut c);
    assert_eq!(table.accept(LISTENER, OWNER + 1), Err(Error::Ownership));
    assert_eq!(table.accept(LISTENER, OWNER), Ok(Some((20, tuple(50000)))));
    let _pending = start(&mut table, 50001, 21, 200, 800);
    assert_eq!(
        table.close_listener(LISTENER, OWNER + 1),
        Err(Error::Ownership)
    );
    assert_eq!(table.listener_count(), 1);
    assert_eq!(table.len(), 2);
    table.close_listener(LISTENER, OWNER).unwrap();
    assert_eq!(table.listener_count(), 0);
    assert_eq!(table.len(), 1);
    assert!(matches!(table.get_mut(21, OWNER), Err(Error::NotFound)));
    table
        .get_mut(20, OWNER)
        .unwrap()
        .queue_send(b"still connected")
        .unwrap();
    assert_eq!(table.get_mut(20, OWNER + 1).err(), Some(Error::Ownership));
}

#[test]
fn completed_backlog_is_fifo_by_completion_instead_of_initial_syn_order() {
    let mut table = listening(8, config());
    let mut a = start(&mut table, 50000, 20, 100, 700);
    let mut b = start(&mut table, 50001, 21, 200, 800);
    complete(&mut table, 21, &mut b);
    complete(&mut table, 20, &mut a);
    assert_eq!(table.accept(LISTENER, OWNER), Ok(Some((21, tuple(50001)))));
    assert_eq!(table.accept(LISTENER, OWNER), Ok(Some((20, tuple(50000)))));
    assert_eq!(table.accept(LISTENER, OWNER), Ok(None));
}

#[test]
fn wrapped_sequences_zero_window_and_default_peer_mss_are_handled_without_overflow() {
    let mut cfg = config();
    cfg.receive_capacity = 0;
    let mut table = listening(3, cfg);
    let t = tuple(50000);
    let syn = packet(reverse(t), u32::MAX, 0, SYN, &[]);
    table.receive_syn(20, t, &syn.segment(), u32::MAX).unwrap();
    let s = table.get_mut(20, OWNER).unwrap();
    assert_eq!(s.peer_mss, 536);
    let tx = s.poll_transmit(0).unwrap().unwrap();
    assert_eq!(
        (tx.sequence, tx.acknowledgment, tx.window),
        (u32::MAX, 0, 0)
    );
    let bad = packet(reverse(t), 1, 0, ACK, &[]);
    assert_eq!(
        table.receive_segment(t, &bad.segment(), 1),
        Ok(Event::OutOfOrder)
    );
    let ack = packet(reverse(t), 0, 0, ACK, &[]);
    table.receive_segment(t, &ack.segment(), 1).unwrap();
    assert_eq!(table.accept(LISTENER, OWNER), Ok(Some((20, t))));
    assert_eq!(table.get_mut(20, OWNER).unwrap().send_unacknowledged, 0);
}

#[test]
fn total_capacity_identifiers_and_listener_ports_remain_bounded_and_disjoint() {
    let mut table = Table::new(2);
    let mut cfg = config();
    cfg.backlog = 0;
    assert_eq!(
        table.listen(10, OWNER, [0; 4], 8000, cfg),
        Err(Error::InvalidState)
    );
    table
        .listen(10, OWNER, [0; 4], tcp::TCP_EPHEMERAL_START, config())
        .unwrap();
    assert_ne!(table.allocate_port(0).unwrap(), tcp::TCP_EPHEMERAL_START);
    assert_ne!(table.allocate_handle(10).unwrap(), 10);
    assert_eq!(table.insert(client(tuple(50000), 100)), Ok(()));
    assert_eq!(
        table.listen(11, OWNER, [0; 4], 9000, config()),
        Err(Error::Capacity)
    );
    table.clear();
    assert!(table.is_empty());
    assert_eq!(table.listener_count(), 0);
}

#[test]
fn invalid_packet_shapes_do_not_allocate_or_promote_transport_state() {
    let mut table = listening(3, config());
    let t = tuple(50000);
    let source = packet(reverse(t), 100, 0, SYN, &[]);
    let large = vec![0; usize::from(u16::MAX)];
    for case in 0..6 {
        let mut segment = source.segment();
        match case {
            0 => segment.source_port = 0,
            1 => segment.destination_port += 1,
            2 => segment.urgent_pointer = 1,
            3 => segment.flags |= 0x200,
            4 => segment.payload = &large,
            _ => segment.flags |= FIN,
        }
        assert_eq!(
            table.receive_syn(20, t, &segment, 700),
            Err(Error::InvalidState)
        );
        assert_eq!(table.len(), 0);
    }
    table.receive_syn(20, t, &source.segment(), 700).unwrap();
    let ack = packet(reverse(t), 101, 701, ACK, &[]);
    let mut wrong = ack.segment();
    wrong.source_port += 1;
    assert_eq!(
        table.receive_segment(t, &wrong, 1),
        Err(Error::InvalidState)
    );
    assert_eq!(table.get_mut(20, OWNER).unwrap().state, State::SynReceived);
    assert_eq!(table.accept(LISTENER, OWNER), Ok(None));
}

#[test]
fn failed_buffer_admission_does_not_publish_a_connection_or_consume_backlog() {
    let syn = packet(reverse(tuple(50000)), 100, 0, SYN, &[]);
    for receive in [false, true] {
        let mut cfg = config();
        if receive {
            cfg.receive_capacity = usize::MAX;
        } else {
            cfg.send_capacity = usize::MAX;
        }
        let mut table = listening(3, cfg);
        assert_eq!(
            table.receive_syn(20, tuple(50000), &syn.segment(), 700),
            Err(Error::Capacity)
        );
        assert_eq!(table.len(), 0);
        assert_eq!(table.accept(LISTENER, OWNER), Ok(None));
        table.close_listener(LISTENER, OWNER).unwrap();
        table
            .listen(LISTENER, OWNER, [0; 4], 8000, config())
            .unwrap();
        assert_eq!(
            table.receive_syn(20, tuple(50000), &syn.segment(), 700),
            Ok(20)
        );
    }
}
