//! Exercise production TCP receive routing with real encoded packets. The
//! loopback fixture pumps packets, without replacing either TCP state machine.
use mochios_network_stack::{
    TCP_FLAG_ACK as ACK, TCP_FLAG_FIN as FIN, TCP_FLAG_RST as RST, TCP_FLAG_SYN as SYN,
    TcpConnection, TcpConnectionError as Error, TcpConnectionTable as Table, TcpDispatch,
    TcpListenConfig as Config, TcpOptions, TcpReceiveResult as Event, TcpSegment,
    TcpState as State, TcpTransmit as Tx, TcpTuple as Tuple,
};
use std::{cell::Cell, collections::VecDeque};

const SERVER: u64 = 11;
const CLIENT: u64 = 22;
const LISTENER: u64 = 1;
const ACTIVE: u64 = 2;
fn config() -> Config {
    Config {
        backlog: 2,
        local_mss: 4,
        send_capacity: 64,
        receive_capacity: 8,
        retransmit_timeout: 10,
        retry_limit: 2,
    }
}
fn tuple() -> Tuple {
    Tuple {
        local_address: [127, 0, 0, 2],
        local_port: 8000,
        remote_address: [127, 0, 0, 1],
        remote_port: 50000,
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
fn input(t: Tuple, seq: u32, ack: u32, flags: u16, data: &[u8]) -> TcpSegment<'_> {
    TcpSegment {
        source_port: t.remote_port,
        destination_port: t.local_port,
        sequence: seq,
        acknowledgment: ack,
        flags,
        window: 64,
        urgent_pointer: 0,
        options: TcpOptions::default(),
        payload: data,
    }
}
fn no_entropy() -> Option<u64> {
    panic!("entropy drawn without a new admissible passive open")
}
fn receive(table: &mut Table, t: Tuple, s: TcpSegment<'_>) -> TcpDispatch {
    table.receive_packet(t, &s, 1, no_entropy).unwrap()
}
fn listener(capacity: usize, c: Config) -> Table {
    let mut table = Table::new(capacity);
    table.listen(LISTENER, SERVER, [0; 4], 8000, c).unwrap();
    table
}
fn packet(t: Tuple, tx: &Tx) -> Vec<u8> {
    let mut bytes = vec![0; 60 + tx.payload.len()];
    let n = TcpSegment {
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
    bytes.truncate(n);
    bytes
}
struct Loopback {
    table: Table,
    draws: Cell<u32>,
}
impl Loopback {
    fn new() -> Self {
        let mut table = listener(8, config());
        table
            .insert(TcpConnection::connect(
                ACTIVE,
                CLIENT,
                reverse(tuple()),
                100,
                4,
                64,
                8,
                10,
                2,
            ))
            .unwrap();
        Self {
            table,
            draws: Cell::new(0),
        }
    }
    fn deliver(&mut self, t: Tuple, tx: &Tx, now: u64) -> TcpDispatch {
        let bytes = packet(t, tx);
        let s = TcpSegment::decode(t.local_address, t.remote_address, &bytes).unwrap();
        self.table
            .receive_packet(reverse(t), &s, now, || {
                self.draws.set(self.draws.get() + 1);
                Some(500u64 << 32 | 77)
            })
            .unwrap()
    }
    fn transmit(&mut self, id: u64, owner: u64, now: u64) -> Option<(Tuple, Tx)> {
        let c = self.table.get_mut(id, owner).unwrap();
        c.poll_transmit(now).unwrap().map(|tx| (c.tuple, tx))
    }
    fn pump(&mut self, first: (Tuple, Tx), now: u64) {
        let mut queue = VecDeque::from([first]);
        for _ in 0..32 {
            let Some((t, tx)) = queue.pop_front() else {
                return;
            };
            if let Some(reply) = self.deliver(t, &tx, now).reply {
                queue.push_back((reverse(t), reply));
            }
        }
        panic!("TCP control reply loop");
    }
    fn connect(&mut self) -> u64 {
        let syn = self.transmit(ACTIVE, CLIENT, 0).unwrap();
        self.pump(syn, 0);
        let (accepted, t) = self.table.accept(LISTENER, SERVER).unwrap().unwrap();
        assert_eq!(t, tuple());
        assert_eq!(self.table.accept(LISTENER, SERVER), Ok(None));
        assert_eq!(self.draws.get(), 1);
        accepted
    }
    fn send(&mut self, id: u64, owner: u64, data: &[u8], now: u64) {
        self.table
            .get_mut(id, owner)
            .unwrap()
            .queue_send(data)
            .unwrap();
        while let Some(tx) = self.transmit(id, owner, now) {
            self.pump(tx, now);
        }
    }
}

#[test]
fn closed_ports_reset_with_correct_sequence_lengths_without_reset_loops() {
    let mut table = Table::new(2);
    let t = tuple();
    for flags in [0, SYN, FIN, SYN | FIN] {
        let r = receive(&mut table, t, input(t, u32::MAX - 1, 99, flags, b"abc"));
        assert_eq!(r.connection, None);
        let tx = r.reply.unwrap();
        assert_eq!(tx.flags, RST | ACK);
        assert_eq!(tx.sequence, 0);
        assert_eq!(
            tx.acknowledgment,
            1 + u32::from(flags & SYN != 0) + u32::from(flags & FIN != 0)
        );
        assert!(tx.payload.is_empty());
        // Encode and return the response to prove the reset itself is silent.
        let bytes = packet(t, &tx);
        let s = TcpSegment::decode(t.local_address, t.remote_address, &bytes).unwrap();
        assert!(
            table
                .receive_packet(reverse(t), &s, 1, no_entropy)
                .unwrap()
                .reply
                .is_none()
        );
    }
    let r = receive(&mut table, t, input(t, 55, 987, ACK, b"data"));
    let tx = r.reply.unwrap();
    assert_eq!((tx.flags, tx.sequence, tx.acknowledgment), (RST, 987, 0));
    assert!(table.is_empty());
}

#[test]
fn listener_drops_resets_and_non_syn_data_but_resets_unexpected_acks() {
    let mut table = listener(4, config());
    let t = tuple();
    for flags in [RST, RST | ACK, 0, FIN, SYN | FIN] {
        let r = receive(&mut table, t, input(t, 100, 42, flags, b"x"));
        assert_eq!(
            r,
            TcpDispatch {
                connection: None,
                event: None,
                reply: None
            }
        );
    }
    for flags in [ACK, SYN | ACK, FIN | ACK] {
        let r = receive(&mut table, t, input(t, 100, 42, flags, b"x"));
        let tx = r.reply.unwrap();
        assert_eq!((tx.flags, tx.sequence), (RST, 42));
    }
    assert!(table.is_empty());
    assert_eq!(table.listener_count(), 1);
}

#[test]
fn nic_independent_loopback_stream_obeys_window_data_and_half_close() {
    let mut l = Loopback::new();
    let accepted = l.connect();
    assert_eq!(
        l.table.get_mut(accepted, CLIENT).err(),
        Some(Error::Ownership)
    );
    l.send(ACTIVE, CLIENT, b"abcdefghij", 1);
    assert_eq!(l.table.get_mut(accepted, SERVER).unwrap().received_len(), 8);
    assert_eq!(
        l.table.get_mut(ACTIVE, CLIENT).unwrap().queued_send_len(),
        2
    );
    let mut buffer = [0; 16];
    let c = l.table.get_mut(accepted, SERVER).unwrap();
    assert_eq!(c.receive(&mut buffer), 8);
    assert_eq!(&buffer[..8], b"abcdefgh");
    let update = (c.tuple, c.acknowledgment());
    l.pump(update, 2);
    let next = l.transmit(ACTIVE, CLIENT, 2).unwrap();
    l.pump(next, 2);
    assert_eq!(
        l.table
            .get_mut(accepted, SERVER)
            .unwrap()
            .receive(&mut buffer),
        2
    );
    assert_eq!(&buffer[..2], b"ij");
    l.table
        .get_mut(ACTIVE, CLIENT)
        .unwrap()
        .request_close()
        .unwrap();
    let fin = l.transmit(ACTIVE, CLIENT, 3).unwrap();
    l.pump(fin, 3);
    assert_eq!(
        l.table.get_mut(accepted, SERVER).unwrap().state,
        State::CloseWait
    );
    l.send(accepted, SERVER, b"reply", 4);
    assert_eq!(
        l.table
            .get_mut(ACTIVE, CLIENT)
            .unwrap()
            .receive(&mut buffer),
        5
    );
    assert_eq!(&buffer[..5], b"reply");
    l.table
        .get_mut(accepted, SERVER)
        .unwrap()
        .request_close()
        .unwrap();
    let fin = l.transmit(accepted, SERVER, 5).unwrap();
    l.pump(fin, 5);
    assert_eq!(
        l.table.get_mut(accepted, SERVER).unwrap().state,
        State::Closed
    );
    assert_eq!(
        l.table.get_mut(ACTIVE, CLIENT).unwrap().state,
        State::TimeWait
    );
}

#[test]
fn refused_connect_becomes_reset_instead_of_a_handshake_timeout() {
    let mut l = Loopback::new();
    l.table.close_listener(LISTENER, SERVER).unwrap();
    let syn = l.transmit(ACTIVE, CLIENT, 0).unwrap();
    l.pump(syn, 0);
    assert_eq!(l.table.get_mut(ACTIVE, CLIENT).unwrap().state, State::Reset);
    assert_eq!(l.draws.get(), 0);
}

#[test]
fn duplicate_syn_and_lost_final_ack_recover_without_new_entropy_or_accept() {
    let mut l = Loopback::new();
    let (t, syn) = l.transmit(ACTIVE, CLIENT, 0).unwrap();
    let first = l.deliver(t, &syn, 0);
    let passive = first.connection.unwrap();
    let syn_ack = first.reply.unwrap();
    let duplicate = l.deliver(t, &syn, 1);
    assert_eq!(duplicate.connection, Some(passive));
    assert_eq!(duplicate.reply.unwrap().sequence, syn_ack.sequence);
    let lost_ack = l.deliver(reverse(t), &syn_ack, 1).reply.unwrap();
    assert_eq!(lost_ack.flags, ACK);
    assert_eq!(l.table.accept(LISTENER, SERVER), Ok(None));
    let retry = l.transmit(passive, SERVER, 10).unwrap();
    assert!(retry.1.retransmission);
    l.pump(retry, 10);
    assert_eq!(
        l.table.accept(LISTENER, SERVER).unwrap().unwrap().0,
        passive
    );
    assert_eq!(l.table.accept(LISTENER, SERVER), Ok(None));
    assert_eq!(l.draws.get(), 1);
}

#[test]
fn entropy_failure_has_no_predictable_sequence_or_published_connection() {
    let mut table = listener(4, config());
    let t = tuple();
    let syn = input(t, 100, 0, SYN, &[]);
    assert_eq!(
        table.receive_packet(t, &syn, 0, || None),
        Err(Error::EntropyUnavailable)
    );
    assert!(table.is_empty());
    assert_eq!(table.accept(LISTENER, SERVER), Ok(None));
    let r = table
        .receive_packet(t, &syn, 0, || Some(777u64 << 32))
        .unwrap();
    assert_eq!(r.reply.unwrap().sequence, 777);
}

#[test]
fn backlog_flood_does_not_draw_entropy_and_expiry_releases_admission() {
    let mut c = config();
    c.backlog = 1;
    c.retry_limit = 0;
    let mut table = listener(8, c);
    let t = tuple();
    let first = table
        .receive_packet(t, &input(t, 10, 0, SYN, &[]), 20, || Some(88))
        .unwrap();
    let other = Tuple {
        remote_port: 50001,
        ..t
    };
    assert_eq!(
        table.receive_packet(other, &input(other, 10, 0, SYN, &[]), 21, no_entropy),
        Err(Error::Capacity)
    );
    let c = table.get_mut(first.connection.unwrap(), SERVER).unwrap();
    assert_eq!(c.poll_transmit(29), Ok(None));
    assert_eq!(c.poll_transmit(30), Err(Error::RetryLimit));
    let r = table
        .receive_packet(other, &input(other, 10, 0, SYN, &[]), 30, || Some(99))
        .unwrap();
    assert!(r.connection.is_some());
    assert_eq!(table.len(), 1);
}

#[test]
fn full_table_and_wrong_listener_address_never_draw_entropy() {
    let mut table = listener(1, config());
    let t = tuple();
    assert_eq!(
        table.receive_packet(t, &input(t, 10, 0, SYN, &[]), 1, no_entropy),
        Err(Error::Capacity)
    );
    let mut table = Table::new(4);
    table
        .listen(LISTENER, SERVER, [127, 0, 0, 3], 8000, config())
        .unwrap();
    assert_eq!(
        receive(&mut table, t, input(t, 10, 0, SYN, &[]))
            .reply
            .unwrap()
            .flags,
        RST | ACK
    );
    assert!(table.is_empty());
}

#[test]
fn excessive_syn_text_is_rejected_before_entropy_or_connection_publication() {
    let mut c = config();
    c.receive_capacity = 2;
    let mut table = listener(4, c);
    let t = tuple();
    assert_eq!(
        table.receive_packet(t, &input(t, 10, 0, SYN, b"abc"), 0, no_entropy),
        Err(Error::ReceiveBufferFull)
    );
    assert!(table.is_empty());
    let r = table
        .receive_packet(t, &input(t, 10, 0, SYN, b"ab"), 0, || Some(1))
        .unwrap();
    assert_eq!(r.reply.unwrap().window, 0);
}

#[test]
fn synchronized_resets_need_exact_sequence_and_clear_buffered_data() {
    let mut l = Loopback::new();
    let accepted = l.connect();
    l.send(ACTIVE, CLIENT, b"data", 1);
    for (seq, reply) in [(104, false), (106, true), (109, false)] {
        let r = receive(&mut l.table, tuple(), input(tuple(), seq, 0, RST, &[]));
        assert_eq!(r.reply.is_some(), reply);
        if let Some(tx) = r.reply {
            assert_eq!(tx.flags, ACK);
        }
        assert_eq!(
            l.table.get_mut(accepted, SERVER).unwrap().state,
            State::Established
        );
    }
    let r = receive(&mut l.table, tuple(), input(tuple(), 105, 0, RST, &[]));
    assert_eq!(r.event, Some(Event::Reset));
    assert!(r.reply.is_none());
    let c = l.table.get_mut(accepted, SERVER).unwrap();
    assert_eq!(c.state, State::Reset);
    assert_eq!(c.received_len(), 0);
}

#[test]
fn invalid_acks_get_state_appropriate_replies_without_releasing_send_data() {
    let mut l = Loopback::new();
    let active = reverse(tuple());
    for flags in [ACK, SYN | ACK, RST | ACK] {
        let r = receive(&mut l.table, active, input(active, 500, 999, flags, &[]));
        assert_eq!(r.reply.is_some(), flags & RST == 0);
        if let Some(tx) = r.reply {
            assert_eq!((tx.flags, tx.sequence), (RST, 999));
        }
        assert_eq!(
            l.table.get_mut(ACTIVE, CLIENT).unwrap().state,
            State::SynSent
        );
    }
    let accepted = l.connect();
    l.table
        .get_mut(accepted, SERVER)
        .unwrap()
        .queue_send(b"1234")
        .unwrap();
    l.transmit(accepted, SERVER, 1).unwrap();
    for (seq, ack, flags) in [(101, 999, ACK), (90, 505, ACK), (101, 505, 0)] {
        let r = receive(&mut l.table, tuple(), input(tuple(), seq, ack, flags, &[]));
        assert!(r.reply.as_ref().is_none_or(|tx| tx.flags == ACK));
        assert!(
            l.table
                .get_mut(accepted, SERVER)
                .unwrap()
                .has_unacknowledged()
        );
    }
    receive(&mut l.table, tuple(), input(tuple(), 101, 505, ACK, &[]));
    assert!(
        !l.table
            .get_mut(accepted, SERVER)
            .unwrap()
            .has_unacknowledged()
    );
}

#[test]
fn passive_invalid_acks_and_rst_challenges_never_retransmit_syn_ack() {
    let mut table = listener(4, config());
    let t = tuple();
    let r = table
        .receive_packet(t, &input(t, 100, 0, SYN, &[]), 0, || Some(500u64 << 32))
        .unwrap();
    let id = r.connection.unwrap();
    for (seq, ack, flags, expected) in [
        (101, 800, ACK, Some(RST)),
        (99, 501, ACK, Some(ACK)),
        (102, 0, RST, Some(ACK)),
        (99, 0, RST, None),
        (101, 0, 0, None),
    ] {
        let r = receive(&mut table, t, input(t, seq, ack, flags, &[]));
        assert_eq!(r.reply.map(|tx| tx.flags), expected);
        assert_eq!(table.get_mut(id, SERVER).unwrap().state, State::SynReceived);
        assert_eq!(table.accept(LISTENER, SERVER), Ok(None));
    }
    receive(&mut table, t, input(t, 101, 501, ACK, &[]));
    assert_eq!(table.accept(LISTENER, SERVER).unwrap().unwrap().0, id);
}

#[test]
fn input_validation_precedes_routing_or_entropy() {
    let mut table = listener(4, config());
    let t = tuple();
    let mut s = input(t, 100, 0, SYN, &[]);
    s.destination_port += 1;
    assert_eq!(
        table.receive_packet(t, &s, 0, no_entropy),
        Err(Error::InvalidState)
    );
    s.destination_port = t.local_port;
    s.urgent_pointer = 1;
    assert_eq!(
        table.receive_packet(t, &s, 0, no_entropy),
        Err(Error::InvalidState)
    );
    assert!(table.is_empty());
}

#[test]
fn non_unicast_endpoints_do_not_emit_resets_or_challenges() {
    let mut table = listener(4, config());
    for address in [[0; 4], [0, 1, 2, 3], [224, 0, 0, 1], [255; 4]] {
        for t in [
            Tuple {
                local_address: address,
                ..tuple()
            },
            Tuple {
                remote_address: address,
                ..tuple()
            },
        ] {
            for flags in [SYN, ACK, RST] {
                assert_eq!(
                    table.receive_packet(t, &input(t, 100, 501, flags, &[]), 0, no_entropy),
                    Err(Error::InvalidState)
                );
            }
        }
    }
    assert!(table.is_empty());
}

#[test]
fn syn_text_and_sequence_wrap_complete_with_zero_receive_window() {
    let mut c = config();
    c.receive_capacity = 3;
    let mut table = listener(4, c);
    let t = tuple();
    let r = table
        .receive_packet(t, &input(t, u32::MAX - 1, 0, SYN, b"abc"), 0, || {
            Some(u64::MAX)
        })
        .unwrap();
    let id = r.connection.unwrap();
    let tx = r.reply.unwrap();
    assert_eq!(
        (tx.sequence, tx.acknowledgment, tx.window),
        (u32::MAX, 2, 0)
    );
    assert_eq!(table.get_mut(id, SERVER).unwrap().received_len(), 0);
    // A nonempty final ACK cannot enter a zero window, even with a correct ACK.
    let r = receive(&mut table, t, input(t, 2, 0, ACK, b"d"));
    assert_eq!(r.reply.unwrap().flags, ACK);
    assert_eq!(table.accept(LISTENER, SERVER), Ok(None));
    // An empty ACK at RCV.NXT remains valid and publishes all queued SYN text.
    let r = receive(&mut table, t, input(t, 2, 0, ACK, &[]));
    assert_eq!(r.reply.unwrap().acknowledgment, 2);
    assert_eq!(table.accept(LISTENER, SERVER).unwrap().unwrap().0, id);
    let mut out = [0; 3];
    let c = table.get_mut(id, SERVER).unwrap();
    assert_eq!(c.receive(&mut out), 3);
    assert_eq!(&out, b"abc");
    assert_eq!(c.local_window(), 3);
}

#[test]
fn retained_reset_cannot_be_retargeted_when_same_tuple_reconnects() {
    let mut l = Loopback::new();
    let old = l.connect();
    receive(&mut l.table, tuple(), input(tuple(), 101, 0, RST, &[]));
    let r = l
        .table
        .receive_packet(tuple(), &input(tuple(), 200, 0, SYN, &[]), 1, || {
            Some(500u64 << 32 | 77)
        })
        .unwrap();
    assert_ne!(r.connection, Some(old));
    assert_eq!(l.table.get_mut(old, SERVER).unwrap().state, State::Reset);
    assert_eq!(
        l.table
            .get_mut(r.connection.unwrap(), SERVER)
            .unwrap()
            .state,
        State::SynReceived
    );
}
