//! Production network-service TCP resources; no fake stream or socket engine.
extern crate alloc;
#[allow(dead_code)]
mod backend {
    include!("../../network/src/stream.rs");

    fn endpoint(port: u16) -> Endpoint {
        Endpoint {
            address: [127, 0, 0, 1],
            port,
        }
    }
    fn listener(b: &mut Transport, port: u16, backlog: usize) -> Socket {
        let socket = b.open().unwrap();
        b.bind(socket, endpoint(port)).unwrap();
        b.listen(socket, backlog).unwrap();
        socket
    }
    fn entropy() -> Option<u64> {
        Some(0xffff_ffff_1111_2222)
    }
    fn advance(b: &mut Transport) {
        for _ in 0..64 {
            assert!(b.advance(0, entropy) <= PUMP_BUDGET);
        }
    }
    fn pair(b: &mut Transport) -> (Socket, Socket, Socket) {
        let listener = listener(b, 8000, 4);
        let client = b.open().unwrap();
        b.connect(client, endpoint(8000), entropy).unwrap();
        assert!(b.status(client).unwrap().connecting);
        assert_eq!(b.accept(listener), Err(-11));
        advance(b);
        assert!(b.status(listener).unwrap().readable);
        let accepted = b.accept(listener).unwrap();
        assert!(!b.status(listener).unwrap().readable);
        assert!(b.status(client).unwrap().writable);
        assert!(!b.status(client).unwrap().connecting);
        (listener, client, accepted)
    }

    #[test]
    fn endpoint_binding_is_exclusive_and_ephemeral_ports_are_reserved_before_listen() {
        let mut b = Transport::new();
        let a = b.open().unwrap();
        let c = b.open().unwrap();
        b.bind(
            a,
            Endpoint {
                address: [0; 4],
                port: 8000,
            },
        )
        .unwrap();
        assert_eq!(b.bind(c, endpoint(8000)), Err(-98));
        assert_eq!(
            b.bind(
                c,
                Endpoint {
                    address: [192, 0, 2, 1],
                    port: 9000
                }
            ),
            Err(-99)
        );
        b.bind(c, endpoint(0)).unwrap();
        let local = b.local(c).unwrap();
        assert!(local.port >= TCP_EPHEMERAL_START);
        let d = b.open().unwrap();
        assert_eq!(b.bind(d, local), Err(-98));
        b.release(c, 0);
        b.bind(d, local).unwrap();
        assert_eq!(b.bind(a, endpoint(8001)), Err(-22));
    }

    #[test]
    fn connect_and_accept_preserve_exact_peer_and_local_endpoints() {
        let mut b = Transport::new();
        let (_, client, accepted) = pair(&mut b);
        assert_eq!(b.peer(client).unwrap(), b.local(accepted).unwrap());
        assert_eq!(b.peer(accepted).unwrap(), b.local(client).unwrap());
        assert_eq!(b.send(client, b"hello"), Ok(5));
        advance(&mut b);
        let mut out = [0; 5];
        assert_eq!(b.receive(accepted, true, &mut out), Ok(5));
        assert_eq!(&out, b"hello");
        assert_eq!(b.receive(accepted, false, &mut out), Ok(5));
        assert_eq!(b.receive(accepted, false, &mut out), Err(-11));
        assert_eq!(b.send(accepted, b"reply"), Ok(5));
        advance(&mut b);
        assert_eq!(b.receive(client, false, &mut out), Ok(5));
        assert_eq!(&out, b"reply");
    }

    #[test]
    fn short_writes_backpressure_and_draining_window_update_resume_the_sender() {
        let mut b = Transport::new();
        let (_, client, accepted) = pair(&mut b);
        let first = vec![1; BUFFER + 17];
        assert_eq!(b.send(client, &first), Ok(BUFFER));
        assert_eq!(b.send(client, b"x"), Err(-11));
        assert!(!b.status(client).unwrap().writable);
        advance(&mut b);
        assert!(b.status(accepted).unwrap().readable);
        assert_eq!(b.send(client, &vec![2; BUFFER]), Ok(BUFFER));
        advance(&mut b);
        assert!(!b.status(client).unwrap().writable);
        let mut out = vec![0; BUFFER];
        assert_eq!(b.receive(accepted, true, &mut out), Ok(BUFFER));
        assert!(out.iter().all(|byte| *byte == 1));
        advance(&mut b);
        assert!(!b.status(client).unwrap().writable);
        assert_eq!(b.receive(accepted, false, &mut out), Ok(BUFFER));
        advance(&mut b);
        assert!(b.status(client).unwrap().writable);
        assert_eq!(b.receive(accepted, false, &mut out), Ok(BUFFER));
        assert!(out.iter().all(|byte| *byte == 2));
    }

    #[test]
    fn shutdown_write_delivers_queued_data_before_eof_and_preserves_reverse_direction() {
        let mut b = Transport::new();
        let (_, client, accepted) = pair(&mut b);
        b.send(client, b"tail").unwrap();
        b.shutdown(client, false, true).unwrap();
        b.shutdown(client, false, true).unwrap();
        assert_eq!(b.send(client, b"x"), Err(-32));
        advance(&mut b);
        let mut out = [0; 8];
        assert_eq!(b.receive(accepted, false, &mut out), Ok(4));
        assert_eq!(&out[..4], b"tail");
        assert_eq!(b.receive(accepted, false, &mut out), Ok(0));
        assert!(b.status(accepted).unwrap().peer_closed);
        assert_eq!(b.send(accepted, b"reply"), Ok(5));
        advance(&mut b);
        assert_eq!(b.receive(client, false, &mut out), Ok(5));
        assert_eq!(&out[..5], b"reply");
    }

    #[test]
    fn shutdown_read_discards_text_but_keeps_advertising_receive_space() {
        let mut b = Transport::new();
        let (_, client, accepted) = pair(&mut b);
        b.shutdown(accepted, true, false).unwrap();
        for _ in 0..3 {
            assert_eq!(b.send(client, &vec![7; BUFFER]), Ok(BUFFER));
            advance(&mut b);
            assert!(b.status(client).unwrap().writable);
            let mut out = [0; 8];
            assert_eq!(b.receive(accepted, false, &mut out), Ok(0));
            assert_eq!(out, [0; 8]);
        }
        assert_eq!(b.send(accepted, b"reply"), Ok(5));
    }

    #[test]
    fn refused_connect_keeps_observable_error_until_release_without_rearming_take_error() {
        let mut b = Transport::new();
        let c = b.open().unwrap();
        b.connect(c, endpoint(9999), entropy).unwrap();
        advance(&mut b);
        let status = b.status(c).unwrap();
        assert!(status.readable && status.writable && status.peer_closed);
        assert!(!status.connecting);
        assert_eq!(status.error, -111);
        assert_eq!(b.take_error(c), Ok(-111));
        assert_eq!(b.take_error(c), Ok(0));
        advance(&mut b);
        assert_eq!(b.status(c).unwrap().error, 0);
        assert_eq!(b.receive(c, false, &mut [0; 1]), Err(-111));
        assert_eq!(b.rows.len(), 1);
        b.release(c, 0);
        assert_eq!(b.status(c), Err(-9));
    }

    #[test]
    fn backlog_is_recovered_after_accept_without_drawing_entropy_for_refused_syns() {
        let mut b = Transport::new();
        let listener = listener(&mut b, 8000, 1);
        let a = b.open().unwrap();
        let c = b.open().unwrap();
        b.connect(a, endpoint(8000), entropy).unwrap();
        b.connect(c, endpoint(8000), entropy).unwrap();
        let mut draws = 0;
        b.advance(0, || {
            draws += 1;
            entropy()
        });
        assert_eq!(draws, 1);
        assert!(b.status(a).unwrap().writable);
        assert!(b.status(c).unwrap().connecting);
        b.accept(listener).unwrap();
        b.advance(500, || {
            draws += 1;
            entropy()
        });
        assert_eq!(draws, 2);
        assert!(b.status(c).unwrap().writable);
        b.accept(listener).unwrap();
        assert_eq!(b.accept(listener), Err(-11));
    }

    #[test]
    fn listener_backlog_updates_do_not_drop_established_unaccepted_connections() {
        let mut b = Transport::new();
        let listener = listener(&mut b, 8000, 2);
        let a = b.open().unwrap();
        let c = b.open().unwrap();
        b.connect(a, endpoint(8000), entropy).unwrap();
        b.connect(c, endpoint(8000), entropy).unwrap();
        advance(&mut b);
        b.listen(listener, 1).unwrap();
        b.accept(listener).unwrap();
        b.accept(listener).unwrap();
        assert_eq!(b.listen(listener, 0), Err(-22));
    }

    #[test]
    fn releasing_listener_preserves_accepted_connections() {
        let mut b = Transport::new();
        let (listener, client, accepted) = pair(&mut b);
        b.release(listener, 0);
        assert_eq!(b.status(listener), Err(-9));
        b.send(client, b"data").unwrap();
        advance(&mut b);
        let mut out = [0; 4];
        assert_eq!(b.receive(accepted, false, &mut out), Ok(4));
        assert_eq!(&out, b"data");
    }

    #[test]
    fn releasing_listener_resets_established_but_unaccepted_connections() {
        let mut b = Transport::new();
        let listener = listener(&mut b, 8000, 4);
        let client = b.open().unwrap();
        b.connect(client, endpoint(8000), entropy).unwrap();
        advance(&mut b);
        assert!(b.status(client).unwrap().writable);
        b.release(listener, 0);
        advance(&mut b);
        assert_eq!(b.status(client).unwrap().error, -104);
        assert_eq!(b.table.listener_count(), 0);
    }

    #[test]
    fn resource_capacity_failure_does_not_consume_a_ready_accept() {
        let mut b = Transport::new();
        let listener = listener(&mut b, 8000, 4);
        let client = b.open().unwrap();
        b.connect(client, endpoint(8000), entropy).unwrap();
        advance(&mut b);
        let mut last = client;
        for _ in 2..RESOURCE_LIMIT {
            last = b.open().unwrap();
        }
        assert_eq!(b.accept(listener), Err(-24));
        assert!(b.status(listener).unwrap().readable);
        b.release(last, 0);
        b.accept(listener).unwrap();
        assert!(!b.status(listener).unwrap().readable);
    }

    #[test]
    fn graceful_release_keeps_fin_state_but_invalidates_resource_immediately() {
        let mut b = Transport::new();
        let (listener, client, accepted) = pair(&mut b);
        b.release(client, 0);
        assert_eq!(b.send(client, b"x"), Err(-9));
        advance(&mut b);
        assert_eq!(b.receive(accepted, false, &mut [0; 1]), Ok(0));
        b.release(accepted, 0);
        advance(&mut b);
        b.advance(CLOSE_TIMEOUT, entropy);
        assert_eq!(b.rows.len(), 1);
        assert_eq!(b.table.len(), 0);
        b.release(listener, CLOSE_TIMEOUT);
        assert!(b.rows.is_empty());
    }

    #[test]
    fn unread_text_on_release_resets_peer_and_retained_handle_does_not_change_identity() {
        let mut b = Transport::new();
        let (_, client, accepted) = pair(&mut b);
        b.send(client, b"unread").unwrap();
        advance(&mut b);
        b.release(accepted, 0);
        advance(&mut b);
        assert_eq!(b.status(client).unwrap().error, -104);
        let replacement = b.open().unwrap();
        assert_ne!(replacement, accepted);
        assert_eq!(b.local(accepted), Err(-9));
    }

    #[test]
    fn abandoned_fin_wait_is_bounded_and_does_not_leak_the_local_port() {
        let mut b = Transport::new();
        let (_, client, accepted) = pair(&mut b);
        let old = b.local(client).unwrap();
        b.release(client, 0);
        advance(&mut b);
        let replacement = b.open().unwrap();
        assert_eq!(b.bind(replacement, old), Err(-98));
        b.advance(CLOSE_TIMEOUT, entropy);
        advance(&mut b);
        assert_eq!(b.status(accepted).unwrap().error, -104);
        b.bind(replacement, old).unwrap();
    }

    #[test]
    fn pending_connection_retry_expiry_is_timeout_not_connection_refused() {
        let mut b = Transport::new();
        let c = b.open().unwrap();
        b.connect(c, endpoint(9999), entropy).unwrap();
        let Binding::Connection { tcp, owner } = b.rows[0].binding else {
            panic!()
        };
        // Drop every actual SYN without replacing TCP's retry accounting.
        for now in [0, 500, 1500, 3500, 7500, 15500] {
            assert!(
                b.table
                    .get_mut(tcp, owner)
                    .unwrap()
                    .poll_transmit(now)
                    .unwrap()
                    .is_some()
            );
        }
        b.advance(31500, entropy);
        assert_eq!(b.status(c).unwrap().error, -110);
        assert_eq!(b.take_error(c), Ok(-110));
        b.advance(32000, entropy);
        assert_eq!(b.take_error(c), Ok(0));
    }

    #[test]
    fn entropy_failure_and_bad_remote_leave_unbound_resource_retryable() {
        let mut b = Transport::new();
        let c = b.open().unwrap();
        assert_eq!(b.connect(c, endpoint(8000), || None), Err(-5));
        assert_eq!(b.local(c), Ok(EMPTY));
        assert_eq!(b.peer(c), Err(-107));
        assert_eq!(
            b.connect(
                c,
                Endpoint {
                    address: [192, 0, 2, 1],
                    port: 8000
                },
                || panic!()
            ),
            Err(-101)
        );
        b.connect(c, endpoint(8000), entropy).unwrap();
    }

    #[test]
    fn bounded_resources_are_recovered_without_reusing_socket_ids() {
        let mut b = Transport::new();
        let mut sockets = Vec::new();
        for _ in 0..RESOURCE_LIMIT {
            sockets.push(b.open().unwrap());
        }
        assert_eq!(b.open(), Err(-24));
        let old = sockets.pop().unwrap();
        b.release(old, 0);
        let new = b.open().unwrap();
        assert_ne!(old, new);
        assert_eq!(b.local(old), Err(-9));
        for socket in sockets {
            b.release(socket, 0);
        }
        b.release(new, 0);
        assert!(b.rows.is_empty());
    }

    #[test]
    fn packet_budget_returns_with_queue_intact_and_does_not_starve_other_resource_operations() {
        let mut b = Transport::new();
        let (_, client, accepted) = pair(&mut b);
        for _ in 0..QUEUE_LIMIT {
            let Binding::Connection { tcp, owner } = b.rows[b.index(client).unwrap()].binding
            else {
                panic!()
            };
            let c = b.table.get_mut(tcp, owner).unwrap();
            let mut tx = c.acknowledgment();
            tx.sequence = tx.sequence.wrapping_sub(10);
            b.pending.push_back(Packet {
                tuple: c.tuple,
                transmit: tx,
                origin: Some(tcp),
            });
        }
        assert_eq!(b.advance(0, entropy), PUMP_BUDGET);
        assert!(!b.pending.is_empty());
        assert!(b.pending.len() <= QUEUE_LIMIT);
        let unrelated = b.open().unwrap();
        b.bind(unrelated, endpoint(9000)).unwrap();
        assert_eq!(b.local(unrelated).unwrap().port, 9000);
        assert!(b.status(accepted).is_ok());
    }

    #[test]
    fn active_connection_storage_failure_is_reported_without_allocation_panic() {
        let tuple = TcpTuple {
            local_address: [127, 0, 0, 1],
            local_port: 8000,
            remote_address: [127, 0, 0, 2],
            remote_port: 9000,
        };
        assert_eq!(
            TcpConnection::try_connect(1, 2, tuple, 100, 1460, usize::MAX, 1, 10, 2).err(),
            Some(TcpConnectionError::Capacity)
        );
        assert_eq!(
            TcpConnection::try_connect(1, 2, tuple, 100, 1460, 1, usize::MAX, 10, 2).err(),
            Some(TcpConnectionError::Capacity)
        );
    }

    #[test]
    fn listener_observation_and_backlog_mutation_check_owner_before_any_cleanup() {
        let mut b = Transport::new();
        let listener = listener(&mut b, 8000, 4);
        let client = b.open().unwrap();
        b.connect(client, endpoint(8000), entropy).unwrap();
        advance(&mut b);
        let Binding::Listener(tcp) = b.rows[b.index(listener).unwrap()].binding else {
            panic!()
        };
        for c in b.table.connections_mut() {
            if c.owner == listener.0 {
                c.abort();
            }
        }
        let retained = b.table.len();
        assert_eq!(
            b.table.listener_ready(tcp, listener.0 + 100),
            Err(TcpConnectionError::Ownership)
        );
        assert_eq!(
            b.table.set_backlog(tcp, listener.0 + 100, 1),
            Err(TcpConnectionError::Ownership)
        );
        assert_eq!(b.table.len(), retained);
        assert_eq!(b.table.listener_ready(tcp, listener.0), Ok(false));
        assert_eq!(b.table.len(), retained - 1);
    }
}
