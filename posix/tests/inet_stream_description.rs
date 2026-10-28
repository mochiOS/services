//! POSIX shared TCP policy over the production loopback transport. No fake
//! connection/data state machine; only native Handle ownership is an adapter.
extern crate alloc;
#[allow(dead_code)]
#[path = "../../network/src/stream.rs"]
mod transport;
use mochios_net_device_protocol::datagram::Endpoint as NativeEndpoint;
use mochios_posix_protocol::socket::{self as wire, Address};
use posix_service::inet_datagram::Endpoint;
use posix_service::inet_stream::{Backend, ConnectProgress as Progress, Observation, Stream};
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};

#[derive(Clone)]
struct Adapter {
    tcp: Rc<RefCell<transport::Loopback>>,
    closed: Rc<RefCell<Vec<transport::Socket>>>,
    bad_local: Rc<Cell<bool>>,
    zero_local: Rc<Cell<bool>>,
    bad_peer: Rc<Cell<bool>>,
    bad_error: Rc<Cell<bool>>,
    opens: Rc<Cell<usize>>,
}
impl Adapter {
    fn new() -> Self {
        Self {
            tcp: Rc::new(RefCell::new(transport::Loopback::new())),
            closed: Default::default(),
            bad_local: Default::default(),
            zero_local: Default::default(),
            bad_peer: Default::default(),
            bad_error: Default::default(),
            opens: Default::default(),
        }
    }
    fn drive(&self) {
        for _ in 0..64 {
            self.tcp
                .borrow_mut()
                .advance(0, || Some(0x1234_5678_90ab_cdef));
        }
    }
}
fn native(e: Endpoint) -> NativeEndpoint {
    NativeEndpoint {
        address: e.address,
        port: e.port,
    }
}
fn posix(e: NativeEndpoint) -> Endpoint {
    Endpoint {
        address: e.address,
        port: e.port,
    }
}
impl Backend for Adapter {
    type Handle = transport::Socket;
    fn open(&mut self) -> Result<Self::Handle, i32> {
        self.opens.set(self.opens.get() + 1);
        self.tcp.borrow_mut().open()
    }
    fn close(&mut self, h: Self::Handle) {
        self.closed.borrow_mut().push(h);
        self.tcp.borrow_mut().release(h, 0);
    }
    fn local(&mut self, h: Self::Handle) -> Result<Endpoint, i32> {
        let mut e = posix(self.tcp.borrow().local(h)?);
        if self.bad_local.get() {
            e.port = 0xe111;
        }
        if self.zero_local.get() {
            e.address = [0; 4];
        }
        Ok(e)
    }
    fn peer(&mut self, h: Self::Handle) -> Result<Endpoint, i32> {
        let mut e = posix(self.tcp.borrow_mut().peer(h)?);
        if self.bad_peer.get() {
            e.port = 0;
        }
        Ok(e)
    }
    fn bind(&mut self, h: Self::Handle, e: Endpoint) -> Result<(), i32> {
        self.tcp.borrow_mut().bind(h, native(e))
    }
    fn connect(&mut self, h: Self::Handle, e: Endpoint) -> Result<(), i32> {
        self.tcp
            .borrow_mut()
            .connect(h, native(e), || Some(500u64 << 32 | 7))
    }
    fn listen(&mut self, h: Self::Handle, b: usize) -> Result<(), i32> {
        self.tcp.borrow_mut().listen(h, b)
    }
    fn accept(&mut self, h: Self::Handle) -> Result<(Self, Self::Handle), i32> {
        let accepted = self.tcp.borrow_mut().accept(h)?;
        Ok((self.clone(), accepted))
    }
    fn observe(&mut self, h: Self::Handle) -> Result<Observation, i32> {
        let s = self.tcp.borrow_mut().status(h)?;
        Ok(Observation {
            readable: s.readable,
            writable: s.writable,
            peer_closed: s.peer_closed,
            connecting: s.connecting,
            error: s.error,
        })
    }
    fn take_error(&mut self, h: Self::Handle) -> Result<i32, i32> {
        let e = self.tcp.borrow_mut().take_error(h)?;
        Ok(if self.bad_error.get() { 0 } else { e })
    }
    fn send(&mut self, h: Self::Handle, b: &[u8]) -> Result<usize, i32> {
        self.tcp.borrow_mut().send(h, b)
    }
    fn receive(&mut self, h: Self::Handle, peek: bool, b: &mut [u8]) -> Result<usize, i32> {
        self.tcp.borrow_mut().receive(h, peek, b)
    }
    fn shutdown(&mut self, h: Self::Handle, r: bool, w: bool) -> Result<(), i32> {
        self.tcp.borrow_mut().shutdown(h, r, w)
    }
}
fn create() -> wire::Create {
    wire::Create {
        domain: wire::Domain::Ipv4,
        kind: wire::Kind::Stream,
        protocol: 0,
        options: 0,
    }
}
fn address(port: u16) -> Address<'static> {
    Address::Ipv4 {
        address: [127, 0, 0, 1],
        port,
    }
}
fn fresh(a: &Adapter) -> Stream<Adapter> {
    Stream::new(a.clone(), create()).unwrap()
}
fn pair(a: &Adapter) -> (Stream<Adapter>, Stream<Adapter>, Stream<Adapter>) {
    let mut listener = fresh(a);
    listener.bind(address(8000)).unwrap();
    listener.listen(4).unwrap();
    let mut client = fresh(a);
    assert_eq!(client.connect(address(8000)), Ok(Progress::Pending));
    a.drive();
    assert_eq!(
        client.connect_result(client.attempt()),
        Ok(Progress::Connected)
    );
    let accepted = listener.accept(wire::Accept { options: 0 }).unwrap();
    (listener, client, accepted)
}

#[test]
fn invalid_create_never_opens_a_resource_and_bad_publication_closes_once() {
    let a = Adapter::new();
    for mode in 0..4 {
        let mut c = create();
        match mode {
            0 => c.domain = wire::Domain::Unix,
            1 => c.kind = wire::Kind::Datagram,
            2 => c.protocol = 17,
            _ => c.options = 2,
        };
        assert!(Stream::new(a.clone(), c).is_err());
    }
    assert_eq!(a.opens.get(), 0);
    a.bad_local.set(true);
    assert!(Stream::new(a.clone(), create()).is_err());
    assert_eq!(a.closed.borrow().len(), 1);
}

#[test]
fn nonblocking_and_timeouts_belong_to_shared_description_not_fd_flags() {
    let a = Adapter::new();
    let mut s = fresh(&a);
    assert_eq!(s.options(), 0);
    s.set_options(wire::NONBLOCKING).unwrap();
    s.set_receive_timeout(123);
    s.set_send_timeout(456);
    assert_eq!(
        (s.options(), s.receive_timeout(), s.send_timeout()),
        (1, 123, 456)
    );
    assert_eq!(s.set_options(2), Err(-22));
    assert_eq!(s.options(), 1);
    s.bind(address(0)).unwrap();
    assert_ne!(s.local_address().unwrap().port, 0);
    assert_eq!(s.bind(address(9000)), Err(-22));
}

#[test]
fn pending_connect_readiness_completion_and_attempt_tags_are_distinct() {
    let a = Adapter::new();
    let mut listener = fresh(&a);
    listener.bind(address(8000)).unwrap();
    listener.listen(4).unwrap();
    let mut client = fresh(&a);
    assert_eq!(client.connect(address(8000)), Ok(Progress::Pending));
    let attempt = client.attempt();
    assert_eq!(client.connect_result(0), Err(-9));
    assert_eq!(client.connect_result(attempt + 1), Err(-9));
    assert_eq!(client.connect(address(8000)), Err(-114));
    assert_eq!(client.readiness(), Ok(0));
    assert_eq!(client.send(b"x"), Err(-11));
    a.drive();
    assert_eq!(client.connect_result(attempt), Ok(Progress::Connected));
    assert_eq!(client.connect(address(8000)), Err(-106));
    assert_eq!(client.peer_address().unwrap().port, 8000);
    assert_ne!(client.readiness().unwrap() & wire::READY_WRITE, 0);
}

#[test]
fn queued_data_peek_and_zero_length_reads_do_not_create_eof() {
    let a = Adapter::new();
    let (_, mut client, mut server) = pair(&a);
    assert_eq!(client.send(b"hello"), Ok(5));
    a.drive();
    let mut b = [0; 8];
    assert_eq!(server.receive(false, &mut []), Ok(0));
    assert_eq!(server.readiness().unwrap() & wire::READ_CLOSED, 0);
    assert_eq!(server.receive(true, &mut b[..2]), Ok(2));
    assert_eq!(&b[..2], b"he");
    assert_eq!(server.receive(false, &mut b), Ok(5));
    assert_eq!(&b[..5], b"hello");
    assert_eq!(server.receive(false, &mut b), Err(-11));
}

#[test]
fn half_close_has_read_eof_without_disabling_reverse_writes() {
    let a = Adapter::new();
    let (_, mut client, mut server) = pair(&a);
    client.send(b"tail").unwrap();
    client.shutdown(wire::SHUTDOWN_WRITE).unwrap();
    a.drive();
    let mut b = [0; 8];
    assert_eq!(server.receive(false, &mut b), Ok(4));
    assert_eq!(server.receive(false, &mut b), Ok(0));
    let ready = server.readiness().unwrap();
    assert_ne!(ready & wire::READ_CLOSED, 0);
    assert_eq!(ready & wire::WRITE_CLOSED, 0);
    assert_eq!(client.send(b"bad"), Err(-32));
    assert_eq!(server.send(b"reply"), Ok(5));
    a.drive();
    assert_eq!(client.receive(false, &mut b), Ok(5));
}

#[test]
fn so_error_is_consumed_once_but_a_started_connect_retains_its_failure() {
    let a = Adapter::new();
    let mut client = fresh(&a);
    assert_eq!(client.connect(address(9000)), Ok(Progress::Pending));
    let attempt = client.attempt();
    a.drive();
    assert_eq!(client.connect_result(attempt), Err(-111));
    assert_ne!(client.readiness().unwrap() & wire::ERROR_PENDING, 0);
    assert_eq!(client.take_error(), Ok(111));
    assert_eq!(client.take_error(), Ok(0));
    assert_eq!(client.connect_result(attempt), Err(-111));
    assert_eq!(client.readiness().unwrap() & wire::ERROR_PENDING, 0);
    assert_eq!(client.receive(false, &mut [0; 1]), Ok(0));
    assert_eq!(client.send(b"x"), Err(-32));
}

#[test]
fn io_consumes_a_pending_reset_without_rearming_it_from_the_backend() {
    let a = Adapter::new();
    let (_, mut client, server) = pair(&a);
    client.send(b"unread").unwrap();
    a.drive();
    drop(server);
    a.drive();
    assert_eq!(client.receive(false, &mut [0; 1]), Err(-104));
    assert_eq!(client.take_error(), Ok(0));
    assert_eq!(client.receive(false, &mut [0; 1]), Ok(0));
    assert_eq!(client.send(b"x"), Err(-32));
}

#[test]
fn accept_uses_requested_nonblocking_flag_and_independent_description_lifetime() {
    let a = Adapter::new();
    let mut listener = fresh(&a);
    listener.set_options(wire::NONBLOCKING).unwrap();
    listener.set_receive_timeout(123);
    listener.set_send_timeout(456);
    listener.bind(address(8000)).unwrap();
    listener.listen(0).unwrap();
    let mut client = fresh(&a);
    client.connect(address(8000)).unwrap();
    a.drive();
    let mut server = listener.accept(wire::Accept { options: 0 }).unwrap();
    assert_eq!(
        (
            server.options(),
            server.receive_timeout(),
            server.send_timeout()
        ),
        (0, 123, 456)
    );
    let local = server.local_address().unwrap();
    drop(listener);
    client.send(b"data").unwrap();
    a.drive();
    assert_eq!(server.receive(false, &mut [0; 4]), Ok(4));
    assert_eq!(server.local_address(), Ok(local));
}

#[test]
fn malformed_accepted_peer_closes_only_provisional_connection() {
    let a = Adapter::new();
    let mut listener = fresh(&a);
    listener.bind(address(8000)).unwrap();
    listener.listen(4).unwrap();
    let mut client = fresh(&a);
    client.connect(address(8000)).unwrap();
    a.drive();
    a.bad_peer.set(true);
    assert!(listener.accept(wire::Accept { options: 0 }).is_err());
    assert_eq!(a.closed.borrow().len(), 1);
    a.bad_peer.set(false);
    assert!(listener.accepting());
    assert!(listener.local_address().is_ok());
}

#[test]
fn malformed_error_consumption_cannot_promote_a_failed_connect() {
    let a = Adapter::new();
    let mut client = fresh(&a);
    client.connect(address(9000)).unwrap();
    let attempt = client.attempt();
    a.drive();
    a.bad_error.set(true);
    assert_eq!(client.connect_result(attempt), Err(-5));
    a.bad_error.set(false);
    assert_eq!(client.connect_result(attempt), Err(-5));
    assert_eq!(client.take_error(), Ok(5));
}

#[test]
fn successful_lower_connect_with_mismatched_peer_is_never_published() {
    let a = Adapter::new();
    let mut listener = fresh(&a);
    listener.bind(address(8000)).unwrap();
    listener.listen(4).unwrap();
    let mut client = fresh(&a);
    client.connect(address(8000)).unwrap();
    let attempt = client.attempt();
    a.drive();
    a.bad_peer.set(true);
    assert_eq!(client.connect_result(attempt), Err(-5));
    a.bad_peer.set(false);
    assert_eq!(client.connect_result(attempt), Err(-5));
}

#[test]
fn final_drop_closes_exact_owned_transport_reference_once() {
    let a = Adapter::new();
    let s = fresh(&a);
    let h = s.binding_handle();
    assert!(a.closed.borrow().is_empty());
    drop(s);
    assert_eq!(a.closed.borrow().as_slice(), &[h]);
}

#[test]
fn unspecified_local_address_cannot_publish_established_connection() {
    let a = Adapter::new();
    let mut listener = fresh(&a);
    listener.bind(address(8000)).unwrap();
    listener.listen(4).unwrap();
    let mut client = fresh(&a);
    client.connect(address(8000)).unwrap();
    let attempt = client.attempt();
    a.drive();
    a.zero_local.set(true);
    assert_eq!(client.connect_result(attempt), Err(-5));
    a.zero_local.set(false);
    assert_eq!(client.connect_result(attempt), Err(-5));
}
