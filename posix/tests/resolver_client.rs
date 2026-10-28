use mochios_net_device_protocol::resolver as w;
use mochios_posix_client::{
    ClientError, ObjectHandleAttachment as Object, ObjectHandles, ObjectTransport, Transport,
    resolver as client,
};
use std::cell::{Cell, RefCell};
const NAME: &[u8] = b"\x07example\x03com\0";
fn name() -> w::Name<'static> {
    w::Name::decode(NAME).unwrap()
}
fn limits() -> w::Limits {
    w::Limits {
        scopes: w::ALL_SCOPES,
        maximum_timeout: w::MAX_TIMEOUT,
    }
}
#[derive(Clone, Copy)]
enum Mode {
    Valid,
    Remote,
    Transport,
    Alias,
    Duplicate,
    WrongRights,
    Null,
    Short,
}
struct Endpoint {
    mode: Mode,
    calls: RefCell<Vec<(u16, Vec<Object<u32>>)>>,
    closed: RefCell<Vec<u32>>,
}
impl Endpoint {
    fn new(mode: Mode) -> Self {
        Self {
            mode,
            calls: RefCell::new(Vec::new()),
            closed: RefCell::new(Vec::new()),
        }
    }
}
impl Transport for Endpoint {
    type Error = i32;
    fn call(&self, _: &[u8], _: &mut [u8]) -> Result<usize, i32> {
        panic!("objects must use explicit attachment path")
    }
}
impl ObjectTransport for Endpoint {
    type Handle = u32;
    fn close_received_handle(&self, h: u32) {
        self.closed.borrow_mut().push(h);
    }
    fn call_with_handles(
        &self,
        request: &[u8],
        out: &mut [u8],
        handles: &mut ObjectHandles<u32>,
    ) -> Result<usize, i32> {
        let op = w::operation(request).unwrap();
        self.calls
            .borrow_mut()
            .push((op, handles.iter().collect()));
        let source = handles.get(0).map(|h| h.handle);
        handles.clear();
        let rights = if op == w::OPEN {
            client::JOB_RIGHTS
        } else {
            client::FACTORY_RIGHTS
        };
        let h = if matches!(self.mode, Mode::Alias) {
            source.unwrap_or(7)
        } else {
            100
        };
        let count = if matches!(self.mode, Mode::Duplicate) {
            2
        } else if op == w::VALIDATE && matches!(self.mode, Mode::Valid) {
            0
        } else {
            1
        };
        for _ in 0..count {
            handles
                .push(Object {
                    handle: if matches!(self.mode, Mode::Null) {
                        0
                    } else {
                        h
                    },
                    rights: if matches!(self.mode, Mode::WrongRights) {
                        rights | mnu_abi::HANDLE_RIGHT_WRITE
                    } else {
                        rights
                    },
                })
                .unwrap();
        }
        w::reply(
            op,
            if matches!(self.mode, Mode::Remote) {
                -13
            } else {
                0
            },
            out,
        )
        .unwrap();
        if matches!(self.mode, Mode::Transport) {
            return Err(-5);
        }
        Ok(if matches!(self.mode, Mode::Short) {
            8
        } else {
            w::REPLY_LEN
        })
    }
}
fn factory() -> Object<u32> {
    Object {
        handle: 7,
        rights: client::FACTORY_RIGHTS,
    }
}

#[test]
fn acquisition_derivation_validation_and_start_use_exact_attenuated_attachments() {
    let t = Endpoint::new(Mode::Valid);
    assert_eq!(
        client::acquire(&t, limits()).unwrap(),
        Object {
            handle: 100,
            rights: client::FACTORY_RIGHTS
        }
    );
    client::derive(
        &t,
        factory(),
        w::Limits {
            scopes: w::A_SCOPE,
            maximum_timeout: 100,
        },
    )
    .unwrap();
    client::validate(&t, factory()).unwrap();
    assert_eq!(
        client::start(&t, factory(), w::Kind::Ptr, name(), 100)
            .unwrap()
            .rights,
        client::JOB_RIGHTS
    );
    let calls = t.calls.borrow();
    assert_eq!(calls[0], (w::ACQUIRE, vec![]));
    for (_, objects) in &calls[1..] {
        assert_eq!(
            objects,
            &[Object {
                handle: 7,
                rights: mnu_abi::HANDLE_RIGHT_CONTROL
            }]
        );
    }
    assert!(t.closed.borrow().is_empty());
}

#[test]
fn malformed_error_and_extra_handle_replies_close_only_distinct_received_objects() {
    for mode in [
        Mode::Remote,
        Mode::Transport,
        Mode::Duplicate,
        Mode::WrongRights,
        Mode::Null,
        Mode::Short,
    ] {
        let t = Endpoint::new(mode);
        assert!(client::start(&t, factory(), w::Kind::A, name(), 100).is_err());
        assert_eq!(
            *t.closed.borrow(),
            if matches!(mode, Mode::Null) {
                vec![]
            } else {
                vec![100]
            }
        );
    }
    let t = Endpoint::new(Mode::Alias);
    assert!(matches!(
        client::derive(&t, factory(), limits()),
        Err(ClientError::MismatchedResponse)
    ));
    assert!(t.closed.borrow().is_empty());
    let t = Endpoint::new(Mode::WrongRights);
    assert!(client::validate(&t, factory()).is_err());
    assert_eq!(*t.closed.borrow(), [100]);
}

#[test]
fn invalid_authority_or_request_is_rejected_before_invoking_the_endpoint() {
    let t = Endpoint::new(Mode::Valid);
    for f in [
        Object {
            handle: 0,
            rights: client::FACTORY_RIGHTS,
        },
        Object {
            handle: 7,
            rights: mnu_abi::HANDLE_RIGHT_READ,
        },
    ] {
        assert!(matches!(
            client::start(&t, f, w::Kind::A, name(), 100),
            Err(ClientError::Remote(-13))
        ));
    }
    assert!(client::start(&t, factory(), w::Kind::A, name(), 0).is_err());
    assert!(
        client::acquire(
            &t,
            w::Limits {
                scopes: 0,
                ..limits()
            }
        )
        .is_err()
    );
    assert!(t.calls.borrow().is_empty());
}

struct Io {
    snapshot: Vec<u8>,
    observation: w::Observation,
    reads: RefCell<Vec<(u64, usize)>>,
    chunk: usize,
    early_eof: bool,
    overcount: bool,
    cancel: u32,
    error: Cell<bool>,
}
impl Io {
    fn new(status: i32, count: usize) -> Self {
        let mut bytes = vec![0; w::MAX_RESULT_LEN];
        let values = vec![&[1; 16][..]; count];
        let n = if status == 0 {
            w::encode_result(
                w::Kind::Aaaa,
                0,
                name(),
                Some(name()),
                false,
                core::iter::empty(),
                values.into_iter(),
                &mut bytes,
            )
            .unwrap()
        } else {
            w::encode_failure(w::Kind::Aaaa, status, name(), &mut bytes).unwrap()
        };
        bytes.truncate(n);
        Self {
            snapshot: bytes,
            observation: w::Observation {
                kind: w::Kind::Aaaa,
                ready: true,
                status,
                length: n as u64,
            },
            reads: RefCell::new(Vec::new()),
            chunk: 37,
            early_eof: false,
            overcount: false,
            cancel: 1,
            error: Cell::new(false),
        }
    }
}
impl client::Io<u32> for Io {
    type Error = i32;
    fn query(&self, h: u32, tag: u64, out: &mut [u8]) -> Result<usize, i32> {
        assert_eq!((h, tag), (33, w::STATUS));
        if self.error.get() {
            return Err(-5);
        }
        Ok(self.observation.encode(out).unwrap())
    }
    fn control(&self, h: u32, tag: u64, out: &mut [u8]) -> Result<usize, i32> {
        assert_eq!(h, 33);
        if tag == w::QUERY_LIMITS {
            return Ok(limits().encode(out).unwrap());
        }
        assert_eq!(tag, w::CANCEL);
        out.copy_from_slice(&self.cancel.to_le_bytes());
        Ok(4)
    }
    fn read_at(&self, h: u32, offset: u64, out: &mut [u8]) -> Result<usize, i32> {
        assert_eq!(h, 33);
        assert!(out.len() <= 4096);
        self.reads.borrow_mut().push((offset, out.len()));
        if self.overcount {
            return Ok(out.len() + 1);
        }
        if self.early_eof && offset != 0 {
            return Ok(0);
        }
        let start = offset as usize;
        let n = (self.snapshot.len() - start).min(out.len()).min(self.chunk);
        out[..n].copy_from_slice(&self.snapshot[start..start + n]);
        Ok(n)
    }
}

#[test]
fn positioned_reads_reconstruct_large_results_and_can_be_repeated() {
    let io = Io::new(0, 1024);
    let mut out = vec![0; io.snapshot.len()];
    for _ in 0..2 {
        let view = client::snapshot(&io, 33, w::Kind::Aaaa, name(), &mut out).unwrap();
        assert_eq!(view.values().len(), 1024);
        assert_eq!(view.status, 0);
    }
    let reads = io.reads.borrow();
    assert!(reads.len() > 100);
    assert_eq!(reads.iter().filter(|(offset, _)| *offset == 0).count(), 2);
    assert_eq!(client::limits(&io, 33).unwrap(), limits());
    assert!(client::cancel(&io, 33).unwrap());
}

#[test]
fn pending_wrong_type_and_short_output_do_not_read_snapshot_bytes() {
    let mut io = Io::new(0, 1);
    let mut out = [0; 512];
    io.observation.ready = false;
    io.observation.length = 0;
    assert!(matches!(
        client::snapshot(&io, 33, w::Kind::Aaaa, name(), &mut out),
        Err(ClientError::Remote(-11))
    ));
    io.observation.ready = true;
    io.observation.length = io.snapshot.len() as u64;
    assert!(matches!(
        client::snapshot(&io, 33, w::Kind::A, name(), &mut out),
        Err(ClientError::MismatchedResponse)
    ));
    assert!(matches!(
        client::snapshot(&io, 33, w::Kind::Aaaa, name(), &mut []),
        Err(ClientError::ResponseTooLarge)
    ));
    assert!(io.reads.borrow().is_empty());
}

#[test]
fn short_reads_overcounts_wrong_identity_and_corruption_never_return_partial_success() {
    for mode in 0..5 {
        let mut io = Io::new(0, 10);
        let mut out = vec![0; io.snapshot.len()];
        match mode {
            0 => io.early_eof = true,
            1 => io.overcount = true,
            2 => io.snapshot[12..16].copy_from_slice(&(-6i32).to_le_bytes()),
            3 => io.snapshot[41] = b'z',
            _ => io.snapshot[39] = 1,
        }
        assert!(matches!(
            client::snapshot(&io, 33, w::Kind::Aaaa, name(), &mut out),
            Err(ClientError::MismatchedResponse)
        ));
    }
    let io = Io::new(0, 1);
    io.error.set(true);
    assert!(matches!(
        client::observe(&io, 33),
        Err(ClientError::Transport(-5))
    ));
}

#[test]
fn resolver_failure_is_distinct_from_native_handle_failure_and_cancel_is_canonical() {
    let mut io = Io::new(-6, 0);
    let mut out = [0; 512];
    let view = client::snapshot(&io, 33, w::Kind::Aaaa, name(), &mut out).unwrap();
    assert_eq!(view.status, -6);
    assert!(view.canonical.is_none());
    assert_eq!(view.values().len(), 0);
    io.cancel = 0;
    assert!(!client::cancel(&io, 33).unwrap());
    io.cancel = 2;
    assert!(matches!(
        client::cancel(&io, 33),
        Err(ClientError::MismatchedResponse)
    ));
}
