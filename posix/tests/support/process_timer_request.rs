use super::*;
use posix_service::{
    process_timer::Samples,
    process_timer_request::{ClockBackend, Reading},
};
use protocol::process_timer::{self as wire, Clock, Notification, Value};
use std::{cell::Cell, rc::Rc};

struct Clocks {
    samples: Samples,
    reads: Vec<(u32, Clock)>,
    fail: bool,
    exec: bool,
}
thread_local! {
    static CLOCKS: RefCell<Clocks> = const { RefCell::new(Clocks {
        samples: Samples { realtime_ns: 1_000, monotonic_ns: 10, process_cpu_ns: 2 },
        reads: Vec::new(), fail: false, exec: false,
    }) };
}
impl ClockBackend<u32> for RecordingProcesses {
    fn timer_clock(&mut self, process: u32, clock: Clock) -> Result<Reading, i32> {
        CLOCKS.with(|control| {
            let mut control = control.borrow_mut();
            control.reads.push((process, clock));
            if control.fail {
                return Err(protocol::STATUS_EIO);
            }
            if control.exec {
                control.exec = false;
                self.images.insert(
                    process,
                    Ok(mnu_abi::ProcessStatus {
                        process_id: self
                            .identities
                            .get(&process)
                            .copied()
                            .unwrap_or(u64::from(process)),
                        state: mnu_abi::PROCESS_STATE_RUNNING,
                        image_revision: 1,
                        ..Default::default()
                    }),
                );
            }
            Ok(match clock {
                Clock::Realtime => Reading::Realtime(control.samples.realtime_ns),
                Clock::Monotonic => Reading::Counter(control.samples.monotonic_ns),
                Clock::ProcessCpu => Reading::Counter(control.samples.process_cpu_ns),
            })
        })
    }
}
struct Environment {
    service: PosixService,
    processes: RecordingProcesses,
}
struct TimerTransport {
    peer: PeerIdentity,
    environment: Rc<RefCell<Environment>>,
    bad_reply: Cell<u32>,
    closed: RefCell<Vec<u32>>,
}
impl Transport for TimerTransport {
    type Error = ();
    fn call(&self, _: &[u8], _: &mut [u8]) -> Result<usize, ()> {
        panic!("timer controls must inspect received Handles")
    }
}
impl ObjectTransport for TimerTransport {
    type Handle = u32;
    fn close_received_handle(&self, handle: u32) {
        self.closed.borrow_mut().push(handle);
    }
    fn call_with_handles(
        &self,
        input: &[u8],
        output: &mut [u8],
        handles: &mut ObjectHandles<u32>,
    ) -> Result<usize, ()> {
        let (header, payload) = protocol::decode(input).map_err(|_| ())?;
        assert!(handles.is_empty());
        let mut environment = self.environment.borrow_mut();
        let Environment { service, processes } = &mut *environment;
        service
            .refresh_image_state(self.peer, processes)
            .map_err(|_| ())?;
        let image = service.capture_request_image(self.peer).unwrap();
        let mut reply = service
            .handle_process_timer_request(self.peer, image, header, payload, &[], processes)
            .response;
        match self.bad_reply.get() {
            1 => {
                for _ in 0..2 {
                    handles
                        .push(ObjectHandleAttachment {
                            handle: 71,
                            rights: 1,
                        })
                        .unwrap();
                }
            }
            2 => {
                reply.payload = vec![0; 8];
            }
            3 => {
                reply.payload = vec![0; 7];
            }
            4 => {
                reply.payload = u32::MAX.to_le_bytes().to_vec();
            }
            _ => {}
        }
        reply.header.payload_len = reply.payload.len() as u32;
        protocol::encode(reply.header, &reply.payload, output).map_err(|_| ())
    }
}
fn setup() -> (Client<TimerTransport>, Rc<RefCell<Environment>>) {
    CLOCKS.with(|control| {
        *control.borrow_mut() = Clocks {
            samples: Samples {
                realtime_ns: 1_000,
                monotonic_ns: 10,
                process_cpu_ns: 2,
            },
            reads: Vec::new(),
            fail: false,
            exec: false,
        };
    });
    let peer = PeerIdentity {
        process_id: 2901,
        effective_uid: 501,
        effective_gid: 20,
    };
    let environment = Rc::new(RefCell::new(Environment {
        service: service_for(peer),
        processes: RecordingProcesses::default(),
    }));
    let transport = TimerTransport {
        peer,
        environment: environment.clone(),
        bad_reply: Cell::new(0),
        closed: RefCell::new(Vec::new()),
    };
    (Client::new(transport), environment)
}

#[test]
fn timer_client_and_service_exchange_canonical_frames_and_select_only_needed_owner_clocks() {
    let (client, _) = setup();
    let id = client
        .timer_create(Clock::Realtime, Notification::None)
        .unwrap();
    assert_eq!(
        client
            .timer_set(
                id,
                false,
                Value {
                    remaining_ns: 20,
                    interval_ns: 7
                }
            )
            .unwrap(),
        Value::default()
    );
    assert_eq!(client.timer_value(id).unwrap().remaining_ns, 20);
    CLOCKS.with(|c| assert_eq!(c.borrow().reads, vec![(2901, Clock::Monotonic); 2]));
    CLOCKS.with(|c| c.borrow_mut().reads.clear());
    let previous = client
        .timer_set(
            id,
            true,
            Value {
                remaining_ns: 1_020,
                interval_ns: 0,
            },
        )
        .unwrap();
    assert_eq!(previous.remaining_ns, 20);
    CLOCKS.with(|c| {
        assert_eq!(
            c.borrow().reads,
            vec![(2901, Clock::Monotonic), (2901, Clock::Realtime)]
        )
    });
    assert_eq!(client.timer_value(id).unwrap().remaining_ns, 20);
    assert_eq!(client.timer_overrun(id), Ok(0));
    let cpu = client
        .timer_create(Clock::ProcessCpu, Notification::None)
        .unwrap();
    CLOCKS.with(|c| c.borrow_mut().reads.clear());
    client
        .timer_set(
            cpu,
            false,
            Value {
                remaining_ns: 5,
                interval_ns: 0,
            },
        )
        .unwrap();
    CLOCKS.with(|c| assert_eq!(c.borrow().reads, vec![(2901, Clock::ProcessCpu)]));
    client.timer_delete(id).unwrap();
    assert_eq!(
        client.timer_value(id),
        Err(ClientError::Remote(STATUS_EINVAL))
    );
}

#[test]
fn timer_codec_rejects_noncanonical_versions_reserved_bytes_modes_and_duration_widths() {
    let mut create = [0; wire::CREATE_LEN];
    wire::encode_create(Clock::Monotonic, Notification::None, &mut create).unwrap();
    for index in [0, 2, 4, 8, 12, 16] {
        let mut bad = create;
        bad[index] = 255;
        assert!(wire::decode_create(&bad).is_err());
    }
    for count in 0..wire::CREATE_LEN {
        assert!(wire::decode_create(&create[..count]).is_err());
    }
    let mut set = [0; wire::SET_LEN];
    let maximum = Value {
        remaining_ns: wire::MAX_DURATION_NS,
        interval_ns: wire::MAX_DURATION_NS,
    };
    wire::encode_set(71, true, maximum, &mut set).unwrap();
    assert_eq!(wire::decode_set(&set).unwrap(), (71, true, maximum));
    for index in [8, 12, 31, 47] {
        let mut bad = set;
        bad[index] = 255;
        assert!(wire::decode_set(&bad).is_err());
    }
    assert!(wire::encode_set(0, false, maximum, &mut set).is_err());
    assert!(wire::decode_id(&[0; 8]).is_err());
}

#[test]
fn failed_clock_observation_and_exec_during_observation_never_commit_a_replacement() {
    let (client, environment) = setup();
    let id = client
        .timer_create(Clock::Monotonic, Notification::None)
        .unwrap();
    client
        .timer_set(
            id,
            false,
            Value {
                remaining_ns: 20,
                interval_ns: 0,
            },
        )
        .unwrap();
    CLOCKS.with(|c| c.borrow_mut().fail = true);
    assert_eq!(
        client.timer_set(
            id,
            false,
            Value {
                remaining_ns: 99,
                interval_ns: 1
            }
        ),
        Err(ClientError::Remote(protocol::STATUS_EIO))
    );
    CLOCKS.with(|c| c.borrow_mut().fail = false);
    assert_eq!(client.timer_value(id).unwrap().remaining_ns, 20);
    CLOCKS.with(|c| c.borrow_mut().exec = true);
    assert_eq!(
        client.timer_set(
            id,
            false,
            Value {
                remaining_ns: 99,
                interval_ns: 1
            }
        ),
        Err(ClientError::Remote(protocol::STATUS_ESRCH))
    );
    assert_eq!(
        client.timer_value(id),
        Err(ClientError::Remote(STATUS_EINVAL))
    );
    assert_eq!(
        environment.borrow().processes.image_reads.last(),
        Some(&2901)
    );
}

#[test]
fn unrepresentable_old_value_cannot_commit_a_replacement_with_an_error_reply() {
    let (client, _) = setup();
    let id = client
        .timer_create(Clock::Realtime, Notification::None)
        .unwrap();
    client
        .timer_set(
            id,
            true,
            Value {
                remaining_ns: wire::MAX_DURATION_NS,
                interval_ns: 0,
            },
        )
        .unwrap();
    CLOCKS.with(|c| c.borrow_mut().samples.realtime_ns = -1);
    assert_eq!(
        client.timer_set(
            id,
            false,
            Value {
                remaining_ns: 5,
                interval_ns: 0
            }
        ),
        Err(ClientError::Remote(posix_service::STATUS_EOVERFLOW))
    );
    CLOCKS.with(|c| c.borrow_mut().samples.realtime_ns = 1_000);
    assert_eq!(
        client.timer_value(id).unwrap().remaining_ns,
        wire::MAX_DURATION_NS - 1_000
    );
}

#[test]
fn unavailable_async_delivery_is_explicit_instead_of_successfully_silent() {
    let (client, _) = setup();
    for notification in [
        Notification::Default,
        Notification::Signal {
            signal: protocol::SIGNAL_ALRM,
            value: 17,
        },
        Notification::Thread { cookie: 1 },
    ] {
        assert_eq!(
            client.timer_create(Clock::Monotonic, notification),
            Err(ClientError::Remote(protocol::STATUS_ENOSYS))
        );
    }
    // A rejected notification must not reserve an ID or slot.
    assert_eq!(
        client.timer_create(Clock::Monotonic, Notification::None),
        Ok(1)
    );
}

#[test]
fn malformed_or_object_carrying_scalar_replies_are_rejected_and_new_references_closed_once() {
    let (client, _) = setup();
    client.transport().bad_reply.set(1);
    assert_eq!(
        client.timer_create(Clock::Monotonic, Notification::None),
        Err(ClientError::MismatchedResponse)
    );
    assert_eq!(*client.transport().closed.borrow(), vec![71]);
    for bad in [2, 3] {
        client.transport().bad_reply.set(bad);
        assert!(matches!(
            client.timer_create(Clock::Monotonic, Notification::None),
            Err(ClientError::Protocol(_))
        ));
    }
    client.transport().bad_reply.set(0);
    let id = client
        .timer_create(Clock::Monotonic, Notification::None)
        .unwrap();
    client.transport().bad_reply.set(4);
    assert!(matches!(
        client.timer_overrun(id),
        Err(ClientError::Protocol(_))
    ));
}

#[test]
fn request_envelope_attachments_and_foreign_timer_ids_cannot_mutate_state() {
    let (mut service, root, parent, _, _, mut processes) = orphan_family();
    let id = service
        .process_timers(parent)
        .unwrap()
        .create(Clock::Monotonic, Notification::None)
        .unwrap();
    let image = service.capture_request_image(root).unwrap();
    let header = protocol::Header {
        opcode: protocol::OP_TIMER_DELETE,
        request_id: 17,
        payload_len: 8,
        ..Default::default()
    };
    let payload = id.raw().to_le_bytes();
    assert_eq!(
        service
            .handle_process_timer_request(parent, image, header, &payload, &[], &mut processes,)
            .response
            .header
            .status,
        protocol::STATUS_EPERM
    );
    let reply =
        service.handle_process_timer_request(root, image, header, &payload, &[], &mut processes);
    assert_eq!(reply.response.header.status, STATUS_EINVAL);
    for case in 0..4 {
        let mut header = header;
        match case {
            0 => header.flags = 1,
            1 => header.status = 1,
            2 => header.payload_len = 0,
            _ => {}
        }
        let attached = [AttachedObject {
            handle: 77,
            rights: mnu_abi::HANDLE_RIGHT_TRANSFER,
        }];
        let attachments = if case == 3 { &attached[..] } else { &[] };
        let image = service.capture_request_image(parent).unwrap();
        let reply = service.handle_process_timer_request(
            parent,
            image,
            header,
            &payload,
            attachments,
            &mut processes,
        );
        assert_eq!(reply.response.header.status, STATUS_EINVAL);
    }
    assert_eq!(
        service.process_timers(parent).unwrap().clock(id),
        Ok(Clock::Monotonic)
    );
    let mut unknown = header;
    unknown.opcode = 0x7fff;
    let image = service.capture_request_image(parent).unwrap();
    assert_eq!(
        service
            .handle_process_timer_request(parent, image, unknown, &payload, &[], &mut processes)
            .response
            .header
            .status,
        protocol::STATUS_ENOSYS
    );
}
