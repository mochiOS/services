use super::*;
use posix_service::{
    process_timer::Samples,
    process_timer_request::{ClockBackend, Reading},
};
use protocol::process_timer::{self as wire, Clock, Notification, Value};
use std::{cell::Cell, rc::Rc};

#[path = "process_timer_delivery.rs"]
mod delivery;
#[path = "process_timer_wait.rs"]
mod wait;

struct Clocks {
    samples: Samples,
    reads: Vec<(u32, Clock)>,
    fail: bool,
    fail_clock: Option<Clock>,
    fail_owner: Option<u32>,
    exec: bool,
}
thread_local! {
    static CLOCKS: RefCell<Clocks> = const { RefCell::new(Clocks {
        samples: Samples { realtime_ns: 1_000, monotonic_ns: 10, process_cpu_ns: 2 },
        reads: Vec::new(), fail: false, fail_clock: None, fail_owner: None, exec: false,
    }) };
}
impl ClockBackend<u32> for RecordingProcesses {
    fn timer_clock(&mut self, process: u32, clock: Clock) -> Result<Reading, i32> {
        CLOCKS.with(|control| {
            let mut control = control.borrow_mut();
            control.reads.push((process, clock));
            if control.fail
                || control.fail_clock == Some(clock)
                || control.fail_owner == Some(process)
            {
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
            fail_clock: None,
            fail_owner: None,
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

fn arm_internal(
    service: &mut PosixService,
    peer: PeerIdentity,
    clock: Clock,
    notification: Notification,
    initial: u128,
    interval: u128,
    absolute: bool,
) -> posix_service::process_timer::TimerId {
    let mut timers = service.process_timers(peer).unwrap();
    let id = timers.create(clock, notification).unwrap();
    timers
        .set(
            id,
            Samples {
                realtime_ns: 0,
                monotonic_ns: 0,
                process_cpu_ns: 0,
            },
            initial,
            interval,
            absolute,
        )
        .unwrap();
    id
}

#[test]
fn reactor_observes_without_client_rpc_and_keeps_equal_signals_separate() {
    let (client, environment) = setup();
    let peer = client.transport().peer;
    let mut environment = environment.borrow_mut();
    let Environment { service, processes } = &mut *environment;
    let mut ids = Vec::new();
    for notification in [
        Notification::Signal {
            signal: protocol::SIGNAL_ALRM,
            value: 17,
        },
        Notification::Signal {
            signal: protocol::SIGNAL_ALRM,
            value: 18,
        },
        Notification::Thread { cookie: 19 },
    ] {
        ids.push(arm_internal(
            service,
            peer,
            Clock::Monotonic,
            notification,
            10,
            10,
            false,
        ));
    }
    assert!(service.has_observable_process_timers());
    assert_eq!(service.observe_process_timers(processes), Ok(3));
    CLOCKS.with(|c| assert_eq!(c.borrow().reads, vec![(2901, Clock::Monotonic)]));
    let mask = 1u64 << (protocol::SIGNAL_ALRM - 1);
    let pending: Vec<_> = service
        .process_timers(peer)
        .unwrap()
        .pending_signals(mask)
        .collect();
    assert_eq!(pending.len(), 2);
    assert_ne!(pending[0].timer, pending[1].timer);
    assert!(
        service
            .process_timers(peer)
            .unwrap()
            .pending_signals(0)
            .next()
            .is_none()
    );
    CLOCKS.with(|c| c.borrow_mut().samples.monotonic_ns = 35);
    assert_eq!(service.observe_process_timers(processes), Ok(3));
    let mut timers = service.process_timers(peer).unwrap();
    let all: Vec<_> = timers.pending_notifications().collect();
    assert_eq!(all.len(), 3);
    assert!(all.iter().all(|pending| pending.overrun() == 2));
    let accepted = timers
        .accept(
            pending[0],
            Samples {
                realtime_ns: 1_000,
                monotonic_ns: 39,
                process_cpu_ns: 2,
            },
        )
        .unwrap();
    assert_eq!(accepted.overrun(), 2);
    assert_eq!(timers.pending_signals(mask).count(), 1);
    assert_eq!(timers.pending_notifications().count(), 2);
    assert_eq!(timers.clock(ids[2]), Ok(Clock::Monotonic));
}

#[test]
fn reactor_clock_failure_leaves_its_timer_unconsumed_but_advances_other_clocks() {
    let (client, environment) = setup();
    let peer = client.transport().peer;
    let mut environment = environment.borrow_mut();
    let Environment { service, processes } = &mut *environment;
    let real = arm_internal(
        service,
        peer,
        Clock::Realtime,
        Notification::Default,
        1_000,
        10,
        true,
    );
    let mono = arm_internal(
        service,
        peer,
        Clock::Monotonic,
        Notification::Default,
        10,
        10,
        false,
    );
    CLOCKS.with(|c| c.borrow_mut().fail_clock = Some(Clock::Realtime));
    assert_eq!(
        service.observe_process_timers(processes),
        Err(protocol::STATUS_EIO)
    );
    let pending: Vec<_> = service
        .process_timers(peer)
        .unwrap()
        .pending_notifications()
        .collect();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].timer, mono);
    CLOCKS.with(|c| {
        c.borrow_mut().fail_clock = None;
        c.borrow_mut().samples.realtime_ns = 1_020;
    });
    assert_eq!(service.observe_process_timers(processes), Ok(2));
    let pending: Vec<_> = service
        .process_timers(peer)
        .unwrap()
        .pending_notifications()
        .collect();
    let real_pending = pending
        .iter()
        .find(|pending| pending.timer == real)
        .unwrap();
    assert_eq!(real_pending.overrun(), 2); // Failed 1000 was not consumed.
    assert_eq!(
        pending
            .iter()
            .find(|pending| pending.timer == mono)
            .unwrap()
            .overrun(),
        0
    );
}

#[test]
fn reactor_failure_for_one_owner_does_not_sample_the_service_or_block_another_owner() {
    let _ = setup();
    let (mut service, root, parent, _, _, mut processes) = orphan_family();
    let root_timer = arm_internal(
        &mut service,
        root,
        Clock::ProcessCpu,
        Notification::Default,
        1,
        1,
        false,
    );
    let parent_timer = arm_internal(
        &mut service,
        parent,
        Clock::ProcessCpu,
        Notification::Default,
        1,
        1,
        false,
    );
    CLOCKS.with(|c| c.borrow_mut().fail_owner = Some(140));
    assert_eq!(
        service.observe_process_timers(&mut processes),
        Err(protocol::STATUS_EIO)
    );
    assert_eq!(
        service
            .process_timers(root)
            .unwrap()
            .pending_notifications()
            .count(),
        0
    );
    let pending: Vec<_> = service
        .process_timers(parent)
        .unwrap()
        .pending_notifications()
        .collect();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].timer, parent_timer);
    CLOCKS.with(|c| {
        assert_eq!(
            c.borrow().reads,
            vec![(140, Clock::ProcessCpu), (141, Clock::ProcessCpu)]
        );
        c.borrow_mut().fail_owner = None;
    });
    assert_eq!(service.observe_process_timers(&mut processes), Ok(2));
    let pending: Vec<_> = service
        .process_timers(root)
        .unwrap()
        .pending_notifications()
        .collect();
    assert_eq!(pending[0].timer, root_timer);
    assert_eq!(pending[0].overrun(), 1);
}

#[test]
fn reactor_revalidates_each_image_after_samples_and_does_not_revive_old_plan_entries() {
    let _ = setup();
    let (mut service, root, parent, _, _, mut processes) = orphan_family();
    let id = arm_internal(
        &mut service,
        root,
        Clock::ProcessCpu,
        Notification::Default,
        1,
        1,
        false,
    );
    let other = arm_internal(
        &mut service,
        parent,
        Clock::ProcessCpu,
        Notification::Default,
        1,
        1,
        false,
    );
    CLOCKS.with(|c| c.borrow_mut().exec = true);
    assert_eq!(
        service.observe_process_timers(&mut processes),
        Err(protocol::STATUS_ESRCH)
    );
    assert_eq!(
        service.process_timers(root).unwrap().clock(id),
        Err(STATUS_EINVAL)
    );
    assert_eq!(
        service
            .process_timers(root)
            .unwrap()
            .pending_notifications()
            .count(),
        0
    );
    let pending: Vec<_> = service
        .process_timers(parent)
        .unwrap()
        .pending_notifications()
        .collect();
    assert_eq!(pending[0].timer, other);
    assert_eq!(service.observe_process_timers(&mut processes), Ok(1));
}

#[test]
fn reactor_discards_a_preexisting_exec_plan_before_reading_any_old_timer_clock() {
    let (client, environment) = setup();
    let peer = client.transport().peer;
    let mut environment = environment.borrow_mut();
    let Environment { service, processes } = &mut *environment;
    let id = arm_internal(
        service,
        peer,
        Clock::Monotonic,
        Notification::Default,
        10,
        10,
        false,
    );
    processes.images.insert(
        2901,
        Ok(mnu_abi::ProcessStatus {
            process_id: 2901,
            state: mnu_abi::PROCESS_STATE_RUNNING,
            image_revision: 1,
            ..Default::default()
        }),
    );
    assert_eq!(service.observe_process_timers(processes), Ok(0));
    assert_eq!(
        service.process_timers(peer).unwrap().clock(id),
        Err(STATUS_EINVAL)
    );
    assert!(!service.has_observable_process_timers());
    CLOCKS.with(|c| assert!(c.borrow().reads.is_empty()));
}

#[test]
fn interleaved_owner_ids_remain_searchable_after_middle_deletion_and_image_retirement() {
    let _ = setup();
    let (mut service, root, parent, child, _, mut processes) = orphan_family();
    let a = arm_internal(
        &mut service,
        root,
        Clock::ProcessCpu,
        Notification::Default,
        1,
        1,
        false,
    );
    let removed = arm_internal(
        &mut service,
        parent,
        Clock::Monotonic,
        Notification::Default,
        1,
        1,
        false,
    );
    let b = arm_internal(
        &mut service,
        child,
        Clock::Realtime,
        Notification::Default,
        1_000,
        10,
        true,
    );
    let c = arm_internal(
        &mut service,
        root,
        Clock::Monotonic,
        Notification::Default,
        10,
        10,
        false,
    );
    let d = arm_internal(
        &mut service,
        child,
        Clock::ProcessCpu,
        Notification::Default,
        1,
        1,
        false,
    );
    service
        .process_timers(parent)
        .unwrap()
        .delete(removed)
        .unwrap();
    let e = arm_internal(
        &mut service,
        parent,
        Clock::ProcessCpu,
        Notification::Default,
        1,
        1,
        false,
    );
    assert_eq!(service.observe_process_timers(&mut processes), Ok(5));
    for (owner, id, clock) in [
        (root, a, Clock::ProcessCpu),
        (child, b, Clock::Realtime),
        (root, c, Clock::Monotonic),
        (child, d, Clock::ProcessCpu),
        (parent, e, Clock::ProcessCpu),
    ] {
        assert_eq!(service.process_timers(owner).unwrap().clock(id), Ok(clock));
        let pending: Vec<_> = service
            .process_timers(owner)
            .unwrap()
            .pending_notifications()
            .collect();
        assert!(pending.iter().any(|pending| pending.timer == id));
    }
    processes.images.insert(
        140,
        Ok(mnu_abi::ProcessStatus {
            process_id: root.process_id,
            state: mnu_abi::PROCESS_STATE_RUNNING,
            image_revision: 1,
            ..Default::default()
        }),
    );
    assert_eq!(service.observe_process_timers(&mut processes), Ok(3));
    assert_eq!(
        service.process_timers(root).unwrap().clock(a),
        Err(STATUS_EINVAL)
    );
    assert_eq!(
        service.process_timers(root).unwrap().clock(c),
        Err(STATUS_EINVAL)
    );
    assert_eq!(
        service.process_timers(child).unwrap().clock(b),
        Ok(Clock::Realtime)
    );
    assert_eq!(
        service.process_timers(child).unwrap().clock(d),
        Ok(Clock::ProcessCpu)
    );
    assert_eq!(
        service.process_timers(parent).unwrap().clock(e),
        Ok(Clock::ProcessCpu)
    );
}

#[test]
fn reactor_does_not_wake_for_silent_disarmed_or_already_pending_one_shot_timers() {
    let (client, environment) = setup();
    let peer = client.transport().peer;
    let mut environment = environment.borrow_mut();
    let Environment { service, processes } = &mut *environment;
    arm_internal(
        service,
        peer,
        Clock::Monotonic,
        Notification::None,
        1,
        1,
        false,
    );
    let id = arm_internal(
        service,
        peer,
        Clock::Monotonic,
        Notification::Default,
        0,
        1,
        false,
    );
    assert!(!service.has_observable_process_timers());
    assert_eq!(service.observe_process_timers(processes), Ok(0));
    CLOCKS.with(|c| assert!(c.borrow().reads.is_empty()));
    service
        .process_timers(peer)
        .unwrap()
        .set(
            id,
            Samples {
                realtime_ns: 0,
                monotonic_ns: 0,
                process_cpu_ns: 0,
            },
            10,
            0,
            false,
        )
        .unwrap();
    assert_eq!(service.observe_process_timers(processes), Ok(1));
    assert!(!service.has_observable_process_timers());
    let pending: Vec<_> = service
        .process_timers(peer)
        .unwrap()
        .pending_notifications()
        .collect();
    assert_eq!(pending.len(), 1);
    CLOCKS.with(|c| c.borrow_mut().reads.clear());
    assert_eq!(service.observe_process_timers(processes), Ok(0));
    CLOCKS.with(|c| assert!(c.borrow().reads.is_empty()));
    assert_eq!(
        service
            .process_timers(peer)
            .unwrap()
            .pending_notifications()
            .next(),
        Some(pending[0])
    );
}
