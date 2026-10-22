use super::*;
use mochios_posix_client::signal_context::{
    CLD_CONTINUED, CLD_EXITED, CLD_KILLED, CLD_STOPPED, SigInfo,
};
use protocol::signal_origin::*;

pub(super) fn notification(service: &mut PosixService, parent: PeerIdentity) -> Origin {
    let delivery = dequeue_signal(service, parent);
    assert_eq!(delivery.signal, protocol::SIGNAL_CHLD);
    let mut bytes = [0; protocol::SIGNAL_DELIVERY_LEN];
    protocol::encode_signal_delivery(delivery, &mut bytes).unwrap();
    let response =
        thread_signal_request(service, parent, protocol::OP_SIGNAL_DELIVERY_ORIGIN, &bytes);
    assert_eq!(response.header.status, 0);
    let origin = decode(&response.payload).unwrap();
    service.complete_signal_delivery(parent, &bytes).unwrap();
    origin
}

#[test]
fn reaped_child_keeps_exit_code_in_the_pending_notification() {
    let (mut service, _, parent, child, mut filesystem, mut processes) = orphan_family();
    processes
        .states
        .insert(142, ProcessLifecycle::Exited { exit_code: 0x125 });
    let result = service
        .wait_child(
            parent,
            protocol::WaitRequest {
                selector: child.process_id as i64,
                options: 0,
            },
            &mut filesystem,
            &mut processes,
        )
        .unwrap();
    assert_eq!(result.status, 37 << 8);
    assert!(service.session(child.process_id).is_none());
    let origin = notification(&mut service, parent);
    assert_eq!(origin.process_id, child.process_id);
    assert_eq!(
        origin.child,
        ChildStatus {
            event: EXITED,
            status: 37
        }
    );
    let info = SigInfo::from_origin(protocol::SIGNAL_CHLD, origin).unwrap();
    assert_eq!(
        (info.si_code, info.si_status, info.si_pid, info.si_uid),
        (CLD_EXITED, 37, child.process_id as i32, 505)
    );
}

#[test]
fn signal_termination_is_not_misreported_as_an_exit_status_of_128_plus_signal() {
    let (mut service, _, parent, child, mut filesystem, mut processes) = orphan_family();
    let delivery = deliver_signal(&mut service, parent, child, 15);
    let mut bytes = [0; protocol::SIGNAL_DELIVERY_LEN];
    protocol::encode_signal_delivery(delivery, &mut bytes).unwrap();
    service
        .report_process_signaled(child, &bytes, &mut processes)
        .unwrap();
    let result = service
        .wait_child(
            parent,
            protocol::WaitRequest {
                selector: child.process_id as i64,
                options: 0,
            },
            &mut filesystem,
            &mut processes,
        )
        .unwrap();
    assert_eq!(result.status, 15);
    let origin = notification(&mut service, parent);
    assert_eq!(
        origin.child,
        ChildStatus {
            event: KILLED,
            status: 15
        }
    );
    let info = SigInfo::from_origin(protocol::SIGNAL_CHLD, origin).unwrap();
    assert_eq!((info.si_code, info.si_status), (CLD_KILLED, 15));
}

#[test]
fn coalescing_preserves_the_first_stop_event_and_a_fresh_continue_has_its_own_status() {
    let (mut service, _, parent, child, _, mut processes) = orphan_family();
    let mut bytes = [0; protocol::SIGNAL_DELIVERY_LEN];
    for coalesce in [true, false] {
        let delivery = deliver_signal(&mut service, parent, child, protocol::SIGNAL_STOP);
        protocol::encode_signal_delivery(delivery, &mut bytes).unwrap();
        service
            .report_process_stopped(child, &bytes, &mut processes)
            .unwrap();
        if coalesce {
            send_signal(&mut service, parent, child, protocol::SIGNAL_CONT);
            service.refresh_child_notifications(&mut processes).unwrap();
        }
        let origin = notification(&mut service, parent);
        assert_eq!(
            origin.child,
            ChildStatus {
                event: STOPPED,
                status: protocol::SIGNAL_STOP
            }
        );
        let info = SigInfo::from_origin(protocol::SIGNAL_CHLD, origin).unwrap();
        assert_eq!(
            (info.si_code, info.si_status),
            (CLD_STOPPED, protocol::SIGNAL_STOP as i32)
        );
    }
    send_signal(&mut service, parent, child, protocol::SIGNAL_CONT);
    service.refresh_child_notifications(&mut processes).unwrap();
    let origin = notification(&mut service, parent);
    assert_eq!(
        origin.child,
        ChildStatus {
            event: CONTINUED,
            status: protocol::SIGNAL_CONT
        }
    );
    let info = SigInfo::from_origin(protocol::SIGNAL_CHLD, origin).unwrap();
    assert_eq!(
        (info.si_code, info.si_status),
        (CLD_CONTINUED, protocol::SIGNAL_CONT as i32)
    );
}
