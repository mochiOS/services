use mnu_abi::{HANDLE_RIGHT_READ as R, HANDLE_RIGHT_TRANSFER as T};
use mochios_posix_client::{
    Client, ObjectHandleAttachment, ObjectHandles, ObjectTransport, Transport,
};
use mochios_posix_protocol::{self as wire, fifo::WaitCondition};
use std::{cell::RefCell, rc::Rc};
#[derive(Default)]
struct State {
    rights: u64,
    reply: u32,
    remote: i32,
    fail: bool,
    flags: u32,
    closed: Vec<u32>,
    calls: usize,
}
#[derive(Clone)]
struct Mock(Rc<RefCell<State>>);
impl Transport for Mock {
    type Error = ();
    fn call(&self, _: &[u8], _: &mut [u8]) -> Result<usize, ()> {
        panic!("explicit attachment required")
    }
}
impl ObjectTransport for Mock {
    type Handle = u32;
    fn close_received_handle(&self, h: u32) {
        self.0.borrow_mut().closed.push(h);
    }
    fn call_with_handles(
        &self,
        bytes: &[u8],
        out: &mut [u8],
        objects: &mut ObjectHandles<u32>,
    ) -> Result<usize, ()> {
        let (header, payload) = wire::decode(bytes).unwrap();
        assert_eq!(header.opcode, wire::OP_FIFO_WAIT);
        assert_eq!(header.flags, 0);
        assert_eq!(WaitCondition::decode(payload), Ok(WaitCondition::Read));
        assert_eq!(
            objects.get(0),
            Some(ObjectHandleAttachment {
                handle: 7,
                rights: R | T
            })
        );
        assert_eq!(objects.len(), 1);
        objects.clear();
        let mut s = self.0.borrow_mut();
        s.calls += 1;
        objects
            .push(ObjectHandleAttachment {
                handle: s.reply,
                rights: s.rights,
            })
            .unwrap();
        if s.fail {
            return Err(());
        }
        Ok(wire::encode(
            wire::Header {
                opcode: wire::OP_STATUS,
                request_id: header.request_id,
                status: s.remote,
                flags: s.flags,
                ..Default::default()
            },
            &[],
            out,
        )
        .unwrap())
    }
}
#[test]
fn wait_attenuates_source_and_drains_only_owned_reply_on_all_failures() {
    for (reply, rights, remote, fail, success, closed) in [
        (42, wire::fifo::NOTIFICATION_RIGHTS, 0, false, true, vec![]),
        (42, R | T, 0, false, false, vec![42]),
        (
            42,
            wire::fifo::NOTIFICATION_RIGHTS,
            -5,
            false,
            false,
            vec![42],
        ),
        (
            42,
            wire::fifo::NOTIFICATION_RIGHTS,
            0,
            true,
            false,
            vec![42],
        ),
        (7, wire::fifo::NOTIFICATION_RIGHTS, 0, false, false, vec![]),
        (0, wire::fifo::NOTIFICATION_RIGHTS, 0, false, false, vec![]),
    ] {
        let state = Rc::new(RefCell::new(State {
            reply,
            rights,
            remote,
            fail,
            ..Default::default()
        }));
        let client = Client::new(Mock(state.clone()));
        let result = client.fifo_wait(
            ObjectHandleAttachment {
                handle: 7,
                rights: wire::fifo::data_rights(wire::OPEN_READ).unwrap(),
            },
            WaitCondition::Read,
        );
        assert_eq!(result.is_ok(), success);
        assert_eq!(state.borrow().closed, closed);
        assert_eq!(state.borrow().calls, 1);
    }
}
#[test]
fn invalid_source_is_rejected_locally() {
    let state = Rc::new(RefCell::new(State::default()));
    let client = Client::new(Mock(state.clone()));
    for (handle, rights) in [(0, R | T), (7, R), (7, R | mnu_abi::HANDLE_RIGHT_WRITE | T)] {
        assert!(
            client
                .fifo_wait(
                    ObjectHandleAttachment { handle, rights },
                    WaitCondition::Read
                )
                .is_err()
        );
    }
    assert_eq!(state.borrow().calls, 0);
}

#[test]
fn reserved_reply_flags_close_the_owned_job() {
    let state = Rc::new(RefCell::new(State {
        reply: 42,
        rights: wire::fifo::NOTIFICATION_RIGHTS,
        flags: 1,
        ..Default::default()
    }));
    let client = Client::new(Mock(state.clone()));
    assert!(
        client
            .fifo_wait(
                ObjectHandleAttachment {
                    handle: 7,
                    rights: R | T
                },
                WaitCondition::Read
            )
            .is_err()
    );
    assert_eq!(state.borrow().closed, vec![42]);
}
