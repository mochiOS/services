extern crate alloc;

use mochios_posix_client::{
    Client, ClientError, ObjectHandleAttachment, ObjectHandles, ObjectTransport, Transport,
};
use mochios_posix_protocol as protocol;
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::rc::Rc;

mod native_process {
    use super::*;
    pub struct NativeProcess {
        pub handle: u32,
        pub closed: Rc<Cell<usize>>,
        pub confirmed: bool,
    }
    impl NativeProcess {
        pub fn tree_exit_confirmed(&self) -> bool {
            self.confirmed
        }
        pub fn confirm_tree_exit(&mut self) {
            self.confirmed = true;
        }
        pub fn termination_attachment(&self) -> ObjectHandleAttachment<u32> {
            ObjectHandleAttachment {
                handle: self.handle,
                rights: mnu_abi::HANDLE_RIGHT_WAIT | mnu_abi::HANDLE_RIGHT_SIGNAL,
            }
        }
    }
    impl Drop for NativeProcess {
        fn drop(&mut self) {
            self.closed.set(self.closed.get() + 1);
        }
    }
}
#[path = "../../service-manager/src/session_teardown.rs"]
mod production;

struct Replies {
    expected_handle: Cell<u32>,
    status: Cell<i32>,
    fail_transport: Cell<bool>,
    calls: Cell<usize>,
    reclaim_status: Cell<i32>,
    lose_reclaim_reply: Cell<bool>,
    opcodes: RefCell<Vec<u16>>,
}
impl Transport for Replies {
    type Error = u32;
    fn call(&self, _: &[u8], _: &mut [u8]) -> Result<usize, u32> {
        panic!("explicit Handle required")
    }
}
impl ObjectTransport for Replies {
    type Handle = u32;

    fn close_received_handle(&self, _: u32) {
        panic!("unexpected owned reply Handle in this fixture");
    }
    fn call_with_handles(
        &self,
        request: &[u8],
        response: &mut [u8],
        handles: &mut ObjectHandles<u32>,
    ) -> Result<usize, u32> {
        self.calls.set(self.calls.get() + 1);
        let (header, payload) = protocol::decode(request).unwrap();
        assert!(matches!(
            header.opcode,
            protocol::OP_PROCESS_TREE_TERMINATE | protocol::OP_PROCESS_TREE_RECLAIM
        ));
        self.opcodes.borrow_mut().push(header.opcode);
        assert!(payload.is_empty());
        assert_eq!(handles.len(), 1);
        assert_eq!(
            handles.get(0),
            Some(ObjectHandleAttachment {
                handle: self.expected_handle.get(),
                rights: mnu_abi::HANDLE_RIGHT_WAIT | mnu_abi::HANDLE_RIGHT_SIGNAL
            })
        );
        handles.clear();
        if self.fail_transport.get() {
            return Err(7);
        }
        let status = if header.opcode == protocol::OP_PROCESS_TREE_RECLAIM {
            if self.lose_reclaim_reply.replace(false) {
                self.reclaim_status.set(protocol::STATUS_ESRCH);
                return Err(7);
            }
            self.reclaim_status.get()
        } else {
            self.status.get()
        };
        protocol::encode(
            protocol::Header {
                opcode: protocol::OP_STATUS,
                request_id: header.request_id,
                status,
                ..Default::default()
            },
            &[],
            response,
        )
        .map_err(|_| 8)
    }
}

#[test]
fn failed_or_delayed_teardown_keeps_the_actual_process_owner_until_success() {
    let closed = Rc::new(Cell::new(0));
    let mut owners = BTreeMap::new();
    owners.insert(
        1030,
        native_process::NativeProcess {
            handle: 52,
            closed: Rc::clone(&closed),
            confirmed: false,
        },
    );
    let client = Client::new(Replies {
        expected_handle: Cell::new(52),
        status: Cell::new(0),
        fail_transport: Cell::new(false),
        calls: Cell::new(0),
        reclaim_status: Cell::new(0),
        lose_reclaim_reply: Cell::new(false),
        opcodes: RefCell::new(Vec::new()),
    });
    for error in [protocol::STATUS_EAGAIN, protocol::STATUS_EPERM, -5] {
        client.transport().status.set(error);
        assert_eq!(
            production::terminate_owned_root(&client, &mut owners, 1030),
            Err(ClientError::Remote(error))
        );
        assert!(owners.contains_key(&1030));
        assert_eq!(closed.get(), 0);
    }
    client.transport().status.set(0);
    client.transport().fail_transport.set(true);
    assert_eq!(
        production::terminate_owned_root(&client, &mut owners, 1030),
        Err(ClientError::Transport(7))
    );
    assert!(owners.contains_key(&1030));
    assert_eq!(closed.get(), 0);
    client.transport().fail_transport.set(false);
    production::terminate_owned_root(&client, &mut owners, 1030).unwrap();
    assert!(!owners.contains_key(&1030));
    assert_eq!(closed.get(), 1);
    let calls = client.transport().calls.get();
    assert_eq!(
        production::terminate_owned_root(&client, &mut owners, 1030),
        Err(ClientError::Remote(protocol::STATUS_ESRCH))
    );
    assert_eq!(client.transport().calls.get(), calls);
}

fn session_owners(closed: &Rc<Cell<usize>>) -> BTreeMap<u64, native_process::NativeProcess> {
    [1030, 1040, 1050]
        .into_iter()
        .enumerate()
        .map(|(index, process_id)| {
            (
                process_id,
                native_process::NativeProcess {
                    handle: 52 + index as u32,
                    closed: Rc::clone(closed),
                    confirmed: false,
                },
            )
        })
        .collect()
}

#[test]
fn failed_launch_retries_reverse_creation_order_without_touching_other_owners() {
    let closed = Rc::new(Cell::new(0));
    let mut owners = session_owners(&closed);
    // Deliberately not PID order: these roots were created in this order.
    let mut plan =
        production::SessionTeardown::begin_failed_launch(&[1050, 1030], &owners).unwrap();
    assert_eq!(plan.pending_root(), Some(1030));
    assert_eq!(
        plan.step(|_| Err::<(), _>(protocol::STATUS_EAGAIN)),
        Err(protocol::STATUS_EAGAIN)
    );
    assert_eq!(plan.pending_root(), Some(1030));
    assert_eq!(owners.len(), 3);
    assert_eq!(closed.get(), 0);
    let mut attempted = Vec::new();
    let mut release = |root| -> Result<(), i32> {
        attempted.push(root);
        owners.remove(&root).unwrap();
        Ok(())
    };
    assert_eq!(plan.step(&mut release), Ok(false));
    assert_eq!(plan.pending_root(), Some(1050));
    assert_eq!(plan.step(&mut release), Ok(true));
    assert_eq!(plan.step(&mut release), Ok(true));
    assert_eq!(attempted, [1030, 1050]);
    assert_eq!(closed.get(), 2);
    assert!(owners.contains_key(&1040));
}

#[test]
fn failed_launch_preflight_requires_all_retained_owners_and_allows_an_empty_batch() {
    let closed = Rc::new(Cell::new(0));
    let owners = session_owners(&closed);
    for roots in [&[0][..], &[1030, 1030][..]] {
        assert_eq!(
            production::SessionTeardown::begin_failed_launch(roots, &owners).unwrap_err(),
            production::TeardownError::InvalidRoot
        );
    }
    assert_eq!(
        production::SessionTeardown::begin_failed_launch(&[1030, 9999], &owners).unwrap_err(),
        production::TeardownError::MissingOwner
    );
    let mut empty = production::SessionTeardown::begin_failed_launch(&[], &owners).unwrap();
    assert_eq!(
        empty.step(|_| -> Result<(), i32> { panic!("no root") }),
        Ok(true)
    );
    assert_eq!(closed.get(), 0);
}

#[test]
fn failed_launch_lost_reclaim_reply_preserves_the_root_and_retries_the_same_handle() {
    let closed = Rc::new(Cell::new(0));
    let mut owners = session_owners(&closed);
    let mut plan =
        production::SessionTeardown::begin_failed_launch(&[1040, 1030], &owners).unwrap();
    let client = Client::new(Replies {
        expected_handle: Cell::new(52),
        status: Cell::new(0),
        fail_transport: Cell::new(false),
        calls: Cell::new(0),
        reclaim_status: Cell::new(0),
        lose_reclaim_reply: Cell::new(true),
        opcodes: RefCell::new(Vec::new()),
    });
    assert_eq!(
        plan.step(|root| production::terminate_owned_root(&client, &mut owners, root)),
        Err(ClientError::Transport(7))
    );
    assert_eq!(plan.pending_root(), Some(1030));
    assert!(owners.get(&1030).unwrap().confirmed);
    assert_eq!(closed.get(), 0);
    assert_eq!(
        plan.step(|root| production::terminate_owned_root(&client, &mut owners, root)),
        Ok(false)
    );
    assert_eq!(closed.get(), 1);
    assert_eq!(plan.pending_root(), Some(1040));
    assert_eq!(
        *client.transport().opcodes.borrow(),
        [
            protocol::OP_PROCESS_TREE_TERMINATE,
            protocol::OP_PROCESS_TREE_RECLAIM,
            protocol::OP_PROCESS_TREE_RECLAIM
        ]
    );
    client.transport().expected_handle.set(53);
    client.transport().status.set(protocol::STATUS_EPERM);
    assert_eq!(
        plan.step(|root| production::terminate_owned_root(&client, &mut owners, root)),
        Err(ClientError::Remote(protocol::STATUS_EPERM))
    );
    assert_eq!(plan.pending_root(), Some(1040));
    assert_eq!(closed.get(), 1);
    assert!(owners.contains_key(&1040));
    client.transport().status.set(0);
    client.transport().reclaim_status.set(0);
    assert_eq!(
        plan.step(|root| production::terminate_owned_root(&client, &mut owners, root)),
        Ok(true)
    );
    assert_eq!(closed.get(), 2);
    assert_eq!(owners.len(), 1);
    assert!(owners.contains_key(&1050));
}

#[test]
fn logout_preflights_all_roots_without_closing_or_terminating_any_process() {
    use production::TeardownError::{InvalidRoot, MissingOwner};
    let closed = Rc::new(Cell::new(0));
    let mut owners = session_owners(&closed);
    for (linux, workspace, binder, errno) in [
        (Some(0), 1040, 1050, InvalidRoot),
        (Some(1030), 0, 1050, InvalidRoot),
        (Some(1030), 1040, 0, InvalidRoot),
        (Some(1030), 1030, 1050, InvalidRoot),
        (None, 1040, 1040, InvalidRoot),
        (Some(1030), 1040, 9999, MissingOwner),
    ] {
        assert_eq!(
            production::SessionTeardown::begin(linux, workspace, binder, &owners).unwrap_err(),
            errno
        );
        assert_eq!(owners.len(), 3);
        assert_eq!(closed.get(), 0);
    }
    owners.remove(&1050);
    assert_eq!(
        production::SessionTeardown::begin(Some(1030), 1040, 1050, &owners).unwrap_err(),
        MissingOwner
    );
    assert_eq!(owners.len(), 2);
    assert_eq!(closed.get(), 1);
}

#[test]
fn partial_logout_retries_the_pending_root_and_keeps_binder_alive_until_last() {
    let closed = Rc::new(Cell::new(0));
    let mut owners = session_owners(&closed);
    let client = Client::new(Replies {
        expected_handle: Cell::new(52),
        status: Cell::new(0),
        fail_transport: Cell::new(false),
        calls: Cell::new(0),
        reclaim_status: Cell::new(0),
        lose_reclaim_reply: Cell::new(false),
        opcodes: RefCell::new(Vec::new()),
    });
    let mut logout = production::SessionTeardown::begin(Some(1030), 1040, 1050, &owners).unwrap();
    assert_eq!(logout.pending_root(), Some(1030));
    let mut attempted = Vec::new();
    let mut step = |logout: &mut production::SessionTeardown| {
        logout.step(|process_id| {
            attempted.push(process_id);
            client
                .transport()
                .expected_handle
                .set(owners.get(&process_id).unwrap().handle);
            production::terminate_owned_root(&client, &mut owners, process_id)
        })
    };
    assert_eq!(step(&mut logout), Ok(false));
    assert_eq!(logout.pending_root(), Some(1040));
    for error in [protocol::STATUS_EAGAIN, -5, protocol::STATUS_EPERM] {
        client.transport().status.set(error);
        assert_eq!(step(&mut logout), Err(ClientError::Remote(error)));
        assert_eq!(logout.pending_root(), Some(1040));
        assert_eq!(closed.get(), 1);
    }
    client.transport().status.set(0);
    client.transport().fail_transport.set(true);
    assert_eq!(step(&mut logout), Err(ClientError::Transport(7)));
    assert_eq!(closed.get(), 1);
    client.transport().fail_transport.set(false);
    assert_eq!(step(&mut logout), Ok(false));
    assert_eq!(logout.pending_root(), Some(1050));
    assert_eq!(closed.get(), 2);
    client.transport().status.set(protocol::STATUS_EAGAIN);
    assert_eq!(
        step(&mut logout),
        Err(ClientError::Remote(protocol::STATUS_EAGAIN))
    );
    assert_eq!(closed.get(), 2);
    client.transport().status.set(0);
    assert_eq!(step(&mut logout), Ok(true));
    assert_eq!(logout.pending_root(), None);
    assert_eq!(closed.get(), 3);
    assert_eq!(step(&mut logout), Ok(true));
    assert_eq!(attempted, [1030, 1040, 1040, 1040, 1040, 1040, 1050, 1050]);
    assert!(owners.is_empty());
}

#[test]
fn logout_without_linux_still_requires_workspace_and_binder_confirmation() {
    let closed = Rc::new(Cell::new(0));
    let owners = session_owners(&closed);
    let mut logout = production::SessionTeardown::begin(None, 1040, 1050, &owners).unwrap();
    assert_eq!(logout.pending_root(), Some(1040));
    let mut attempted = Vec::new();
    let mut terminate = |process_id| -> Result<(), i32> {
        attempted.push(process_id);
        Ok(())
    };
    assert_eq!(logout.step(&mut terminate), Ok(false));
    assert_eq!(logout.step(&mut terminate), Ok(true));
    assert_eq!(logout.step(&mut terminate), Ok(true));
    assert_eq!(attempted, [1040, 1050]);
}

#[test]
fn reclaim_reply_loss_retries_only_reclaim_after_confirmed_tree_exit() {
    let closed = Rc::new(Cell::new(0));
    let mut owners = session_owners(&closed);
    let client = Client::new(Replies {
        expected_handle: Cell::new(52),
        status: Cell::new(0),
        fail_transport: Cell::new(false),
        calls: Cell::new(0),
        reclaim_status: Cell::new(0),
        lose_reclaim_reply: Cell::new(true),
        opcodes: RefCell::new(Vec::new()),
    });
    assert_eq!(
        production::terminate_owned_root(&client, &mut owners, 1030),
        Err(ClientError::Transport(7))
    );
    assert!(owners.get(&1030).unwrap().confirmed);
    assert_eq!(closed.get(), 0);
    // The server already reclaimed its records, and the success reply was
    // lost. Only this root's remembered exit confirmation allows ESRCH here.
    assert_eq!(
        production::terminate_owned_root(&client, &mut owners, 1030),
        Ok(())
    );
    assert!(!owners.contains_key(&1030));
    assert_eq!(closed.get(), 1);
    assert_eq!(
        *client.transport().opcodes.borrow(),
        [
            protocol::OP_PROCESS_TREE_TERMINATE,
            protocol::OP_PROCESS_TREE_RECLAIM,
            protocol::OP_PROCESS_TREE_RECLAIM,
        ]
    );
}

#[test]
fn missing_exit_confirmation_is_not_completion_and_reclaim_denials_keep_the_owner() {
    let closed = Rc::new(Cell::new(0));
    let mut owners = session_owners(&closed);
    let client = Client::new(Replies {
        expected_handle: Cell::new(52),
        status: Cell::new(protocol::STATUS_ESRCH),
        fail_transport: Cell::new(false),
        calls: Cell::new(0),
        reclaim_status: Cell::new(protocol::STATUS_EPERM),
        lose_reclaim_reply: Cell::new(false),
        opcodes: RefCell::new(Vec::new()),
    });
    assert_eq!(
        production::terminate_owned_root(&client, &mut owners, 1030),
        Err(ClientError::Remote(protocol::STATUS_ESRCH))
    );
    assert!(!owners.get(&1030).unwrap().confirmed);
    assert_eq!(closed.get(), 0);
    assert_eq!(
        *client.transport().opcodes.borrow(),
        [protocol::OP_PROCESS_TREE_TERMINATE]
    );
    client.transport().status.set(0);
    for error in [protocol::STATUS_EPERM, protocol::STATUS_EAGAIN, -5] {
        client.transport().reclaim_status.set(error);
        assert_eq!(
            production::terminate_owned_root(&client, &mut owners, 1030),
            Err(ClientError::Remote(error))
        );
        assert!(owners.get(&1030).unwrap().confirmed);
        assert_eq!(closed.get(), 0);
    }
    client.transport().reclaim_status.set(0);
    production::terminate_owned_root(&client, &mut owners, 1030).unwrap();
    assert_eq!(closed.get(), 1);
    assert_eq!(
        client
            .transport()
            .opcodes
            .borrow()
            .iter()
            .filter(|&&opcode| opcode == protocol::OP_PROCESS_TREE_TERMINATE)
            .count(),
        2
    );
}

#[test]
fn teardown_never_captures_an_arbitrary_pid_or_discards_an_owner_before_reply() {
    let source = include_str!("../../service-manager/src/session_teardown.rs");
    assert!(!source.contains("open_handle_for_process_id"));
    assert!(!source.contains("process::list"));
    assert!(
        source.find("client.terminate_launched_tree").unwrap()
            < source.find("owners.remove").unwrap()
    );
    assert!(
        source.find("client.terminate_launched_tree").unwrap()
            < source.find("process.confirm_tree_exit()").unwrap()
    );
    assert!(
        source.find("client.reclaim_launched_tree").unwrap()
            < source.find("owners.remove").unwrap()
    );
    assert!(!source.contains("handle_status"));
    let owner = include_str!("../../service-manager/src/native_process.rs");
    assert!(owner.contains("handle: self.handle"));
    assert!(owner.contains("HANDLE_RIGHT_WAIT | platform::handle::HANDLE_RIGHT_SIGNAL"));
}
