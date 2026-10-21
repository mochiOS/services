use mochios_posix_client::{
    Client, ClientError, Transport,
    signal::{SA_RESETHAND, SA_RESTART, SA_SIGINFO},
};
use mochios_posix_protocol as posix_protocol;
use posix_service::{AuthenticatedProcess, PeerIdentity, PosixService};
use std::ffi::c_int;
use std::sync::{
    Arc, Barrier, Mutex, MutexGuard, OnceLock,
    atomic::{AtomicUsize, Ordering},
};

const EINVAL: i32 = 22;
const EIO: i32 = 5;
const SA_NOCLDSTOP: i32 = 1;
const SA_NOCLDWAIT: i32 = 2;
const PEER: PeerIdentity = PeerIdentity {
    process_id: 70,
    effective_uid: 501,
    effective_gid: 20,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SignalAction {
    handler: usize,
    sa_mask: u64,
    sa_flags: c_int,
}
impl SignalAction {
    const fn default_action() -> Self {
        Self {
            handler: 0,
            sa_mask: 0,
            sa_flags: 0,
        }
    }
}
struct RuntimeMutex<T>(Mutex<T>);
impl<T> RuntimeMutex<T> {
    const fn new(value: T) -> Self {
        Self(Mutex::new(value))
    }
    fn lock(&self) -> MutexGuard<'_, T> {
        self.0.lock().unwrap()
    }
}
static CASE: Mutex<()> = Mutex::new(());
static SIGNAL_ACTION_UPDATE: RuntimeMutex<()> = RuntimeMutex::new(());
static SIGNAL_ACTIONS: RuntimeMutex<[SignalAction; 64]> =
    RuntimeMutex::new([SignalAction::default_action(); 64]);
static SERVICE: OnceLock<Mutex<PosixService>> = OnceLock::new();
static FAIL: AtomicUsize = AtomicUsize::new(0);
static RPCS: AtomicUsize = AtomicUsize::new(0);
static BLOCK: Mutex<Option<Arc<[Barrier; 2]>>> = Mutex::new(None);

fn service() -> &'static Mutex<PosixService> {
    SERVICE.get_or_init(|| Mutex::new(PosixService::new()))
}
struct Local;
impl Transport for Local {
    type Error = ();
    fn call(&self, input: &[u8], output: &mut [u8]) -> Result<usize, ()> {
        RPCS.fetch_add(1, Ordering::SeqCst);
        if FAIL.load(Ordering::SeqCst) != 0 {
            return Err(());
        }
        let (header, payload) = posix_protocol::decode(input).map_err(|_| ())?;
        let block = BLOCK.lock().unwrap().clone();
        if let Some(block) = block {
            if header.opcode == posix_protocol::OP_SIGNAL_DISPOSITION
                && posix_protocol::decode_signal_disposition(payload)
                    .unwrap()
                    .kind
                    == posix_protocol::SIGNAL_DISPOSITION_DEFAULT
            {
                block[0].wait();
                block[1].wait();
            }
        }
        let mut state = service().lock().unwrap();
        let response = if matches!(
            header.opcode,
            posix_protocol::OP_SIGNAL_THREAD_MASK
                | posix_protocol::OP_SIGNAL_THREAD_DEQUEUE
                | posix_protocol::OP_SIGNAL_DELIVERY_ORIGIN
        ) {
            state.handle_thread_signal_request(
                PEER,
                mnu_abi::ExecutionIdentity {
                    process_id: PEER.process_id,
                    thread_id: 700,
                },
                header,
                payload,
            )
        } else {
            state.handle(PEER, header, payload)
        };
        posix_protocol::encode(response.header, &response.payload, output).map_err(|_| ())
    }
}
fn posix_client() -> Result<Client<Local>, ClientError<()>> {
    Ok(Client::new(Local))
}
fn map_posix_client_error(error: ClientError<()>) -> c_int {
    match error {
        ClientError::Remote(error) => -error,
        _ => EIO,
    }
}
#[path = "../../../user/crates/newlib-runtime/src/signal_action.rs"]
mod production;

fn install(signal: u32, action: SignalAction) {
    let _update = SIGNAL_ACTION_UPDATE.lock();
    posix_client()
        .unwrap()
        .set_signal_disposition(posix_protocol::SignalDisposition {
            signal,
            kind: match action.handler {
                0 => 0,
                1 => 1,
                _ => 2,
            },
            child_options: if signal == posix_protocol::SIGNAL_CHLD {
                u32::from(action.sa_flags & SA_NOCLDSTOP != 0)
                    * posix_protocol::SIGNAL_CHILD_OPTION_NOCLDSTOP
                    | u32::from(action.sa_flags & SA_NOCLDWAIT != 0)
                        * posix_protocol::SIGNAL_CHILD_OPTION_NOCLDWAIT
            } else {
                0
            },
        })
        .unwrap();
    SIGNAL_ACTIONS.lock()[signal as usize - 1] = action;
}
fn reset() {
    FAIL.store(0, Ordering::SeqCst);
    RPCS.store(0, Ordering::SeqCst);
    *BLOCK.lock().unwrap() = None;
    *SIGNAL_ACTIONS.lock() = [SignalAction::default_action(); 64];
    let mut state = PosixService::new();
    state
        .initialize_bootstrap_process(
            AuthenticatedProcess {
                handle: 7,
                process_id: PEER.process_id,
            },
            501,
            20,
            &[],
        )
        .unwrap();
    *service().lock().unwrap() = state;
}

fn reset_action(action: SignalAction) -> SignalAction {
    SignalAction {
        handler: 0,
        sa_flags: action.sa_flags & !SA_SIGINFO,
        ..action
    }
}

#[test]
fn one_shot_selection_preserves_the_selected_action_and_resets_shared_disposition() {
    let _case = CASE.lock().unwrap();
    reset();
    let action = SignalAction {
        handler: 123,
        sa_mask: 0x102,
        sa_flags: SA_RESETHAND | SA_SIGINFO | SA_RESTART,
    };
    install(30, action);
    assert_eq!(production::select(30), Ok(action));
    assert_eq!(SIGNAL_ACTIONS.lock()[29], reset_action(action));
    assert_eq!(
        posix_client().unwrap().signal_disposition(30).unwrap().kind,
        posix_protocol::SIGNAL_DISPOSITION_DEFAULT
    );
    assert_eq!(production::select(30), Ok(reset_action(action)));
    // Reinstalling from inside the selected handler is a new action, not
    // something to clear when that old handler eventually returns.
    let new = SignalAction {
        handler: 456,
        sa_flags: 0,
        ..action
    };
    install(30, new);
    assert_eq!(production::select(30), Ok(new));
    assert_eq!(production::select(30), Ok(new));
}

#[test]
fn selected_siginfo_origin_survives_reset_of_the_service_disposition() {
    let _case = CASE.lock().unwrap();
    reset();
    let action = SignalAction {
        handler: 123,
        sa_mask: 0,
        sa_flags: SA_RESETHAND | SA_SIGINFO,
    };
    install(30, action);
    let client = posix_client().unwrap();
    client
        .thread_signal_mask(posix_protocol::SIGNAL_MASK_SET, 0)
        .unwrap();
    client.send_signal(PEER.process_id as i64, 30).unwrap();
    let delivery = client.thread_dequeue_signal_delivery().unwrap();
    assert_eq!(delivery.signal, 30);
    let origin = client.signal_delivery_origin(delivery).unwrap();
    assert_eq!(production::select(30), Ok(action));
    assert_eq!(client.signal_delivery_origin(delivery).unwrap(), origin);
    client.complete_signal_delivery(delivery).unwrap();
}

#[test]
fn one_shot_sigchld_preserves_child_policy_and_mask_while_clearing_siginfo() {
    let _case = CASE.lock().unwrap();
    reset();
    let action = SignalAction {
        handler: 123,
        sa_mask: 0x40,
        sa_flags: SA_RESETHAND | SA_SIGINFO | SA_NOCLDSTOP | SA_NOCLDWAIT,
    };
    install(posix_protocol::SIGNAL_CHLD, action);
    assert_eq!(production::select(posix_protocol::SIGNAL_CHLD), Ok(action));
    assert_eq!(
        SIGNAL_ACTIONS.lock()[posix_protocol::SIGNAL_CHLD as usize - 1],
        reset_action(action)
    );
    let disposition = posix_client()
        .unwrap()
        .signal_disposition(posix_protocol::SIGNAL_CHLD)
        .unwrap();
    assert_eq!(disposition.kind, posix_protocol::SIGNAL_DISPOSITION_DEFAULT);
    assert_eq!(
        disposition.child_options,
        posix_protocol::SIGNAL_CHILD_OPTION_NOCLDSTOP
            | posix_protocol::SIGNAL_CHILD_OPTION_NOCLDWAIT
    );
}

#[test]
fn concurrent_deliveries_consume_exactly_one_catching_action() {
    let _case = CASE.lock().unwrap();
    reset();
    let action = SignalAction {
        handler: 123,
        sa_mask: 0,
        sa_flags: SA_RESETHAND,
    };
    install(30, action);
    let start = Arc::new(Barrier::new(3));
    let threads: Vec<_> = (0..2)
        .map(|_| {
            let start = start.clone();
            std::thread::spawn(move || {
                start.wait();
                production::select(30).unwrap()
            })
        })
        .collect();
    start.wait();
    let selected: Vec<_> = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();
    assert_eq!(selected.iter().filter(|value| **value == action).count(), 1);
    assert_eq!(
        selected
            .iter()
            .filter(|value| **value == reset_action(action))
            .count(),
        1
    );
}

#[test]
fn concurrent_sigaction_cannot_be_erased_by_an_old_reset_after_selection() {
    let _case = CASE.lock().unwrap();
    reset();
    let action = SignalAction {
        handler: 123,
        sa_mask: 0,
        sa_flags: SA_RESETHAND,
    };
    install(30, action);
    let block = Arc::new([Barrier::new(2), Barrier::new(2)]);
    *BLOCK.lock().unwrap() = Some(block.clone());
    let selecting = std::thread::spawn(|| production::select(30).unwrap());
    block[0].wait();
    assert!(matches!(
        SIGNAL_ACTION_UPDATE.0.try_lock(),
        Err(std::sync::TryLockError::WouldBlock)
    ));
    let new = SignalAction {
        handler: 456,
        sa_mask: 0,
        sa_flags: 0,
    };
    let setting = std::thread::spawn(move || install(30, new));
    block[1].wait();
    assert_eq!(selecting.join().unwrap(), action);
    setting.join().unwrap();
    *BLOCK.lock().unwrap() = None;
    assert_eq!(production::select(30), Ok(new));
    assert_eq!(
        posix_client().unwrap().signal_disposition(30).unwrap().kind,
        posix_protocol::SIGNAL_DISPOSITION_CAUGHT
    );
}

#[test]
fn failed_reset_does_not_report_a_selection_or_publish_a_local_default() {
    let _case = CASE.lock().unwrap();
    reset();
    let action = SignalAction {
        handler: 123,
        sa_mask: 0,
        sa_flags: SA_RESETHAND,
    };
    install(30, action);
    FAIL.store(1, Ordering::SeqCst);
    assert_eq!(production::select(30), Err(EIO));
    assert_eq!(SIGNAL_ACTIONS.lock()[29], action);
    assert!(SIGNAL_ACTION_UPDATE.0.try_lock().is_ok());
    FAIL.store(0, Ordering::SeqCst);
    assert_eq!(
        posix_client().unwrap().signal_disposition(30).unwrap().kind,
        posix_protocol::SIGNAL_DISPOSITION_CAUGHT
    );
    assert_eq!(production::select(30), Ok(action));
}

#[test]
fn reset_exceptions_noncaught_and_invalid_signals_do_not_issue_reset_rpc() {
    let _case = CASE.lock().unwrap();
    reset();
    for signal in [posix_protocol::SIGNAL_ILL, posix_protocol::SIGNAL_TRAP] {
        let action = SignalAction {
            handler: 123,
            sa_mask: 0,
            sa_flags: SA_RESETHAND,
        };
        install(signal, action);
        let before = RPCS.load(Ordering::SeqCst);
        assert_eq!(production::select(signal), Ok(action));
        assert_eq!(production::select(signal), Ok(action));
        assert_eq!(RPCS.load(Ordering::SeqCst), before);
    }
    for handler in [0, 1, usize::MAX] {
        let action = SignalAction {
            handler,
            sa_mask: 0,
            sa_flags: SA_RESETHAND,
        };
        SIGNAL_ACTIONS.lock()[29] = action;
        let before = RPCS.load(Ordering::SeqCst);
        assert_eq!(production::select(30), Ok(action));
        assert_eq!(RPCS.load(Ordering::SeqCst), before);
    }
    for signal in [0, 65, u32::MAX] {
        assert_eq!(production::select(signal), Err(EINVAL));
    }
}
