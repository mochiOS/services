use mochi_user_platform as platform;

mod shell_launch;

const MSH_PATH: &str = "/bin/msh";
const INPUT_SERVICE_NAME: &str = "input.service";
const INPUT_EVENT_SIZE: usize = core::mem::size_of::<platform::input::InputEvent>();
const TTY_IPC_BUFFER_SIZE: usize = 2048;
const TTY_OUTPUT_MAGIC: &[u8; 4] = b"TOUT";

static mut INPUT_SUBSCRIBE_REPLY_BUF: [u8; 8] = [0; 8];
static mut TTY_IPC_BUF: [u8; TTY_IPC_BUFFER_SIZE] = [0; TTY_IPC_BUFFER_SIZE];

fn input_subscribe_reply_buf() -> &'static mut [u8] {
    unsafe {
        core::slice::from_raw_parts_mut(
            core::ptr::addr_of_mut!(INPUT_SUBSCRIBE_REPLY_BUF).cast::<u8>(),
            core::mem::size_of::<[u8; 8]>(),
        )
    }
}

fn tty_ipc_buf() -> &'static mut [u8] {
    unsafe {
        core::slice::from_raw_parts_mut(
            core::ptr::addr_of_mut!(TTY_IPC_BUF).cast::<u8>(),
            TTY_IPC_BUFFER_SIZE,
        )
    }
}

fn is_tty_output(bytes: &[u8]) -> bool {
    bytes.len() >= TTY_OUTPUT_MAGIC.len() && &bytes[..TTY_OUTPUT_MAGIC.len()] == TTY_OUTPUT_MAGIC
}

fn parse_decimal_u64(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() {
        return None;
    }
    let mut out = 0u64;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        out = out.checked_mul(10)?;
        out = out.checked_add(u64::from(b - b'0'))?;
    }
    Some(out)
}

fn parse_endpoint_arg() -> Option<u64> {
    for argument in std::env::args() {
        if let Some(value) = parse_decimal_u64(argument.as_bytes()) {
            return Some(value);
        }
    }
    None
}

fn find_input_service() -> Option<u64> {
    if let Ok(tid) = platform::process::find_by_name(INPUT_SERVICE_NAME) {
        if tid != 0 {
            return Some(tid);
        }
    }
    None
}

fn trusted_peer(endpoint: u64, package: &[u8]) -> Option<platform::execution_peer::MeasuredPeer> {
    let peer = platform::execution_peer::capture(endpoint).ok()?;
    let context = &peer.context;
    (context.provenance == 1
        && context.subject_key_id == [0; 32]
        && context.package_id.get(..context.package_id_len as usize) == Some(package)
        && context
            .developer_id
            .get(..context.developer_id_len as usize)
            == Some(b"org.mochios.system"))
    .then_some(peer)
}

fn subscribe_input_events(tty_endpoint: u64) -> Option<u64> {
    let input_tid = find_input_service()?;
    let peer = trusted_peer(input_tid, b"org.mochios.input")?;
    let subscribe = platform::input::SubscribeRequest {
        opcode: platform::input::SUBSCRIBE_OPCODE,
        reserved: 0,
        endpoint: tty_endpoint,
    };
    let subscribe_reply = input_subscribe_reply_buf();
    subscribe_reply.fill(0);
    let message = platform::ipc::call(
        input_tid,
        platform::input::bytes_of(&subscribe),
        subscribe_reply,
    )
    .ok()?;
    let current = trusted_peer(input_tid, b"org.mochios.input")?;
    (message >> 32 == input_tid
        && message as u32 == 1
        && subscribe_reply[0] == 0
        && current.context == peer.context
        && current.image == peer.image
        && platform::handle::same_object(current.process.0, peer.process.0) == Ok(true))
    .then_some(input_tid)
}

fn main() {
    let _ = platform::logger::init_from_env();
    let _ = parse_endpoint_arg();

    let tty_endpoint = match platform::ipc::create() {
        Ok(handle) => handle,
        Err(_) => platform::process::exit(1),
    };
    let logger_endpoint = platform::logger::endpoint().unwrap_or(0);

    let input_endpoint = loop {
        if let Some(endpoint) = subscribe_input_events(tty_endpoint) {
            break endpoint;
        }
        platform::thread::yield_now();
    };

    // Keep the POSIX child object for the broker's lifetime. Spawn performs
    // exec authorization, image Handle replacement and FD inheritance through
    // the existing newlib/POSIX implementation, not a TTY-specific syscall.
    let _shell = match shell_launch::spawn_shell(MSH_PATH, tty_endpoint, logger_endpoint) {
        Ok(child) => child,
        Err(error) => {
            eprintln!("tty.service: shell spawn failed: {error}");
            platform::process::exit(1);
        }
    };
    // Retain the native Process backing this POSIX child before accepting a
    // registration. The child ID comes from our own spawn, never IPC bytes.
    let shell_process = platform::execution_peer::ProcessReference(
        platform::process::open_handle_for_process_id(
            u64::from(_shell.id()),
            platform::handle::HANDLE_RIGHT_WAIT,
        )
        .unwrap_or_else(|_| platform::process::exit(1)),
    );

    let mut shell_endpoint = 0u64;
    loop {
        let buf = tty_ipc_buf();
        buf.fill(0);
        let Ok(msg) = platform::ipc::wait(tty_endpoint, buf) else {
            platform::thread::yield_now();
            continue;
        };
        let len = (msg & 0xffff_ffff) as usize;
        let sender = msg >> 32;
        let len = len.min(buf.len());
        if matches!(len, 8 | 16) {
            if shell_endpoint == 0
                && let Some(peer) = trusted_peer(sender, b"org.mochios.msh")
                && platform::handle::same_object(peer.process.0, shell_process.0) == Ok(true)
                && buf[..8] == sender.to_le_bytes()
            {
                shell_endpoint = sender;
            }
            continue;
        }
        if is_tty_output(&buf[..len]) {
            if shell_endpoint != 0 {
                let _ = platform::ipc::send(shell_endpoint, &buf[..len]);
            }
            let status = 0u64;
            let _ = platform::ipc::reply(sender, &status.to_le_bytes());
            continue;
        }
        if len != INPUT_EVENT_SIZE || sender != input_endpoint {
            continue;
        }
        if shell_endpoint != 0 {
            let _ = platform::ipc::send(shell_endpoint, &buf[..len]);
        }
    }
}
