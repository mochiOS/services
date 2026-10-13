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

fn subscribe_input_events(tty_endpoint: u64) -> bool {
    let Some(input_tid) = find_input_service() else {
        return false;
    };
    let subscribe = platform::input::SubscribeRequest {
        opcode: platform::input::SUBSCRIBE_OPCODE,
        reserved: 0,
        endpoint: tty_endpoint,
    };
    let subscribe_reply = input_subscribe_reply_buf();
    subscribe_reply.fill(0);
    platform::ipc::call(
        input_tid,
        platform::input::bytes_of(&subscribe),
        subscribe_reply,
    )
    .is_ok()
}

fn main() {
    let _ = platform::logger::init_from_env();
    let _ = parse_endpoint_arg();

    let tty_endpoint = match platform::ipc::create() {
        Ok(handle) => handle,
        Err(_) => platform::process::exit(1),
    };
    let logger_endpoint = platform::logger::endpoint().unwrap_or(0);

    while !subscribe_input_events(tty_endpoint) {
        platform::thread::yield_now();
    }

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
        if len == core::mem::size_of::<u64>() {
            shell_endpoint = u64::from_le_bytes([
                buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
            ]);
            continue;
        }
        if len == core::mem::size_of::<u64>() * 2 {
            shell_endpoint = u64::from_le_bytes([
                buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
            ]);
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
        if len != INPUT_EVENT_SIZE {
            continue;
        }
        if shell_endpoint != 0 {
            let _ = platform::ipc::send(shell_endpoint, &buf[..len]);
        }
    }
}
