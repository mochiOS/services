use mochi_user_platform as platform;
use mochios_net_device_protocol::{
    Header, Opcode, PING_RESULT_LEN, STACK_STATISTICS_LEN, decode_empty, decode_ping,
    encode_ping_result, encode_stack_statistics,
};

use crate::driver::DriverClient;
use crate::stack::NetworkStack;

const START_TIMEOUT: u64 = 5_000;

pub(crate) fn run() -> ! {
    platform::println!("network.service: start");
    let ready = platform::service_ready::take_bootstrap_target();
    let now = platform::time::ticks().unwrap_or(0);
    let driver = match DriverClient::connect(now.saturating_add(START_TIMEOUT)) {
        Ok(driver) => driver,
        Err(errno) => {
            platform::println!(
                "network.service: virtio-net driver unavailable errno={}",
                errno
            );
            if let Some(target) = ready {
                let _ = platform::service_ready::notify(target, -(errno as i32));
            }
            idle()
        }
    };
    let xid = platform::service_ready::generate_token()
        .map(|value| value as u32)
        .unwrap_or(0x4d4f_4348);
    let mut stack = match NetworkStack::new(driver, ready, xid) {
        Ok(stack) => stack,
        Err(errno) => {
            platform::println!("network.service: interface query failed errno={}", errno);
            idle()
        }
    };
    let info = stack.info();
    platform::println!(
        "network.service: interface id={} mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} link={} mtu={}",
        info.interface_id,
        info.mac[0],
        info.mac[1],
        info.mac[2],
        info.mac[3],
        info.mac[4],
        info.mac[5],
        info.link_up,
        info.mtu
    );
    if stack.start(now).is_err() {
        platform::println!("network.service: DHCP startup failed");
    }

    let mut request = [0u8; 64];
    let mut reply = [0u8; STACK_STATISTICS_LEN];
    loop {
        let now = platform::time::ticks().unwrap_or(0);
        stack.tick(now);
        for _ in 0..32 {
            match stack.poll_receive(now) {
                Ok(true) => {}
                Ok(false) | Err(_) => break,
            }
        }
        match platform::ipc::try_wait(&mut request) {
            Ok(message) => {
                let length = (message & 0xffff_ffff) as usize;
                let sender = message >> 32;
                let Some(bytes) = request.get(..length) else {
                    continue;
                };
                if let Some(length) = handle(&mut stack, bytes, &mut reply, now) {
                    let _ = platform::ipc::reply(sender, &reply[..length]);
                }
            }
            Err(error) if error.raw() == mochi_user_syscall::EAGAIN as i64 => {
                platform::thread::yield_now()
            }
            Err(_) => platform::thread::yield_now(),
        }
    }
}

fn handle(stack: &mut NetworkStack, request: &[u8], reply: &mut [u8], now: u64) -> Option<usize> {
    let header = Header::decode(request).ok()?;
    match header.opcode {
        Opcode::Ping => {
            let (request_id, target) = decode_ping(request).ok()?;
            let (status, rtt) = match stack.ping(target, now) {
                Ok(rtt) => (0, rtt),
                Err(errno) => (-(errno as i32), 0),
            };
            encode_ping_result(request_id, status, rtt, &mut reply[..PING_RESULT_LEN]).ok()
        }
        Opcode::GetStackStatistics => {
            let request_id = decode_empty(Opcode::GetStackStatistics, request).ok()?;
            let mut stats = stack.statistics();
            if let Ok(device) = stack.driver_statistics() {
                stats.rx_errors = stats.rx_errors.saturating_add(device.rx_errors);
                stats.rx_dropped = stats.rx_dropped.saturating_add(device.rx_dropped);
                stats.tx_errors = stats.tx_errors.saturating_add(device.tx_errors);
                stats.tx_dropped = stats.tx_dropped.saturating_add(device.tx_dropped);
            }
            encode_stack_statistics(request_id, stats, &mut reply[..STACK_STATISTICS_LEN]).ok()
        }
        _ => None,
    }
}

fn idle() -> ! {
    loop {
        platform::thread::yield_now()
    }
}
