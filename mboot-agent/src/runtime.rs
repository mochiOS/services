use std::fmt::Write;

use mochi_user_platform as platform;

use crate::agent::{Agent, ReadyStage};
use crate::transport::virtio::VirtioSerialTransport;

const STAGE_TOKEN_PREFIX: &str = "--mboot-stage-token=";
const RETRY_DELAY_MS: u64 = 1_000;
const POLL_DELAY_MS: u64 = 10;

pub fn run() -> ! {
    let _ = platform::logger::init_from_env();
    let stage_token = std::env::args()
        .find_map(|argument| argument.strip_prefix(STAGE_TOKEN_PREFIX).map(str::to_owned))
        .and_then(|value| value.parse::<u64>().ok());
    let started = current_ticks();
    let boot_id = loop {
        if let Some(boot_id) = generate_boot_id() {
            break boot_id;
        }
        platform::println!("mboot-agent.service: boot ID generation failed; retrying");
        let _ = platform::thread::sleep_milliseconds(RETRY_DELAY_MS);
    };
    let mut agent = Agent::new(env!("MOCHIOS_VERSION"), boot_id, started);
    let mut transport = None;
    let mut initialization_error_reported = false;

    loop {
        receive_stage_notifications(&mut agent, stage_token);
        if transport.is_none() {
            match VirtioSerialTransport::initialize() {
                Ok(initialized) => {
                    platform::println!("mboot-agent.service: virtio control transport initialized");
                    transport = Some(initialized);
                    initialization_error_reported = false;
                }
                Err(error) => {
                    if !initialization_error_reported {
                        platform::println!(
                            "mboot-agent.service: control transport unavailable error={:?}",
                            error
                        );
                        initialization_error_reported = true;
                    }
                    let _ = platform::thread::sleep_milliseconds(RETRY_DELAY_MS);
                    continue;
                }
            }
        }
        if let Some(active) = transport.as_mut() {
            let _ = agent.tick(active, current_ticks());
        }
        let _ = platform::thread::sleep_milliseconds(POLL_DELAY_MS);
    }
}

fn receive_stage_notifications(agent: &mut Agent, expected_token: Option<u64>) {
    let mut request = [0u8; platform::service_ready::MESSAGE_LEN];
    loop {
        let received = match platform::ipc::try_wait(&mut request) {
            Ok(received) => received,
            Err(error) if error.raw() == mochi_user_syscall::EAGAIN as i64 => break,
            Err(_) => break,
        };
        let sender = received >> 32;
        let length = (received & 0xffff_ffff) as usize;
        let status = request
            .get(..length)
            .and_then(|message| platform::service_ready::decode_notification(message).ok())
            .filter(|(token, _)| Some(*token) == expected_token)
            .and_then(|(_, stage)| match stage {
                1 => Some(ReadyStage::Userspace),
                2 => Some(ReadyStage::Display),
                3 => Some(ReadyStage::Desktop),
                _ => None,
            })
            .map_or(-(mochi_user_syscall::EINVAL as i32), |stage| {
                agent
                    .mark_ready(stage)
                    .map_or(-(mochi_user_syscall::EINVAL as i32), |()| 0)
            });
        let _ = platform::ipc::reply(sender, &status.to_le_bytes());
    }
}

fn current_ticks() -> u64 {
    platform::time::ticks().unwrap_or(0)
}

fn generate_boot_id() -> Option<String> {
    let mut bytes = [0u8; 16];
    platform::random::fill(&mut bytes).ok()?;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    Some(output)
}
