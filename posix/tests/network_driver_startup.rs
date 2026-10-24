extern crate alloc;
extern crate self as mochi_user_platform;
use mochios_net_device_protocol as wire;
use std::cell::RefCell;
pub mod syscall {
    pub use mochi_user_syscall::*;
}
#[path = "../../network/src/driver.rs"]
mod driver;
#[path = "../../../drivers/virtio-net-driver/src/failure.rs"]
mod failure;
#[path = "../../network/src/status.rs"]
mod status;
#[derive(Default)]
struct State {
    status: i32,
    mode: u8,
    calls: usize,
}
thread_local! {static STATE:RefCell<State>=RefCell::new(State::default());}
pub mod process {
    pub fn find_by_name(name: &str) -> Result<u64, mochi_user_syscall::SysError> {
        assert_eq!(name, "virtio-net.driver");
        Ok(77)
    }
}
pub mod time {
    pub fn ticks() -> Result<u64, mochi_user_syscall::SysError> {
        Ok(0)
    }
}
pub mod thread {
    pub fn yield_now() {
        panic!("driver endpoint should already exist")
    }
}
pub mod ipc {
    pub fn call(
        endpoint: u64,
        request: &[u8],
        reply: &mut [u8],
    ) -> Result<u64, mochi_user_syscall::SysError> {
        assert_eq!(endpoint, 77);
        crate::STATE.with_borrow_mut(|s| {
            s.calls += 1;
            if s.mode == 5 {
                return Err(mochi_user_syscall::SysError::from_raw(
                    mochi_user_syscall::NativeError::PeerClosed.into_raw() as i64,
                ));
            }
            let len = crate::failure::reply(s.status, request, reply).unwrap();
            match s.mode {
                1 => reply[16] ^= 1,
                2 => reply[6..8]
                    .copy_from_slice(&(crate::wire::Opcode::TransmitComplete as u16).to_le_bytes()),
                3 => reply[24..28].copy_from_slice(&0i32.to_le_bytes()),
                4 => reply[24..28].copy_from_slice(&13i32.to_le_bytes()),
                _ => {}
            }
            Ok((77 << 32) | len as u64)
        })
    }
}
#[test]
fn failed_device_answers_all_supported_requests_with_the_original_signed_status() {
    STATE.with_borrow_mut(|s| {
        *s = State {
            status: wire::STATUS_NETWORK_UNAVAILABLE,
            ..Default::default()
        }
    });
    let mut client = driver::DriverClient::connect(10).unwrap();
    assert!(matches!(client.info(),Err(error)if error==(-6i64)as u64));
    assert!(matches!(client.statistics(),Err(error)if error==(-6i64)as u64));
    assert_eq!(client.transmit(&[0u8; 60]), Err((-6i64) as u64));
    assert!(matches!(client.receive(),Err(error)if error==(-6i64)as u64));
    STATE.with_borrow(|s| assert_eq!(s.calls, 4));
}
#[test]
fn metadata_does_not_turn_malformed_or_unrelated_failure_frames_into_success() {
    for mode in 1..=4 {
        STATE.with_borrow_mut(|s| {
            *s = State {
                status: -6,
                mode,
                ..Default::default()
            }
        });
        let mut client = driver::DriverClient::connect(10).unwrap();
        assert!(matches!(client.info(),Err(error)if error==mochi_user_syscall::EIO));
    }
    STATE.with_borrow_mut(|s| {
        *s = State {
            status: -6,
            mode: 5,
            ..Default::default()
        }
    });
    let mut client = driver::DriverClient::connect(10).unwrap();
    assert!(
        matches!(client.info(),Err(error)if error==mochi_user_syscall::NativeError::PeerClosed.into_raw())
    );
}
#[test]
fn failed_device_still_validates_frames_and_never_encodes_success() {
    let mut request = [0u8; wire::HEADER_LEN];
    let mut reply = [0u8; wire::INTERFACE_INFO_LEN];
    for (op, response) in [
        (wire::Opcode::GetInterfaceInfo, wire::Opcode::InterfaceInfo),
        (wire::Opcode::GetStatistics, wire::Opcode::Statistics),
        (wire::Opcode::ReceiveFrame, wire::Opcode::FrameReceived),
    ] {
        wire::encode_empty(op, 17, &mut request).unwrap();
        for status in [0, 13, i32::MIN, -6] {
            let n = failure::reply(status, &request, &mut reply).unwrap();
            let (id, status) = wire::decode_status(response, &reply[..n]).unwrap();
            assert_eq!(id, 17);
            assert!(status < 0 && status != i32::MIN);
        }
        request[12] = 1;
        assert_eq!(failure::reply(-6, &request, &mut reply), None);
    }
}
