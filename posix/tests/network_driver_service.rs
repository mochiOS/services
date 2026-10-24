extern crate alloc;
extern crate self as mochi_user_platform;
use mochios_net_device_protocol as wire;
use std::cell::RefCell;
#[derive(Default)]
struct State {
    mode: u8,
    allowed: bool,
    delivered: bool,
    replies: Vec<Vec<u8>>,
    drops: usize,
    failed: usize,
    info: usize,
}
thread_local! {static STATE:RefCell<State>=RefCell::new(State::default());}
#[macro_export]
macro_rules! println{($($arg:tt)*)=>{{let _=format_args!($($arg)*);}};}
pub mod logger {
    pub fn write_status_fmt(
        _: core::fmt::Arguments<'_>,
    ) -> Result<(), mochi_user_syscall::SysError> {
        Ok(())
    }
}
pub mod thread {
    pub fn yield_now() {
        panic!("unexpected idle loop instead of a device reply")
    }
}
pub mod capability {
    pub fn check_thread(sender: u64, cap: &str) -> Result<u64, mochi_user_syscall::SysError> {
        assert_eq!((sender, cap), (77, "net.raw"));
        Ok(crate::STATE.with_borrow(|s| s.allowed as u64))
    }
}
pub mod ipc {
    pub fn try_wait(bytes: &mut [u8]) -> Result<u64, mochi_user_syscall::SysError> {
        if crate::STATE.with_borrow(|s| s.delivered) {
            std::panic::panic_any(Stop);
        }
        crate::STATE.with_borrow_mut(|s| s.delivered = true);
        let n = crate::wire::encode_empty(crate::wire::Opcode::GetInterfaceInfo, u64::MAX, bytes)
            .unwrap();
        Ok((77 << 32) | n as u64)
    }
    pub fn reply(sender: u64, bytes: &[u8]) -> Result<(), mochi_user_syscall::SysError> {
        assert_eq!(sender, 77);
        crate::STATE.with_borrow_mut(|s| {
            assert_eq!(
                s.drops, 0,
                "failed queues must retain DMA storage while serving errors"
            );
            s.replies.push(bytes.to_vec());
        });
        Ok(())
    }
    #[derive(Debug)]
    pub struct Stop;
}
mod device {
    #[derive(Debug)]
    pub enum NetError {
        QueueExhausted,
        Failure(u64),
    }
    impl NetError {
        pub fn errno(&self) -> u64 {
            match self {
                Self::QueueExhausted => mochi_user_syscall::EAGAIN,
                Self::Failure(e) => *e,
            }
        }
    }
    pub struct NetDevice;
    impl NetDevice {
        pub fn initialize() -> Result<Self, NetError> {
            crate::STATE.with_borrow(|s| {
                if s.mode == 0 {
                    Err(NetError::Failure((-6i64) as u64))
                } else {
                    Ok(Self)
                }
            })
        }
        pub fn info(&self) -> crate::wire::InterfaceInfo {
            crate::STATE.with_borrow_mut(|s| s.info += 1);
            crate::wire::InterfaceInfo {
                interface_id: 1,
                mac: [0; 6],
                link_up: true,
                mtu: 1500,
                driver_id: 1,
                device_id: 2,
                driver_name: *b"test-driver\0",
            }
        }
        pub fn poll(&mut self) -> Result<(), NetError> {
            crate::STATE.with_borrow(|s| {
                if s.mode == 2 {
                    Err(NetError::Failure(mochi_user_syscall::EIO))
                } else {
                    Ok(())
                }
            })
        }
        pub fn fail(&mut self) {
            crate::STATE.with_borrow_mut(|s| s.failed += 1);
        }
        pub fn transmit(&mut self, _: &[u8]) -> Result<(), NetError> {
            panic!("unexpected transmit")
        }
        pub fn receive(&mut self) -> Option<alloc::vec::Vec<u8>> {
            panic!("unexpected receive")
        }
        pub fn statistics(&self) -> crate::wire::DeviceStatistics {
            panic!("unexpected statistics")
        }
    }
    impl Drop for NetDevice {
        fn drop(&mut self) {
            crate::STATE.with_borrow_mut(|s| s.drops += 1);
        }
    }
}
#[path = "../../../drivers/virtio-net-driver/src/failure.rs"]
mod failure;
#[path = "../../../drivers/virtio-net-driver/src/service.rs"]
mod service;
#[test]
fn absent_and_failed_hardware_stays_responsive_without_exposing_raw_authority() {
    for (mode, allowed, status, infos, failed) in [
        (0, true, -6, 0, 0),
        (0, false, -13, 0, 0),
        (1, false, -13, 1, 0),
        (2, true, -5, 1, 1),
    ] {
        STATE.with_borrow_mut(|s| {
            *s = State {
                mode,
                allowed,
                ..Default::default()
            }
        });
        let result = std::panic::catch_unwind(service::run);
        assert!(result.unwrap_err().is::<ipc::Stop>());
        STATE.with_borrow(|s| {
            assert_eq!(s.replies.len(), 1);
            let (id, status_found) =
                wire::decode_status(wire::Opcode::InterfaceInfo, &s.replies[0]).unwrap();
            assert_eq!((id, status_found), (u64::MAX, status));
            assert_eq!(s.info, infos);
            assert_eq!(s.failed, failed);
        });
    }
}
#[test]
fn authenticated_raw_clients_still_receive_real_interface_information() {
    STATE.with_borrow_mut(|s| {
        *s = State {
            mode: 1,
            allowed: true,
            ..Default::default()
        }
    });
    let result = std::panic::catch_unwind(service::run);
    assert!(result.unwrap_err().is::<ipc::Stop>());
    STATE.with_borrow(|s| {
        assert_eq!(s.info, 2);
        let (id, info) = wire::decode_interface_info(&s.replies[0]).unwrap();
        assert_eq!((id, info.mtu), (u64::MAX, 1500));
    });
}
