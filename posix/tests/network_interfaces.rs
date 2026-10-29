//! Real interface wire, client and service; only native IPC reply transport is
//! substituted. Configuration data comes from the service's actual encoder.
#![allow(dead_code)]
extern crate self as mochi_user_platform;
use mochios_net_device_protocol::{InterfaceInfo, interfaces as w};
use mochios_network_stack::Ipv4Config;
use mochios_posix_client::{
    ClientError, ObjectHandleAttachment, ObjectHandles, ObjectTransport, Transport,
    interfaces as client,
};
use std::cell::{Cell, RefCell};
#[path = "../../network/src/interfaces.rs"]
mod server;
thread_local! {
    static REPLY:RefCell<Option<(u64,Vec<u8>)>>=const {RefCell::new(None)};
    static REJECT_LARGE:Cell<bool>=const {Cell::new(false)};
}
pub mod ipc {
    pub use mnu_abi::{IpcObjectHandle, IpcObjectHandles};
    pub fn reply(sender: u64, bytes: &[u8]) -> mochi_user_syscall::SysResult<()> {
        if crate::REJECT_LARGE.get() && bytes.len() > crate::w::HEADER_LEN {
            return Err(mochi_user_syscall::SysError::from_raw(-75));
        }
        crate::REPLY.with_borrow_mut(|r| *r = Some((sender, bytes.into())));
        Ok(())
    }
}

#[test]
fn a_rejected_snapshot_reply_can_fall_back_to_a_small_explicit_error() {
    REJECT_LARGE.set(true);
    let (bytes, called) = dispatch(&w::request(w::SNAPSHOT), handles());
    REJECT_LARGE.set(false);
    assert!(called);
    assert_eq!(bytes.len(), w::HEADER_LEN);
    assert_eq!(w::decode(&bytes).unwrap().status, -75);
}

#[test]
fn a_short_client_buffer_is_rejected_before_any_ipc_call() {
    struct Never;
    impl Transport for Never {
        type Error = i32;
        fn call(&self, _: &[u8], _: &mut [u8]) -> Result<usize, i32> {
            panic!("unexpected IPC");
        }
    }
    impl ObjectTransport for Never {
        type Handle = u32;
        fn close_received_handle(&self, _: u32) {
            panic!("unexpected received Handle");
        }
        fn call_with_handles(
            &self,
            _: &[u8],
            _: &mut [u8],
            _: &mut ObjectHandles<u32>,
        ) -> Result<usize, i32> {
            panic!("unexpected IPC");
        }
    }
    for capacity in [0, 1, w::HEADER_LEN, w::MAX_REPLY - 1] {
        assert!(matches!(
            client::snapshot(&Never, &mut vec![0; capacity]),
            Err(ClientError::ResponseTooLarge)
        ));
    }
}
fn info() -> InterfaceInfo {
    InterfaceInfo {
        interface_id: 1,
        mac: [1, 2, 3, 4, 5, 6],
        link_up: true,
        mtu: 1500,
        driver_id: 3,
        device_id: 4,
        driver_name: [0; mochios_net_device_protocol::DRIVER_NAME_LEN],
    }
}
fn config() -> Ipv4Config {
    Ipv4Config {
        address: [192, 0, 2, 1],
        subnet_mask: [255, 255, 255, 0],
        gateway: [192, 0, 2, 254],
        dns: [192, 0, 2, 53],
    }
}
fn handles() -> ipc::IpcObjectHandles {
    ipc::IpcObjectHandles {
        delivery_flags: mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE,
        ..Default::default()
    }
}
fn dispatch(bytes: &[u8], h: ipc::IpcObjectHandles) -> (Vec<u8>, bool) {
    REPLY.with_borrow_mut(|r| *r = None);
    let called = Cell::new(false);
    let mut out = [0; w::MAX_REPLY];
    assert!(server::dispatch(71, bytes, &h, &mut out, |out| {
        called.set(true);
        server::encode(None, out)
    }));
    let (sender, response) = REPLY.with_borrow_mut(|r| r.take().unwrap());
    assert_eq!(sender, 71);
    (response, called.get())
}
#[test]
fn loopback_only_and_configured_interface_report_distinct_real_state() {
    let mut out = [0; w::MAX_REPLY];
    let n = server::encode(None, &mut out).unwrap();
    let s = w::decode(&out[..n]).unwrap();
    let rows = s.records().collect::<Vec<_>>();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].name, "lo");
    assert_eq!(rows[0].index, 1);
    assert_eq!(rows[0].mtu, 1500);
    assert_eq!(rows[0].flags, w::UP | w::RUNNING | w::LOOPBACK);
    assert_eq!(
        rows[0].addresses().collect::<Vec<_>>(),
        vec![w::Address::V4 {
            bytes: [127, 0, 0, 1],
            prefix: 8,
            flags: w::USABLE
        }]
    );
    assert!(!client::configuration(s).ipv4);
    assert!(!client::configuration(s).ipv6);
    let n = server::encode(Some((info(), None)), &mut out).unwrap();
    let s = w::decode(&out[..n]).unwrap();
    let physical = s.records().nth(1).unwrap();
    assert_eq!(physical.name, "eth0");
    assert_eq!(physical.index, 2);
    assert_eq!(physical.mtu, 1500);
    assert_eq!(physical.addresses().len(), 0);
    assert!(!client::configuration(s).ipv4);
    let n = server::encode(Some((info(), Some(config()))), &mut out).unwrap();
    let s = w::decode(&out[..n]).unwrap();
    let physical = s.records().nth(1).unwrap();
    assert_eq!(
        physical.addresses().next(),
        Some(w::Address::V4 {
            bytes: [192, 0, 2, 1],
            prefix: 24,
            flags: w::USABLE
        })
    );
    assert!(client::configuration(s).ipv4);
    assert!(!client::configuration(s).ipv6);
    assert_eq!(s.index("eth0"), Some(2));
    assert_eq!(s.index("ETH0"), None);
}
#[test]
fn lease_loss_and_link_state_do_not_leave_stale_or_invented_addresses() {
    let mut out = [0; w::MAX_REPLY];
    let mut nic = info();
    nic.link_up = false;
    let n = server::encode(Some((nic, Some(config()))), &mut out).unwrap();
    let s = w::decode(&out[..n]).unwrap();
    assert_eq!(s.records().nth(1).unwrap().flags, w::UP);
    assert!(client::configuration(s).ipv4);
    let n = server::encode(Some((nic, None)), &mut out).unwrap();
    let s = w::decode(&out[..n]).unwrap();
    assert_eq!(s.records().nth(1).unwrap().addresses().len(), 0);
    assert!(!client::configuration(s).ipv4);
    for mask in [[0; 4], [255; 4], [255, 0, 0, 0], [255, 255, 255, 254]] {
        let c = Ipv4Config {
            subnet_mask: mask,
            ..config()
        };
        let n = server::encode(Some((info(), Some(c))), &mut out).unwrap();
        let w::Address::V4 { prefix, .. } = w::decode(&out[..n])
            .unwrap()
            .records()
            .nth(1)
            .unwrap()
            .addresses()
            .next()
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(prefix, u32::from_be_bytes(mask).leading_ones() as u8);
    }
    for c in [
        Ipv4Config {
            subnet_mask: [255, 0, 255, 0],
            ..config()
        },
        Ipv4Config {
            address: [0; 4],
            ..config()
        },
    ] {
        assert_eq!(
            server::encode(Some((info(), Some(c))), &mut out),
            Err(w::Error::Invalid)
        );
    }
}
#[test]
fn only_explicit_endpoint_delivery_can_read_and_no_native_capability_is_granted() {
    let (bytes, called) = dispatch(&w::request(w::SNAPSHOT), handles());
    assert!(called);
    assert_eq!(w::decode(&bytes).unwrap().status, 0);
    for flags in [
        0,
        mnu_abi::IPC_DELIVERY_NATIVE_OBJECT,
        mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE | mnu_abi::IPC_DELIVERY_NATIVE_OBJECT,
        128,
    ] {
        let (bytes, called) = dispatch(
            &w::request(1),
            ipc::IpcObjectHandles {
                delivery_flags: flags,
                ..Default::default()
            },
        );
        assert!(!called);
        assert_eq!(w::decode(&bytes).unwrap().status, -13);
    }
    let mut h = handles();
    h.count = 1;
    h.handles[0] = ipc::IpcObjectHandle {
        handle: 33,
        reserved: 0,
        rights: mnu_abi::HANDLE_RIGHT_CONTROL,
    };
    let (bytes, called) = dispatch(&w::request(1), h);
    assert!(!called);
    assert_eq!(w::decode(&bytes).unwrap().status, -13);
}
#[test]
fn malformed_versions_lengths_and_unknown_operations_do_not_touch_configuration() {
    for bad in [
        b"NIFS".as_slice(),
        b"NIFS\x02\0\x01\0",
        b"NIFS\x01\0\x01\0extra",
    ] {
        let (bytes, called) = dispatch(bad, handles());
        assert!(!called);
        assert_eq!(i32::from_le_bytes(bytes[8..12].try_into().unwrap()), -22);
    }
    let (bytes, called) = dispatch(&w::request(99), handles());
    assert!(!called);
    assert_eq!(&bytes[6..8], &99u16.to_le_bytes());
    assert_eq!(i32::from_le_bytes(bytes[8..12].try_into().unwrap()), -38);
    let mut out = [0; w::MAX_REPLY];
    assert!(!server::dispatch(
        1,
        b"NDNS",
        &handles(),
        &mut out,
        |_| panic!()
    ));
    let called = Cell::new(false);
    assert!(server::dispatch(
        1,
        &w::request(1),
        &handles(),
        &mut out,
        |_| {
            called.set(true);
            Err(w::Error::Buffer)
        }
    ));
    assert!(called.get());
    let bytes = REPLY.with_borrow_mut(|r| r.take().unwrap().1);
    assert_eq!(w::decode(&bytes).unwrap().status, -75);
}
fn all_addresses() -> [w::Address; 4] {
    [
        w::Address::V4 {
            bytes: [192, 0, 2, 1],
            prefix: 24,
            flags: w::USABLE,
        },
        w::Address::V6 {
            bytes: [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            prefix: 64,
            scope: 0,
            flags: w::USABLE,
        },
        w::Address::V6 {
            bytes: [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            prefix: 64,
            scope: 77,
            flags: 0,
        },
        w::Address::V4 {
            bytes: [192, 0, 2, 2],
            prefix: 32,
            flags: 0,
        },
    ]
}
#[test]
fn heterogeneous_address_sets_preserve_scope_prefix_and_usability() {
    let a = all_addresses();
    let mut out = [0; w::MAX_REPLY];
    let n = w::encode(
        [w::Interface {
            index: 77,
            flags: w::UP,
            mtu: 9000,
            name: "network-77",
            addresses: &a,
        }]
        .into_iter(),
        &mut out,
    )
    .unwrap();
    let s = w::decode(&out[..n]).unwrap();
    let r = s.records().next().unwrap();
    assert_eq!(r.addresses().collect::<Vec<_>>(), a);
    let c = client::configuration(s);
    assert!(c.ipv4 && c.ipv6);
    let absent = [
        w::Address::V4 {
            bytes: [127, 1, 2, 3],
            prefix: 8,
            flags: w::USABLE,
        },
        w::Address::V4 {
            bytes: [0; 4],
            prefix: 0,
            flags: w::USABLE,
        },
        w::Address::V6 {
            bytes: [0; 16],
            prefix: 0,
            scope: 0,
            flags: w::USABLE,
        },
        w::Address::V6 {
            bytes: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            prefix: 128,
            scope: 0,
            flags: w::USABLE,
        },
        a[2],
        a[3],
    ];
    let n = w::encode(
        [w::Interface {
            index: 77,
            flags: w::UP,
            mtu: 1500,
            name: "net0",
            addresses: &absent,
        }]
        .into_iter(),
        &mut out,
    )
    .unwrap();
    let c = client::configuration(w::decode(&out[..n]).unwrap());
    assert!(!c.ipv4 && !c.ipv6);
}
#[test]
fn malformed_and_duplicate_interface_identities_are_rejected() {
    let a = all_addresses();
    let base = w::Interface {
        index: 77,
        flags: w::UP,
        mtu: 1500,
        name: "net0",
        addresses: &a,
    };
    let mut out = [0; w::MAX_REPLY];
    for bad in [
        w::Interface { index: 0, ..base },
        w::Interface { flags: 128, ..base },
        w::Interface { mtu: 0, ..base },
        w::Interface { name: "", ..base },
        w::Interface {
            name: "bad\0name",
            ..base
        },
        w::Interface {
            name: "bad/name",
            ..base
        },
    ] {
        assert_eq!(
            w::encode([bad].into_iter(), &mut out),
            Err(w::Error::Invalid)
        );
    }
    assert_eq!(
        w::encode(
            [
                base,
                w::Interface {
                    name: "different",
                    ..base
                }
            ]
            .into_iter(),
            &mut out
        ),
        Err(w::Error::Invalid)
    );
    assert_eq!(
        w::encode(
            [
                base,
                w::Interface {
                    index: 78,
                    addresses: &[],
                    ..base
                }
            ]
            .into_iter(),
            &mut out
        ),
        Err(w::Error::Invalid)
    );
    for address in [
        w::Address::V4 {
            bytes: [1; 4],
            prefix: 33,
            flags: 1,
        },
        w::Address::V6 {
            bytes: [1; 16],
            prefix: 129,
            scope: 0,
            flags: 1,
        },
        w::Address::V6 {
            bytes: [1; 16],
            prefix: 64,
            scope: 78,
            flags: 1,
        },
        w::Address::V4 {
            bytes: [1; 4],
            prefix: 24,
            flags: 2,
        },
    ] {
        assert_eq!(
            w::encode(
                [w::Interface {
                    addresses: &[address],
                    ..base
                }]
                .into_iter(),
                &mut out
            ),
            Err(w::Error::Invalid)
        );
    }
}
#[test]
fn every_truncated_prefix_and_reserved_header_is_rejected_without_partial_records() {
    let mut out = [0; w::MAX_REPLY];
    let n = server::encode(Some((info(), Some(config()))), &mut out).unwrap();
    for end in 0..n {
        assert!(w::decode(&out[..end]).is_err(), "prefix {end}");
    }
    for (at, byte) in [(0, b'X'), (4, 2), (8, 1), (20, 1)] {
        let mut bad = out[..n].to_vec();
        bad[at] = byte;
        assert!(w::decode(&bad).is_err());
    }
    let mut extra = out[..n].to_vec();
    extra.push(0);
    assert!(w::decode(&extra).is_err());
    let mut bad = out[..n].to_vec();
    bad[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(w::decode(&bad).is_err());
    for status in [1, i32::MIN] {
        assert_eq!(w::failure(1, status, &mut out), Err(w::Error::Invalid));
    }
}
#[test]
fn wire_and_destination_capacity_limits_fail_instead_of_truncating() {
    let mut out = [0; w::MAX_REPLY];
    let n = server::encode(None, &mut out).unwrap();
    for capacity in 0..n {
        let mut buffer = vec![0xa5; capacity + 1];
        assert!(server::encode(None, &mut buffer[..capacity]).is_err());
        assert_eq!(buffer[capacity], 0xa5);
    }
    let names = (1..=300)
        .map(|index| format!("n{index}"))
        .collect::<Vec<_>>();
    let rows = names.iter().enumerate().map(|(index, name)| w::Interface {
        index: index as u32 + 1,
        flags: 0,
        mtu: 1500,
        name,
        addresses: &[],
    });
    assert_eq!(w::encode(rows, &mut out), Err(w::Error::Buffer));
}
#[derive(Clone, Copy)]
enum Mode {
    Valid,
    Remote,
    Bad,
    Attached,
    Transport,
    Overcount,
}
struct Endpoint {
    mode: Mode,
    closed: RefCell<Vec<u32>>,
}
impl Transport for Endpoint {
    type Error = i32;
    fn call(&self, _: &[u8], _: &mut [u8]) -> Result<usize, i32> {
        panic!("metadata must use delegated endpoint")
    }
}
impl ObjectTransport for Endpoint {
    type Handle = u32;
    fn close_received_handle(&self, h: u32) {
        assert_ne!(h, 0);
        self.closed.borrow_mut().push(h);
    }
    fn call_with_handles(
        &self,
        request: &[u8],
        out: &mut [u8],
        attached: &mut ObjectHandles<u32>,
    ) -> Result<usize, i32> {
        assert_eq!(request, w::request(1));
        assert!(attached.is_empty());
        let (bytes, called) = dispatch(request, handles());
        assert!(called);
        let n = if matches!(self.mode, Mode::Remote) {
            w::failure(1, -13, out).unwrap()
        } else {
            out[..bytes.len()].copy_from_slice(&bytes);
            bytes.len()
        };
        if matches!(self.mode, Mode::Bad) {
            out[4] = 9;
        }
        if matches!(self.mode, Mode::Attached | Mode::Transport) {
            for h in [100, 100, 0] {
                attached
                    .push(ObjectHandleAttachment {
                        handle: h,
                        rights: 1,
                    })
                    .unwrap();
            }
        }
        if matches!(self.mode, Mode::Transport) {
            return Err(-5);
        }
        Ok(if matches!(self.mode, Mode::Overcount) {
            out.len() + 1
        } else {
            n
        })
    }
}
#[test]
fn client_checks_complete_replies_and_drains_only_explicitly_received_handles() {
    let mut out = [0; w::MAX_REPLY];
    for mode in [
        Mode::Valid,
        Mode::Remote,
        Mode::Bad,
        Mode::Attached,
        Mode::Transport,
        Mode::Overcount,
    ] {
        let t = Endpoint {
            mode,
            closed: RefCell::new(Vec::new()),
        };
        let result = client::snapshot(&t, &mut out);
        match mode {
            Mode::Valid => assert_eq!(result.unwrap().index("lo"), Some(1)),
            Mode::Remote => assert!(matches!(result, Err(ClientError::Remote(-13)))),
            Mode::Transport => assert!(matches!(result, Err(ClientError::Transport(-5)))),
            _ => assert!(matches!(result, Err(ClientError::MismatchedResponse))),
        }
        assert_eq!(
            *t.closed.borrow(),
            if matches!(mode, Mode::Attached | Mode::Transport) {
                vec![100]
            } else {
                vec![]
            }
        );
    }
}
