//! A consistent observation of the interfaces this service actually owns.
//! Holding the delegated callable endpoint authorizes this read-only operation;
//! it confers no authority to acquire sockets or send network packets.
use mochi_user_platform as platform;
use mochios_net_device_protocol::{InterfaceInfo, interfaces as wire};
use mochios_network_stack::Ipv4Config;

pub(crate) fn encode(
    info: Option<(InterfaceInfo, Option<Ipv4Config>)>,
    out: &mut [u8],
) -> Result<usize, wire::Error> {
    let loopback = [wire::Address::V4 {
        bytes: [127, 0, 0, 1],
        prefix: 8,
        flags: wire::USABLE,
    }];
    let local = wire::Interface {
        index: 1,
        flags: wire::UP | wire::RUNNING | wire::LOOPBACK,
        // The current local datagram transport bounds payloads to the native
        // UDP message limit; include the IPv4 and UDP headers in its MTU.
        mtu: mochios_net_device_protocol::datagram::MAX_PAYLOAD as u32 + 28,
        name: "lo",
        addresses: &loopback,
    };
    let mut address = [wire::Address::V4 {
        bytes: [0; 4],
        prefix: 0,
        flags: 0,
    }];
    if let Some((info, config)) = info {
        let n = if let Some(config) = config {
            let mask = u32::from_be_bytes(config.subnet_mask);
            let prefix = mask.leading_ones();
            if mask != u32::MAX.checked_shl(32 - prefix).unwrap_or(0) || config.address == [0; 4] {
                return Err(wire::Error::Invalid);
            }
            address[0] = wire::Address::V4 {
                bytes: config.address,
                prefix: prefix as u8,
                flags: wire::USABLE,
            };
            1
        } else {
            0
        };
        let physical = wire::Interface {
            index: 2,
            flags: wire::UP | if info.link_up { wire::RUNNING } else { 0 },
            mtu: u32::from(info.mtu),
            name: "eth0",
            addresses: &address[..n],
        };
        wire::encode([local, physical].into_iter(), out)
    } else {
        wire::encode([local].into_iter(), out)
    }
}
pub(crate) fn dispatch(
    sender: u64,
    bytes: &[u8],
    handles: &platform::ipc::IpcObjectHandles,
    output: &mut [u8],
    build: impl FnOnce(&mut [u8]) -> Result<usize, wire::Error>,
) -> bool {
    if !bytes.starts_with(b"NIFS") {
        return false;
    }
    let op = bytes
        .get(6..8)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .unwrap_or(0);
    let result =
        if handles.count != 0 || handles.delivery_flags != mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE {
            Err(-13)
        } else {
            wire::operation(bytes).map_err(|_| -22).and_then(|op| {
                if op != wire::SNAPSHOT {
                    Err(-38)
                } else {
                    build(output).map_err(|e| match e {
                        wire::Error::Buffer => -75,
                        wire::Error::Invalid => -5,
                    })
                }
            })
        };
    let n = match result {
        Ok(n) => Some(n),
        Err(status) => wire::failure(op, status, output).ok(),
    };
    if let Some(n) = n {
        if platform::ipc::reply(sender, &output[..n]).is_err() {
            // A peer unable to receive the snapshot may still receive a small
            // error header. There is no mutation or new resource to repeat.
            if let Ok(n) = wire::failure(op, -75, output) {
                let _ = platform::ipc::reply(sender, &output[..n]);
            }
        }
    }
    true
}
