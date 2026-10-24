//! No-NIC integration: failed device and service endpoints must complete both
//! synchronous and one-way requests, with authenticated capability checks.
#[cfg(not(target_os = "mochios"))]
fn main() {
    eprintln!("network-unavailable: SKIP (requires mochiOS without a NIC)");
}
#[cfg(target_os = "mochios")]
fn main() {
    use mochi_user_platform as p;
    use mochios_net_device_protocol as w;
    unsafe extern "C" {
        fn alarm(seconds: u32) -> u32;
    }
    unsafe {
        alarm(90);
    }
    fn find(name: &str) -> u64 {
        let start = p::time::ticks().unwrap();
        loop {
            if let Ok(endpoint) = p::process::find_by_name(name) {
                if endpoint != 0 {
                    return endpoint;
                }
            }
            assert!(
                p::time::ticks().unwrap().saturating_sub(start) < 15000,
                "endpoint unavailable: {name}"
            );
            p::thread::yield_now();
        }
    }
    fn call(endpoint: u64, request: &[u8], reply: &mut [u8]) -> usize {
        let result = p::ipc::call(endpoint, request, reply).unwrap();
        let n = result as u32 as usize;
        assert!(n <= reply.len());
        n
    }
    fn completion(request: &[u8], endpoint: u64, reply: &mut [u8]) -> usize {
        p::ipc::send(endpoint, request).unwrap();
        let start = p::time::ticks().unwrap();
        loop {
            match p::ipc::try_wait(reply) {
                Ok(result) => {
                    let n = result as u32 as usize;
                    assert!(n <= reply.len());
                    if w::Header::decode(&reply[..n]).is_ok() {
                        return n;
                    }
                }
                Err(error) => assert_eq!(
                    error.native_error(),
                    Some(mochi_user_syscall::NativeError::NotReady)
                ),
            }
            assert!(
                p::time::ticks().unwrap().saturating_sub(start) < 5000,
                "one-way completion timeout"
            );
            p::thread::yield_now();
        }
    }
    let driver = find("virtio-net.driver");
    let network = find("network.service");
    let mut request = [0u8; 8192];
    let mut reply = [0u8; 8192];
    let n = w::encode_empty(w::Opcode::GetInterfaceInfo, 101, &mut request).unwrap();
    let count = call(driver, &request[..n], &mut reply);
    assert_eq!(
        w::decode_status(w::Opcode::InterfaceInfo, &reply[..count]).unwrap(),
        (101, -13)
    );
    p::io::stdout(b"network-unavailable: PASS raw driver rejects clients without net.raw\n")
        .unwrap();
    let n = w::encode_tcp_connect(102, "10.0.2.2", 12345, 1000, &mut request).unwrap();
    let count = call(network, &request[..n], &mut reply);
    let result = w::decode_tcp_connect_result(&reply[..count]).unwrap();
    assert_eq!((result.0, result.1, result.2), (102, -6, 0));
    p::io::stdout(
        b"network-unavailable: PASS synchronous TCP fails promptly with device unavailable\n",
    )
    .unwrap();
    let n = w::encode_tcp_connect(103, "10.0.2.2", 12345, 1000, &mut request).unwrap();
    let count = completion(&request[..n], network, &mut reply);
    let result = w::decode_tcp_connect_result(&reply[..count]).unwrap();
    assert_eq!((result.0, result.1, result.2), (103, -6, 0));
    p::io::stdout(
        b"network-unavailable: PASS one-way TCP completion uses native reply failure semantics\n",
    )
    .unwrap();
    let n = w::encode_tls_connect(104, "example.invalid", 443, 1000, &mut request).unwrap();
    let count = call(network, &request[..n], &mut reply);
    let result = w::decode_tls_connect_result(&reply[..count]).unwrap();
    assert_eq!(
        (
            result.request_id,
            result.status,
            result.failure,
            result.handle
        ),
        (104, -6, w::TlsFailure::Transport, 0)
    );
    let n = w::encode_http_request(
        105,
        w::HttpMethod::Get,
        1000,
        "http://example.invalid/",
        "",
        "",
        &[],
        &mut request,
    )
    .unwrap();
    let count = completion(&request[..n], network, &mut reply);
    let result = w::decode_http_request_result(&reply[..count]).unwrap();
    assert_eq!(
        (
            result.request_id,
            result.status,
            result.failure,
            result.handle
        ),
        (105, -6, w::HttpFailure::InvalidState, 0)
    );
    p::io::stdout(b"network-unavailable: PASS TLS and HTTP preserve typed unavailable failures\n")
        .unwrap();
    use w::datagram_authority as authority;
    fn acquire_authority(endpoint: u64) -> Result<u32, i32> {
        let mut response = [0; authority::REPLY_LEN];
        let mut attached = p::ipc::IpcObjectHandles::default();
        // The diagnostic discovers the existing global endpoint. Production
        // consumers will receive a process-local endpoint through bootstrap.
        let n = mochi_user_syscall::call6(
            mnu_abi::SyscallNumber::IpcCallObjectHandles,
            endpoint,
            authority::ACQUIRE.as_ptr() as u64,
            authority::ACQUIRE.len() as u64,
            response.as_mut_ptr() as u64,
            response.len() as u64,
            core::ptr::addr_of_mut!(attached) as u64,
        )
        .unwrap() as u32 as usize;
        let status = authority::status(&response[..n]).unwrap();
        if status != 0 {
            assert_eq!(attached.count, 0);
            return Err(status);
        }
        assert_eq!((attached.count, attached.delivery_flags), (1, 0));
        let object = attached.handles[0];
        assert_eq!(object.reserved, 0);
        assert_eq!(
            object.rights,
            mnu_abi::HANDLE_RIGHT_CONTROL
                | mnu_abi::HANDLE_RIGHT_DUPLICATE
                | mnu_abi::HANDLE_RIGHT_TRANSFER
        );
        Ok(object.handle)
    }
    let authority = acquire_authority(network).unwrap();
    let rights = mnu_abi::HANDLE_RIGHT_CONTROL
        | mnu_abi::HANDLE_RIGHT_DUPLICATE
        | mnu_abi::HANDLE_RIGHT_TRANSFER;
    let alias = p::handle::duplicate(authority, rights).unwrap();
    p::handle::close(authority).unwrap();
    let mut limits = [0; authority::LIMITS_LEN];
    assert_eq!(
        p::handle::control(alias, authority::QUERY_LIMITS, &[], &mut limits).unwrap(),
        limits.len()
    );
    assert_eq!(
        authority::Limits::decode(&limits).unwrap().minimum_port,
        1024
    );
    assert_eq!(
        p::handle::read(alias, &mut [0; 1])
            .unwrap_err()
            .native_error(),
        Some(mochi_user_syscall::NativeError::AccessDenied)
    );
    let forged = mnu_abi::provider::RequestHeader {
        opcode: mnu_abi::provider::OP_CONTROL,
        object_id: (1 << 60) | 1,
        argument: 0,
        basis: authority::QUERY_LIMITS,
        length: authority::LIMITS_LEN as u32,
        data_length: 0,
    };
    let n = forged.encode(&[], &mut request).unwrap();
    let count = call(network, &request[..n], &mut reply);
    assert_eq!(
        mnu_abi::provider::ResponseHeader::decode(&reply[..count])
            .unwrap()
            .0
            .status,
        -13
    );
    for _ in 0..128 {
        let object = acquire_authority(network).unwrap();
        p::handle::close(object).unwrap();
    }
    p::io::stdout(b"network-authority: PASS transfer, duplication, narrow rights, forged request rejection and final-close cleanup\n").unwrap();
    let name = b"net.connect";
    mochi_user_syscall::call2(
        mnu_abi::SyscallNumber::CapDrop,
        name.as_ptr() as u64,
        name.len() as u64,
    )
    .unwrap();
    let n = w::encode_tcp_connect(106, "10.0.2.2", 12345, 1000, &mut request).unwrap();
    let count = call(network, &request[..n], &mut reply);
    let result = w::decode_tcp_connect_result(&reply[..count]).unwrap();
    assert_eq!((result.0, result.1, result.2), (106, -13, 0));
    p::io::stdout(
        b"network-unavailable: PASS failed service still authenticates caller capabilities\n",
    )
    .unwrap();
    assert_eq!(acquire_authority(network), Err(-13));
    assert_eq!(
        p::handle::control(alias, authority::QUERY_LIMITS, &[], &mut limits).unwrap(),
        limits.len()
    );
    use w::datagram as packet;
    fn open_packet(endpoint: u64, factory: u32, local: packet::Endpoint) -> Result<u32, i32> {
        let mut request = [0; 16];
        packet::open(local, &mut request).unwrap();
        let mut response = [0; authority::REPLY_LEN];
        let mut attached = p::ipc::IpcObjectHandles::default();
        attached.count = 1;
        attached.handles[0] = p::ipc::IpcObjectHandle {
            handle: factory,
            reserved: 0,
            rights: mnu_abi::HANDLE_RIGHT_CONTROL,
        };
        let n = mochi_user_syscall::call6(
            mnu_abi::SyscallNumber::IpcCallObjectHandles,
            endpoint,
            request.as_ptr() as u64,
            request.len() as u64,
            response.as_mut_ptr() as u64,
            response.len() as u64,
            core::ptr::addr_of_mut!(attached) as u64,
        )
        .unwrap() as u32 as usize;
        let status = authority::status_for(packet::OPEN_OPCODE, &response[..n]).unwrap();
        if status != 0 {
            assert_eq!(attached.count, 0);
            return Err(status);
        }
        assert_eq!(attached.count, 1);
        assert_eq!(
            attached.handles[0].rights,
            mnu_abi::HANDLE_RIGHT_READ
                | mnu_abi::HANDLE_RIGHT_WRITE
                | mnu_abi::HANDLE_RIGHT_CONTROL
                | mnu_abi::HANDLE_RIGHT_WAIT
                | mnu_abi::HANDLE_RIGHT_DUPLICATE
                | mnu_abi::HANDLE_RIGHT_TRANSFER
        );
        Ok(attached.handles[0].handle)
    }
    fn local(handle: u32) -> packet::Endpoint {
        let mut bytes = [0; 8];
        assert_eq!(
            p::handle::control(handle, packet::LOCAL, &[], &mut bytes).unwrap(),
            8
        );
        packet::Endpoint::decode(&bytes).unwrap()
    }
    fn readable(handle: u32) {
        let mut items = [mnu_abi::HandleWaitItem {
            handle,
            interests: mnu_abi::HANDLE_SIGNAL_READABLE,
            ..Default::default()
        }];
        p::process::wait_many(
            &mut items,
            p::time::monotonic_nanoseconds().unwrap() + 5_000_000_000,
        )
        .unwrap();
    }
    let automatic = packet::Endpoint {
        address: [127, 0, 0, 1],
        port: 0,
    };
    assert_eq!(
        open_packet(
            network,
            alias,
            packet::Endpoint {
                port: 53,
                ..automatic
            }
        ),
        Err(-13)
    );
    assert_eq!(
        open_packet(
            network,
            alias,
            packet::Endpoint {
                address: [192, 0, 2, 1],
                port: 0
            }
        ),
        Err(-99)
    );
    let sender = open_packet(network, alias, automatic).unwrap();
    let receiver = open_packet(network, alias, automatic).unwrap();
    let destination = local(receiver);
    let source = local(sender);
    assert_ne!(destination.port, 0);
    assert_ne!(source.port, destination.port);
    let narrowed = p::handle::duplicate(
        receiver,
        mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_WAIT | mnu_abi::HANDLE_RIGHT_TRANSFER,
    )
    .unwrap();
    assert_eq!(
        p::handle::write(narrowed, b"denied")
            .unwrap_err()
            .native_error(),
        Some(mochi_user_syscall::NativeError::AccessDenied)
    );
    let mut frame = [0; 64];
    let n = packet::send(Some(destination), b"record-one", &mut frame).unwrap();
    assert_eq!(p::handle::write(sender, &frame[..n]).unwrap(), n);
    readable(narrowed);
    let mut peek = [0; 15];
    for _ in 0..2 {
        let n = p::handle::read_at(narrowed, &mut peek, 0).unwrap();
        let r = packet::decode_received(&peek[..n]).unwrap();
        assert_eq!(r.source, source);
        assert_eq!(r.original_length, 10);
        assert_eq!(r.payload, b"rec");
        assert!(r.truncated());
    }
    let n = p::handle::read(narrowed, &mut peek).unwrap();
    assert!(packet::decode_received(&peek[..n]).unwrap().truncated());
    assert_eq!(
        p::handle::read(narrowed, &mut frame).unwrap_err().raw(),
        -11
    );
    p::handle::close(narrowed).unwrap();
    p::io::stdout(b"network-datagram: PASS native Handle transfer, reduced rights, readiness, repeated peek and record truncation\n").unwrap();
    let mut encoded = [0; 8];
    destination.encode(&mut encoded).unwrap();
    p::handle::control(sender, packet::SET_PEER, &encoded, &mut []).unwrap();
    for _ in 0..32 {
        let resource = open_packet(
            network,
            alias,
            packet::Endpoint {
                port: 60000,
                ..automatic
            },
        )
        .unwrap();
        p::handle::close(resource).unwrap();
    }
    p::io::stdout(
        b"network-datagram: PASS final-close releases binding across 32 same-port reopens\n",
    )
    .unwrap();
    // Derived packet authority outlives the factory and ambient Capability.
    p::handle::close(alias).unwrap();
    let n = packet::send(None, &[], &mut frame).unwrap();
    assert_eq!(p::handle::write(sender, &frame[..n]).unwrap(), n);
    readable(receiver);
    let n = p::handle::read(receiver, &mut frame).unwrap();
    assert_eq!(n, packet::RECEIVE_HEADER_LEN);
    assert!(
        packet::decode_received(&frame[..n])
            .unwrap()
            .payload
            .is_empty()
    );
    let n = packet::send(
        Some(packet::Endpoint {
            address: [192, 0, 2, 2],
            port: 8000,
        }),
        b"x",
        &mut frame,
    )
    .unwrap();
    assert_eq!(p::handle::write(sender, &frame[..n]).unwrap_err().raw(), -6);
    p::handle::close(sender).unwrap();
    p::handle::close(receiver).unwrap();
    p::io::stdout(b"network-datagram: PASS empty records, default peer, factory independence and no-device rejection\n").unwrap();

    p::io::stdout(b"network-authority: PASS ambient Capability drop rejects new grants while explicit authority remains usable\n").unwrap();
}
