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
}
