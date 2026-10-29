//! Actual inherited network endpoint without net.connect. Verifies endpoint
//! SEND authority, metadata-only access and no-NIC configuration under two UIDs.
#![cfg(target_os = "mochios")]
use mochi_user_platform as p;
use mochios_posix_client::{ClientError, SyscallEndpointTransport, interfaces as client, resolver};
fn case(network: u32, uid: u32) {
    let capability = b"net.connect";
    assert_eq!(
        p::syscall::call2(
            mnu_abi::SyscallNumber::CapQuery,
            capability.as_ptr() as u64,
            capability.len() as u64
        )
        .unwrap(),
        0
    );
    let endpoint = SyscallEndpointTransport::new(network);
    for _ in 0..64 {
        let mut bytes = [0; client::MAX_REPLY];
        let snapshot = client::snapshot(&endpoint, &mut bytes).unwrap();
        let mut records = snapshot.records();
        let lo = records.next().unwrap();
        assert_eq!(lo.index, 1);
        assert_eq!(lo.name, "lo");
        assert_eq!(lo.mtu, 1500);
        assert_eq!(lo.addresses().len(), 1);
        assert!(records.next().is_none(), "no-NIC runner expected");
        let config = client::configuration(snapshot);
        assert!(!config.ipv4 && !config.ipv6);
        assert_eq!(snapshot.index("lo"), Some(1));
        assert_eq!(snapshot.index("eth0"), None);
    }
    assert!(matches!(
        resolver::acquire(
            &endpoint,
            resolver::Limits {
                scopes: resolver::A_SCOPE,
                maximum_timeout: 100
            }
        ),
        Err(ClientError::Remote(-13))
    ));
    let sender = p::handle::duplicate(network, mnu_abi::HANDLE_RIGHT_SEND).unwrap();
    let mut bytes = [0; client::MAX_REPLY];
    let snapshot = client::snapshot(&SyscallEndpointTransport::new(sender), &mut bytes).unwrap();
    assert_eq!(snapshot.index("lo"), Some(1));
    p::handle::close(sender).unwrap();
    let no_send = p::handle::duplicate(network, 0).unwrap();
    assert!(
        matches!(client::snapshot(&SyscallEndpointTransport::new(no_send),&mut bytes),Err(ClientError::Transport(error)) if error.native_error()==Some(p::syscall::NativeError::AccessDenied))
    );
    p::handle::close(no_send).unwrap();
    if uid == 0 {
        p::io::stdout(b"interfaces: PASS endpoint SEND, no ambient network capability, no-NIC snapshot and family policy euid 0\n").unwrap();
    } else {
        p::io::stdout(b"interfaces: PASS endpoint SEND, no ambient network capability, no-NIC snapshot and family policy euid 501\n").unwrap();
    }
}
pub fn run(network: u32) {
    unsafe extern "C" {
        fn fork() -> i32;
        fn seteuid(uid: u32) -> i32;
        fn geteuid() -> u32;
        fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
        fn _exit(code: i32) -> !;
        fn alarm(seconds: u32) -> u32;
    }
    for uid in [0, 501] {
        unsafe {
            let pid = fork();
            assert!(pid >= 0);
            if pid == 0 {
                alarm(30);
                assert_eq!(seteuid(uid), 0);
                assert_eq!(geteuid(), uid);
                case(network, uid);
                _exit(0);
            }
            let mut status = 0;
            assert_eq!(waitpid(pid, &mut status, 0), pid);
            assert_eq!(status, 0, "interface child uid {uid} status {status}");
        }
    }
    p::io::stdout(b"interfaces: PASS both credential children\n").unwrap();
}
