//! Native call/reply correlation for the production deferred-DNS controller.
//! DNS data is scripted here; physical network transport is tested separately.
use crate::resolver::{Answer, Failure};
use mochi_user_platform as p;
use mochios_net_device_protocol as wire;
use mochios_network_stack::{
    DnsRecordName, DnsRecordType, decode_dns_records, encode_dns_record_query,
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc,
};

struct Backend {
    pending: Option<DnsRecordName>,
    release: bool,
    starts: usize,
}
impl crate::resolver_rpc::Backend for Backend {
    type Query = u32;
    fn start(&mut self, name: DnsRecordName, _: u64, _: u64) -> Result<u32, i32> {
        assert!(self.pending.is_none());
        self.pending = Some(name);
        self.starts += 1;
        Ok(1)
    }
    fn take(&mut self, id: u32) -> Result<Option<Result<Answer, Failure>>, i32> {
        assert_eq!(id, 1);
        if !self.release {
            return Ok(None);
        }
        let name = self.pending.take().unwrap();
        let mut bytes = [0; 512];
        let n = encode_dns_record_query(17, &name, DnsRecordType::A, &mut bytes).unwrap();
        bytes[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        bytes[6..8].copy_from_slice(&1u16.to_be_bytes());
        let record = b"\xc0\x0c\x00\x01\x00\x01\0\0\0\x3c\0\x04\xc0\0\x02\x01";
        bytes[n..n + record.len()].copy_from_slice(record);
        let records =
            decode_dns_records(&bytes[..n + record.len()], 17, &name, DnsRecordType::A).unwrap();
        Ok(Some(Ok(Answer {
            records,
            from_cache: false,
        })))
    }
}

fn call(endpoint: u32, id: u64, name: &str, status: i32, address: [u8; 4]) {
    let mut request = [0; 512];
    let n = wire::encode_resolve_ipv4(id, name, 10000, &mut request).unwrap();
    let mut response = [0; wire::RESOLVE_RESULT_LEN];
    let mut handles = p::ipc::IpcObjectHandles::default();
    let n = p::ipc::call_object_handles(endpoint, &request[..n], &mut response, &mut handles)
        .unwrap() as u32 as usize;
    assert_eq!(handles.count, 0);
    assert_eq!(handles.delivery_flags, 0);
    assert_eq!(
        wire::decode_resolve_ipv4_result(&response[..n]).unwrap(),
        (id, status, address, false)
    );
}

pub(crate) fn run() {
    unsafe extern "C" {
        fn alarm(seconds: u32) -> u32;
        fn geteuid() -> u32;
    }
    let uid = unsafe { geteuid() };
    assert!(uid == 0 || uid == 501);
    unsafe {
        alarm(60);
    }
    p::io::stdout(b"native-dns-rpc: begin deferred reply checks\n").unwrap();
    let started = Arc::new(AtomicBool::new(false));
    let server_started = started.clone();
    let (tx, rx) = mpsc::channel();
    let server = std::thread::spawn(move || {
        let endpoint = p::ipc::create_handle().unwrap();
        tx.send(endpoint).unwrap();
        let mut replies = crate::resolver_rpc::Replies::new();
        let mut backend = Backend {
            pending: None,
            release: false,
            starts: 0,
        };
        let mut order = Vec::new();
        let deadline = p::time::ticks().unwrap() + 10000;
        while order.len() < 3 {
            assert!(
                p::time::ticks().unwrap() < deadline,
                "native DNS reply deadline"
            );
            replies.pump(&mut backend, |sender, bytes| {
                order.push(wire::Header::decode(bytes).unwrap().request_id);
                p::ipc::reply(sender, bytes).unwrap();
            });
            if order.len() == 3 {
                break;
            }
            let mut request = [0; 512];
            let mut handles = p::ipc::IpcObjectHandles::default();
            match p::ipc::try_wait_object_handles(&mut request, &mut handles) {
                Ok(message) => {
                    let n = message as u32 as usize;
                    let sender = message >> 32;
                    assert_eq!(handles.count, 0);
                    assert_eq!(
                        handles.delivery_flags,
                        mnu_abi::IPC_DELIVERY_ENDPOINT_HANDLE
                    );
                    let header = wire::Header::decode(&request[..n]).unwrap();
                    assert!(replies.dispatch(
                        &mut backend,
                        sender,
                        &request[..n],
                        p::time::ticks().unwrap(),
                        |s| p::capability::check_thread(s, "net.connect") == Ok(1),
                        |s, bytes| {
                            order.push(wire::Header::decode(bytes).unwrap().request_id);
                            p::ipc::reply(s, bytes).unwrap();
                        }
                    ));
                    if header.request_id == 7 {
                        assert!(order.is_empty());
                        server_started.store(true, Ordering::Release);
                    }
                    if header.request_id == 8 {
                        assert_eq!(order, [8]);
                        backend.release = true;
                    }
                }
                Err(error) => assert_eq!(
                    error.native_error(),
                    Some(p::syscall::NativeError::NotReady)
                ),
            }
            std::thread::yield_now();
        }
        assert_eq!(backend.starts, 1);
        assert!(backend.pending.is_none());
        p::handle::close(endpoint).unwrap();
        order
    });
    let endpoint = rx.recv().unwrap();
    let slow = std::thread::spawn(move || call(endpoint, 7, "example.com", 0, [192, 0, 2, 1]));
    let deadline = p::time::ticks().unwrap() + 5000;
    while !started.load(Ordering::Acquire) {
        assert!(p::time::ticks().unwrap() < deadline);
        std::thread::yield_now();
    }
    call(endpoint, 8, "192.0.2.2", 0, [192, 0, 2, 2]);
    slow.join().unwrap();
    let capability = b"net.connect";
    p::syscall::call2(
        p::syscall::SyscallNumber::CapDrop,
        capability.as_ptr() as u64,
        capability.len() as u64,
    )
    .unwrap();
    call(endpoint, 9, "denied.test", -13, [0; 4]);
    assert_eq!(server.join().unwrap(), [8, 7, 9]);
    if uid == 0 {
        p::io::stdout(b"native-dns-rpc: PASS deferred order, native sender authorization and cleanup euid 0\n").unwrap();
    } else {
        p::io::stdout(b"native-dns-rpc: PASS deferred order, native sender authorization and cleanup euid 501\n").unwrap();
    }
    unsafe {
        alarm(0);
    }
}
