#[allow(dead_code)]
#[path = "../../capability/src/bootstrap_file.rs"]
mod bootstrap_file;

use mochi_user_platform::syscall::{NativeError, SysError};

#[test]
fn bootstrap_reads_preserve_native_transport_failures_without_retry_or_translation() {
    for failure in [
        NativeError::PeerClosed,
        NativeError::AccessDenied,
        NativeError::NotReady,
        NativeError::ResourceUnavailable,
        NativeError::LimitExceeded,
    ] {
        for directory in [false, true] {
            let mut calls = 0;
            let result = {
                let mut client =
                    bootstrap_file::Client::new(7, |endpoint, _: &[u8], _: &mut [u8]| {
                        assert_eq!(endpoint, 7);
                        calls += 1;
                        Err(SysError::from_raw(failure.into_raw() as i64))
                    });
                if directory {
                    client.read_dir_names("/directory", 1024).map(|_| ())
                } else {
                    client.read_file("/file", 16).map(|_| ())
                }
            };
            assert_eq!(result.unwrap_err().native_error(), Some(failure));
            assert_eq!(calls, 1);
        }
    }
}

#[test]
fn directory_budget_exhaustion_is_a_native_limit_not_a_posix_errno() {
    use mochios_filesystem_protocol as wire;
    let mut client = bootstrap_file::Client::new(7, |_, request: &[u8], reply: &mut [u8]| {
        let (request, _) = wire::decode(request).unwrap();
        wire::encode(
            wire::Header {
                opcode: wire::OP_STATUS,
                request_id: request.request_id,
                offset: 1,
                flags: wire::BOOTSTRAP_EOF,
                length: 1,
                ..Default::default()
            },
            &[0],
            reply,
        )
        .map_err(|_| SysError::from_raw(-5))
    });
    let error = client.read_dir_names("/directory", 0).unwrap_err();
    assert_eq!(error.native_error(), Some(NativeError::LimitExceeded));
    assert_ne!(error.raw(), -75);
}
