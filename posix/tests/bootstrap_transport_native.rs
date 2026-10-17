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
