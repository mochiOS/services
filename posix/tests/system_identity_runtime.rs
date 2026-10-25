#![allow(non_camel_case_types)]
use mochios_posix_client::{Client, ClientError, Transport};
use mochios_posix_protocol as posix_protocol;
use posix_service::{AuthenticatedProcess, PeerIdentity, PosixService};
use std::cell::{Cell, RefCell};
use std::ffi::{c_char, c_void};
type c_int = i32;
const EFAULT: i32 = 14;
const EIO: i32 = 5;
const EINVAL: i32 = 22;
const ENAMETOOLONG: i32 = 36;
thread_local! {
    static SERVICE: RefCell<PosixService> = const { RefCell::new(PosixService::new()) };
    static PID: Cell<u64> = const { Cell::new(70) };
    static ERRNO: Cell<i32> = const { Cell::new(71) };
    static MODE: Cell<u8> = const { Cell::new(0) };
}
struct Local;
impl Transport for Local {
    type Error = ();
    fn call(&self, request: &[u8], output: &mut [u8]) -> Result<usize, ()> {
        if MODE.get() == 1 {
            return Err(());
        }
        let (header, payload) = posix_protocol::decode(request).unwrap();
        let response = SERVICE.with_borrow_mut(|service| {
            service.handle(
                PeerIdentity {
                    process_id: PID.get(),
                    effective_uid: 0,
                    effective_gid: 0,
                },
                header,
                payload,
            )
        });
        if MODE.get() == 2 {
            let bytes = [0u8];
            return Ok(posix_protocol::encode(
                posix_protocol::Header {
                    payload_len: 1,
                    ..response.header
                },
                &bytes,
                output,
            )
            .unwrap());
        }
        Ok(posix_protocol::encode(response.header, &response.payload, output).unwrap())
    }
}
static CLIENT: Client<Local> = Client::new(Local);
fn posix_client() -> Result<&'static Client<Local>, ClientError<()>> {
    Ok(&CLIENT)
}
fn map_posix_client_error(error: ClientError<()>) -> i32 {
    match error {
        ClientError::Remote(status) => -status,
        _ => EIO,
    }
}
fn set_errno(error: i32) {
    ERRNO.set(error);
}
fn result_with_errno(result: Result<i32, i32>, failure: i32) -> i32 {
    match result {
        Ok(value) => value,
        Err(error) => {
            set_errno(error);
            failure
        }
    }
}
mod user_copy {
    use super::*;
    fn check(address: usize, length: usize) -> Result<(), i32> {
        if length == 0 {
            return Ok(());
        }
        if address < 4096 || address.checked_add(length).is_none() {
            Err(EFAULT)
        } else {
            Ok(())
        }
    }
    pub fn read(source: *const u8, output: &mut [u8]) -> Result<(), i32> {
        check(source as usize, output.len())?;
        if !output.is_empty() {
            unsafe {
                std::ptr::copy_nonoverlapping(source, output.as_mut_ptr(), output.len());
            }
        }
        Ok(())
    }
    pub fn write(output: *mut u8, bytes: &[u8]) -> Result<(), i32> {
        check(output as usize, bytes.len())?;
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), output, bytes.len());
        }
        Ok(())
    }
    pub fn write_c_string(output: *mut u8, bytes: &[u8]) -> Result<(), i32> {
        check(output as usize, bytes.len() + 1)?;
        write(output, bytes)?;
        write(unsafe { output.add(bytes.len()) }, &[0])
    }
}
#[path = "../../../user/crates/newlib-runtime/src/system_identity.rs"]
mod runtime;
fn initialize() {
    SERVICE.with_borrow_mut(|s| {
        s.initialize_bootstrap_process(
            AuthenticatedProcess {
                handle: 7,
                process_id: 70,
            },
            0,
            0,
            &[],
        )
        .unwrap();
        s.initialize_process(
            PeerIdentity {
                process_id: 70,
                effective_uid: 0,
                effective_gid: 0,
            },
            AuthenticatedProcess {
                handle: 8,
                process_id: 80,
            },
            501,
            501,
            &[],
        )
        .unwrap();
    });
}
#[test]
fn c_abi_publishes_all_five_terminated_fields_and_preserves_errno() {
    initialize();
    let mut output = [0xa5u8; 1281];
    assert_eq!(runtime::uname(output.as_mut_ptr().cast()), 0);
    assert_eq!(&output[..8], b"mochiOS\0");
    assert_eq!(&output[256..266], b"localhost\0");
    assert!(output[512..768].contains(&0));
    assert!(output[768..1024].starts_with(b"build "));
    assert!(output[1024..1280].starts_with(std::env::consts::ARCH.as_bytes()));
    assert_eq!(output[1280], 0xa5);
    assert_eq!(ERRNO.get(), 71);
    let mut node = [0xa5u8; 12];
    assert_eq!(
        runtime::gethostname(node.as_mut_ptr().cast(), node.len()),
        0
    );
    assert_eq!(&node[..10], b"localhost\0");
    assert_eq!(node[10], 0xa5);
    assert_eq!(ERRNO.get(), 71);
}
#[test]
fn c_hostname_operations_share_the_service_namespace_and_check_authority() {
    initialize();
    assert_eq!(runtime::sethostname(b"workstation".as_ptr().cast(), 11), 0);
    PID.set(80);
    let mut output = [0u8; 256];
    assert_eq!(
        runtime::gethostname(output.as_mut_ptr().cast(), output.len()),
        0
    );
    assert_eq!(&output[..12], b"workstation\0");
    assert_eq!(runtime::sethostname(b"denied".as_ptr().cast(), 6), -1);
    assert_eq!(ERRNO.get(), 1);
    assert_eq!(
        runtime::gethostname(output.as_mut_ptr().cast(), output.len()),
        0
    );
    assert_eq!(&output[..12], b"workstation\0");
    PID.set(70);
    let max = [b'x'; 255];
    assert_eq!(runtime::sethostname(max.as_ptr().cast(), max.len()), 0);
    assert_eq!(
        runtime::gethostname(output.as_mut_ptr().cast(), output.len()),
        0
    );
    assert_eq!(&output[..255], &max);
    assert_eq!(output[255], 0);
    assert_eq!(runtime::sethostname(std::ptr::null(), 0), 0);
    assert_eq!(runtime::gethostname(output.as_mut_ptr().cast(), 1), 0);
    assert_eq!(output[0], 0);
}
#[test]
fn faults_short_buffers_malformed_replies_and_service_errors_propagate() {
    initialize();
    let mut short = [0xa5u8; 9];
    assert_eq!(runtime::gethostname(short.as_mut_ptr().cast(), 9), -1);
    assert_eq!(ERRNO.get(), ENAMETOOLONG);
    assert_eq!(short, [0xa5; 9]);
    assert_eq!(runtime::gethostname(short.as_mut_ptr().cast(), 0), -1);
    assert_eq!(runtime::uname(1usize as *mut c_void), -1);
    assert_eq!(ERRNO.get(), EFAULT);
    assert_eq!(runtime::gethostname(1usize as *mut c_char, 256), -1);
    assert_eq!(ERRNO.get(), EFAULT);
    assert_eq!(runtime::sethostname(1usize as *const c_char, 256), -1);
    assert_eq!(ERRNO.get(), EINVAL);
    assert_eq!(runtime::sethostname(1usize as *const c_char, 3), -1);
    assert_eq!(ERRNO.get(), EFAULT);
    assert_eq!(runtime::sethostname(b"a\0b".as_ptr().cast(), 3), -1);
    assert_eq!(ERRNO.get(), EINVAL);
    let mut output = [0xa5u8; 1280];
    for mode in [1, 2] {
        MODE.set(mode);
        assert_eq!(runtime::uname(output.as_mut_ptr().cast()), -1);
        assert_eq!(ERRNO.get(), EIO);
        assert_eq!(output, [0xa5; 1280]);
    }
}
