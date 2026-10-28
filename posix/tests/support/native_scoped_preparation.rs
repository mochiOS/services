//! Exercise the shared loader through real delegated pathname authority.
use core::ffi::c_void;
use mochi_user_platform as p;
use mochios_posix_client::image_preparation::{Backend, Environment, Preparation, scoped::Scoped};
use mochios_posix_client::newlib_errno::{EIO, ENOEXEC};
use mochios_posix_client::{
    Client, ClientError, ObjectHandleAttachment as Object, SyscallEndpointTransport,
};
use mochios_posix_protocol::CHECK_EXECUTABLE_RIGHTS;

unsafe extern "C" {
    fn malloc(length: usize) -> *mut c_void;
    fn free(pointer: *mut c_void);
}
fn native(error: p::syscall::SysError) -> i32 {
    mochios_posix_client::newlib_errno::from_status(error.raw())
}
fn remote(error: ClientError<p::syscall::SysError>) -> i32 {
    match error {
        ClientError::Remote(status) => {
            mochios_posix_client::newlib_errno::from_status(status as i64)
        }
        ClientError::Transport(error) => native(error),
        _ => EIO,
    }
}
struct Mechanisms;
// Only this Rust diagnostic runs here; it installs no C signal handlers.
// malloc/free provide native max_align_t storage. All Handles are newly owned.
unsafe impl Backend for Mechanisms {
    fn critical<T>(operation: impl FnOnce() -> T) -> T {
        operation()
    }
    fn allocate(length: usize) -> *mut u8 {
        unsafe { malloc(length) }.cast()
    }
    unsafe fn deallocate(pointer: *mut u8) {
        unsafe { free(pointer.cast()) };
    }
    fn close(handle: u32) {
        p::handle::close(handle).unwrap();
    }
    fn read_at(&self, image: u32, output: &mut [u8], offset: usize) -> Result<usize, i32> {
        p::handle::read_at(image, output, offset as u64).map_err(native)
    }
    fn open_library(&self, _: &[u8]) -> Result<Object<u32>, i32> {
        panic!("delegated preparation must not use ambient pathname authority")
    }
    fn validate_library(&self, _: Object<u32>) -> Result<(), i32> {
        panic!("delegated preparation must use scoped file metadata")
    }
    fn validate_captured(
        &self,
        _: mochios_posix_client::image_preparation::Source<'_>,
        _: &[u8],
    ) -> Result<(), i32> {
        // This diagnostic captures an image only; it grants no execute permit.
        Ok(())
    }
    fn entropy(&self, output: &mut [u8]) -> Result<(), i32> {
        let count = p::syscall::call2(
            p::syscall::SyscallNumber::RandomFill,
            output.as_mut_ptr() as u64,
            output.len() as u64,
        )
        .map_err(native)?;
        if count != output.len() as u64 {
            return Err(EIO);
        }
        Ok(())
    }
    fn create_image(&self, length: usize) -> Result<u32, i32> {
        let raw = p::syscall::call2(
            p::syscall::SyscallNumber::MemoryObjectCreate,
            length as u64,
            mnu_abi::MEMORY_OBJECT_RESIZABLE,
        )
        .map_err(native)?;
        u32::try_from(raw)
            .ok()
            .filter(|handle| *handle != 0)
            .ok_or(EIO)
    }
    fn write_at(&self, image: u32, bytes: &[u8], offset: usize) -> Result<usize, i32> {
        p::handle::write_at(image, bytes, offset as u64).map_err(native)
    }
    fn readonly_image(&self, image: u32) -> Result<u32, i32> {
        p::handle::duplicate(image, CHECK_EXECUTABLE_RIGHTS).map_err(native)
    }
}
struct Reference(u32);
impl Drop for Reference {
    fn drop(&mut self) {
        p::handle::close(self.0).unwrap();
    }
}

pub fn run(posix: u32, token: Object<u32>) {
    let client = Client::new(SyscallEndpointTransport::new(posix));
    let reader = Scoped::new(&client, token, &Mechanisms, remote).unwrap();
    assert_eq!(reader.identity().effective_uid, 501);
    assert!(reader.identity().is_secure());
    let file = client
        .read_scope_open(token, true, b"/system/tests/tls-root")
        .unwrap();
    let root = Reference(file.handle);
    let mut original = [0; 16];
    assert_eq!(
        p::handle::read_at(root.0, &mut original, 0).unwrap(),
        original.len()
    );
    let mut bytes = [0; 8];
    assert_eq!(p::handle::read(root.0, &mut bytes).unwrap(), bytes.len());
    assert_eq!(&bytes, &original[..8]);
    assert!(mochios_posix_client::image_preparation::needs_preparation(&reader, root.0).unwrap());
    let mut owner = Preparation::default();
    let prepared = reader
        .prepare(
            &mut owner,
            root.0,
            Environment {
                library_path: Some(b"/untrusted"),
                preload: Some(b"/untrusted.so"),
                audit: Some(b"/untrusted.so"),
            },
        )
        .unwrap();
    assert_ne!(prepared.image, root.0);
    assert_eq!(
        p::handle::rights(prepared.image).unwrap(),
        CHECK_EXECUTABLE_RIGHTS
    );
    assert!(!prepared.lifecycle.is_empty());
    assert!(!prepared.tls.is_empty());
    let executable = prepared.executable.unwrap();
    assert_eq!(
        executable.load_bias, 0,
        "fixed root placement survives shared preparation"
    );
    assert_eq!(
        p::handle::read_at(prepared.image, &mut bytes, 0).unwrap(),
        bytes.len()
    );
    assert_eq!(&bytes[..4], b"\x7fELF");
    let mut templates = [None; 4];
    let base = prepared.tls.as_ptr() as usize;
    let count = mochios_posix_client::static_tls::image::decode(
        base,
        prepared.tls.len(),
        &mut templates,
        |address, output| {
            let offset = address.checked_sub(base).ok_or(EIO)?;
            let source = prepared
                .tls
                .get(offset..offset.checked_add(output.len()).ok_or(EIO)?)
                .ok_or(EIO)?;
            output.copy_from_slice(source);
            Ok::<(), i32>(())
        },
    )
    .map_err(|_| ENOEXEC)
    .unwrap();
    assert_eq!(count, 3);
    // The IE library references TLS defined elsewhere and has no PT_TLS.
    // Its empty slot must remain present so later module IDs do not shift.
    assert!(templates[0].is_some());
    assert!(templates[1].is_some());
    assert!(templates[2].is_none());
    assert_eq!(p::handle::read(root.0, &mut bytes).unwrap(), bytes.len());
    assert_eq!(
        &bytes,
        &original[8..],
        "capturing an image must not advance its cursor"
    );
    drop(owner);
    p::io::stdout(b"shared-loader: PASS delegated euid501 DSO capture, secure search, fixed root, lifecycle, TLS, cursor preservation\n").unwrap();
}
