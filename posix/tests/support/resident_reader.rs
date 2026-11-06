use super::*;
use mochios_posix_client::{
    ObjectHandleAttachment,
    image_preparation::{self as input, Backend},
};
use std::{
    collections::BTreeMap,
    fs::File,
    os::unix::{ffi::OsStrExt, fs::FileExt},
};

#[derive(Default)]
struct Reads {
    files: BTreeMap<u32, File>,
    next: u32,
    verified: usize,
}
thread_local! { static READS: RefCell<Reads> = RefCell::new(Reads::default()); }
struct Reader;
// libc malloc supplies 16-aligned owned storage; the fixture has no foreign
// asynchronous callbacks. File references stay in the per-test thread's map.
unsafe impl Backend for Reader {
    fn critical<T>(f: impl FnOnce() -> T) -> T {
        f()
    }
    fn allocate(length: usize) -> *mut u8 {
        unsafe { libc::malloc(length).cast() }
    }
    unsafe fn deallocate(pointer: *mut u8) {
        unsafe { libc::free(pointer.cast()) };
    }
    fn close(handle: u32) {
        READS.with_borrow_mut(|r| {
            assert!(r.files.remove(&handle).is_some());
        });
    }
    fn read_at(&self, handle: u32, output: &mut [u8], offset: usize) -> Result<usize, i32> {
        READS
            .with_borrow(|r| r.files[&handle].read_at(output, offset as u64))
            .map_err(|_| 5)
    }
    fn open_library(&self, path: &[u8]) -> Result<ObjectHandleAttachment<u32>, i32> {
        let path = Path::new(std::ffi::OsStr::from_bytes(path));
        let file = File::open(path).map_err(|e| e.raw_os_error().unwrap_or(5))?;
        READS.with_borrow_mut(|r| {
            r.next += 1;
            r.files.insert(r.next, file);
            Ok(ObjectHandleAttachment {
                handle: r.next,
                rights: mochios_posix_protocol::CHECK_EXECUTABLE_RIGHTS,
            })
        })
    }
    fn validate_library(&self, _: ObjectHandleAttachment<u32>) -> Result<(), i32> {
        Ok(())
    }
    fn validate_captured(&self, _: input::Source<'_>, bytes: &[u8]) -> Result<(), i32> {
        mochios_elf_signature::verify_image(bytes, None, &Default::default()).map_err(|_| 13)?;
        READS.with_borrow_mut(|r| r.verified += 1);
        Ok(())
    }
    fn entropy(&self, output: &mut [u8]) -> Result<(), i32> {
        output.fill(0);
        Ok(())
    }
    fn create_image(&self, _: usize) -> Result<u32, i32> {
        panic!("resident needs no exec container")
    }
    fn write_at(&self, _: u32, _: &[u8], _: usize) -> Result<usize, i32> {
        panic!("unexpected container")
    }
    fn readonly_image(&self, _: u32) -> Result<u32, i32> {
        panic!("unexpected container")
    }
}

fn signed_fixture() -> Fixture {
    let mut fixture = Fixture::new(false);
    for (index, name) in ["root.so", "libresident.so"].iter().enumerate() {
        let signed = mochios_elf_signature::sign_adhoc(&fixture.bytes[index]).unwrap();
        std::fs::write(fixture.directory.join(name), &signed).unwrap();
        fixture.bytes[index] = signed;
    }
    fixture
}

#[test]
fn owned_graph_authenticates_dependencies_before_mapping_then_calls_and_releases() {
    let fixture = signed_fixture();
    READS.with_borrow_mut(|r| *r = Reads::default());
    let mut library = input::resident::Library::<Reader, Host, 2>::default();
    let path = fixture.directory.join("root.so");
    let env = input::Environment {
        library_path: Some(fixture.directory.as_os_str().as_bytes()),
        ..Default::default()
    };
    library
        .open(
            &Reader,
            path.as_os_str().as_bytes(),
            env,
            Default::default(),
            fixture.bases[0],
        )
        .unwrap();
    READS.with_borrow(|r| {
        assert_eq!(r.verified, 2);
        assert_eq!(r.files.len(), 2); // pin opened inode identities until retirement
    });
    let host = Host::default();
    library.install(|| host.clone()).unwrap();
    library.initialize(invoke).unwrap();
    let address = library.symbol(b"evaluate").unwrap().unwrap();
    let evaluate: unsafe extern "C" fn(i32) -> i32 = unsafe { std::mem::transmute(address) };
    assert_eq!(unsafe { evaluate(7) }, 82);
    assert_eq!(library.symbol(b"absent").unwrap(), None);
    library.close(invoke).unwrap();
    assert_eq!(library.retained(), 0);
    drop(library);
    READS.with_borrow(|r| assert!(r.files.is_empty()));
    for range in &host.0.borrow().releases {
        assert!(access_at(range.address).is_none());
    }
}

#[test]
fn unauthenticated_dependency_never_allocates_executable_memory_or_leaks_files() {
    let fixture = signed_fixture();
    let mut altered = fixture.bytes[1].clone();
    // Corrupt authenticated code rather than an ignored non-loadable trailer.
    altered[0] ^= 1;
    std::fs::write(fixture.directory.join("libresident.so"), altered).unwrap();
    READS.with_borrow_mut(|r| *r = Reads::default());
    let mut library = input::resident::Library::<Reader, Host, 2>::default();
    let path = fixture.directory.join("root.so");
    let env = input::Environment {
        library_path: Some(fixture.directory.as_os_str().as_bytes()),
        ..Default::default()
    };
    assert_eq!(
        library.open(
            &Reader,
            path.as_os_str().as_bytes(),
            env,
            Default::default(),
            fixture.bases[0]
        ),
        Err(13)
    );
    assert_eq!(library.retained(), 0);
    drop(library);
    READS.with_borrow(|r| {
        assert_eq!(r.verified, 1);
        assert!(r.files.is_empty());
    });
}

#[test]
fn different_roots_report_their_shared_dependency_before_a_second_mapping() {
    let fixture = signed_fixture();
    // Change only DT_SONAME, preserving valid code and dependency references.
    let alternate = Fixture::new(false);
    let mut different = alternate.bytes[0].clone();
    let at = different
        .windows(8)
        .position(|bytes| bytes == b"root.so\0")
        .unwrap();
    different[at..at + 7].copy_from_slice(b"toor.so");
    let different = mochios_elf_signature::sign_adhoc(&different).unwrap();
    let second = fixture.directory.join("second.so");
    std::fs::write(&second, different).unwrap();
    READS.with_borrow_mut(|r| *r = Reads::default());
    let mut first = input::resident::Library::<Reader, Host, 2>::default();
    let mut next = input::resident::Library::<Reader, Host, 2>::default();
    let env = input::Environment {
        library_path: Some(fixture.directory.as_os_str().as_bytes()),
        ..Default::default()
    };
    first
        .open(
            &Reader,
            b"root.so",
            env,
            Default::default(),
            fixture.bases[0],
        )
        .unwrap();
    next.open(
        &Reader,
        second.as_os_str().as_bytes(),
        env,
        Default::default(),
        fixture.bases[0] + 0x200000,
    )
    .unwrap();
    assert_ne!(first.source(), next.source());
    assert!(first.intersects(&next));
    assert_eq!(first.retained(), 0);
    assert_eq!(next.retained(), 0);
    drop((first, next));
    READS.with_borrow(|r| assert!(r.files.is_empty()));
}
