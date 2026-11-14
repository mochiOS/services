use super::*;
use mochios_posix_client::elf_mapping::Backend as _;
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
    reuse_initial: bool,
    initial_base: u64,
}
thread_local! { static READS: RefCell<Reads> = RefCell::new(Reads::default()); }
struct Reader;
// libc malloc supplies 16-aligned owned storage; the fixture has no foreign
// asynchronous callbacks. File references stay in the per-test thread's map.
unsafe impl Backend for Reader {
    fn resident_library(name: &[u8]) -> bool {
        READS.with_borrow(|r| r.reuse_initial && name == b"libresident.so")
    }

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

fn initial_exports(name: &[u8]) -> Option<(u64, u64)> {
    let base = READS.with_borrow(|r| r.initial_base);
    match name {
        b"library_value" => Some((base + 16, 4)),
        b"library_function" => Some((base, 0)),
        _ => None,
    }
}

#[test]
fn authenticated_module_reuses_initial_tls_dependency_without_mapping_or_reinitializing_it() {
    let fixture = Fixture::new(true);
    let root = mochios_elf_signature::sign_adhoc(&fixture.bytes[0]).unwrap();
    std::fs::write(fixture.directory.join("root.so"), root).unwrap();
    // The initial module need not even remain available as a pathname. Its
    // initialized image and TLS are owned by the process, not this late group.
    std::fs::remove_file(fixture.directory.join("libresident.so")).unwrap();
    let initial_host = Host::default();
    let initial_range = Range { address: fixture.bases[1], length: 4096 };
    initial_host.reserve(initial_range).unwrap();
    initial_host.populate(initial_range).unwrap();
    // A pinned initial function (return argument + 32) and initialized data.
    initial_host.write(initial_range.address, &[0x89, 0xf8, 0x83, 0xc0, 32, 0xc3]).unwrap();
    initial_host.write(initial_range.address + 16, &32i32.to_ne_bytes()).unwrap();
    initial_host.protect(initial_range, 5).unwrap();
    READS.with_borrow_mut(|r| *r = Reads { reuse_initial: true, initial_base: initial_range.address, ..Default::default() });
    let mut library = input::resident::Library::<Reader, Host, 1>::default();
    library.set_external_lookup(initial_exports).unwrap();
    library.open(&Reader, fixture.directory.join("root.so").as_os_str().as_bytes(),
        Default::default(), Default::default(), fixture.bases[0]).unwrap();
    READS.with_borrow(|r| { assert_eq!(r.verified, 1); assert_eq!(r.files.len(), 1); });
    library.install(Host::default).unwrap();
    assert_eq!(library.retained(), 1);
    library.initialize(invoke).unwrap();
    let address = library.symbol(b"evaluate").unwrap().unwrap();
    let evaluate: unsafe extern "C" fn(i32) -> i32 = unsafe { std::mem::transmute(address) };
    assert_eq!(unsafe { evaluate(7) }, 82);
    library.close(invoke).unwrap();
    drop(library);
    assert!(access_at(initial_range.address).is_some());
    assert_eq!(unsafe { (initial_range.address as *const u8).add(16).cast::<i32>().read() }, 32);
    initial_host.release(initial_range).unwrap();
    READS.with_borrow(|r| assert!(r.files.is_empty()));
}

#[test]
fn reusing_initial_dependency_never_skips_new_module_authentication() {
    let fixture = Fixture::new(true);
    READS.with_borrow_mut(|r| *r = Reads { reuse_initial: true, ..Default::default() });
    let mut library = input::resident::Library::<Reader, Host, 1>::default();
    library.set_external_lookup(initial_exports).unwrap();
    assert_eq!(library.open(&Reader, fixture.directory.join("root.so").as_os_str().as_bytes(),
        Default::default(), Default::default(), fixture.bases[0]), Err(13));
    assert_eq!(library.retained(), 0);
    drop(library);
    READS.with_borrow(|r| assert!(r.files.is_empty()));
}

#[test]
fn named_versions_cannot_be_satisfied_by_unversioned_initial_metadata() {
    let fixture = Fixture::new(true);
    let script = fixture.directory.join("versions.map");
    std::fs::write(&script, "RESIDENT_1 { global: library_value; library_function; local: *; };\n").unwrap();
    let sysroot = run(Command::new("rustc").args(["--print", "sysroot"]));
    let linker = Path::new(sysroot.trim()).join("lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld");
    run(Command::new(&linker).args(["-flavor", "gnu", "-shared", "-soname", "libresident.so"])
        .arg("--version-script").arg(&script).arg(fixture.directory.join("libresident.so.o"))
        .arg("-o").arg(fixture.directory.join("libresident.so")));
    run(Command::new(&linker).args(["-flavor", "gnu", "-shared", "-soname", "root.so"])
        .arg(fixture.directory.join("root.so.o")).arg("-L").arg(&fixture.directory)
        .arg("-l:libresident.so").arg("-o").arg(fixture.directory.join("root.so")));
    let path = fixture.directory.join("root.so");
    let bytes = std::fs::read(&path).unwrap();
    std::fs::write(&path, mochios_elf_signature::sign_adhoc(&bytes).unwrap()).unwrap();
    READS.with_borrow_mut(|r| *r = Reads { reuse_initial: true, ..Default::default() });
    let mut library = input::resident::Library::<Reader, Host, 1>::default();
    library.set_external_lookup(initial_exports).unwrap();
    assert_eq!(library.open(&Reader, path.as_os_str().as_bytes(), Default::default(),
        Default::default(), fixture.bases[0]), Err(mochios_posix_client::newlib_errno::ENOTSUP));
    assert_eq!(library.retained(), 0);
    drop(library);
    READS.with_borrow(|r| { assert_eq!(r.verified, 1); assert!(r.files.is_empty()); });
}
