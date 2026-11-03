#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
use mochios_posix_client::{
    elf_mapping::{Backend, Range},
    pie::{
        Pie,
        link_scope::{
            Object, Scope,
            lookup::Version,
            resident::{Member, Operation, Phase, Resident},
        },
    },
};
use std::{
    cell::RefCell,
    collections::BTreeSet,
    path::{Path, PathBuf},
    process::Command,
    rc::Rc,
    sync::atomic::{AtomicU64, Ordering},
};

#[derive(Default)]
struct Faults {
    calls: usize,
    fail: BTreeSet<usize>,
    releases: Vec<Range>,
}
#[derive(Clone, Default)]
struct Host(Rc<RefCell<Faults>>);
impl Host {
    fn step(&self) -> Result<(), i32> {
        let mut faults = self.0.borrow_mut();
        faults.calls += 1;
        let at = faults.calls;
        if faults.fail.remove(&at) {
            Err(5)
        } else {
            Ok(())
        }
    }
}
fn os_error() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap()
}
impl Backend for Host {
    type Error = i32;
    fn critical<T>(f: impl FnOnce() -> T) -> T {
        f()
    }
    fn reserve(&self, range: Range) -> Result<(), i32> {
        self.step()?;
        map(range, 0, libc::MAP_FIXED_NOREPLACE)
    }
    fn populate(&self, range: Range) -> Result<(), i32> {
        self.step()?;
        map(range, 3, libc::MAP_FIXED)
    }
    fn write(&self, address: u64, bytes: &[u8]) -> Result<(), i32> {
        self.step()?;
        // SAFETY: the real loader owns this RW/NX reservation exclusively.
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), address as *mut u8, bytes.len()) };
        Ok(())
    }
    fn protect(&self, range: Range, access: u64) -> Result<(), i32> {
        self.step()?;
        assert_ne!(access & 6, 6, "never create W+X pages");
        if unsafe {
            libc::mprotect(
                range.address as *mut _,
                range.length as usize,
                access as i32,
            )
        } == 0
        {
            Ok(())
        } else {
            Err(os_error())
        }
    }
    fn release(&self, range: Range) -> Result<(), i32> {
        self.step()?;
        if unsafe { libc::munmap(range.address as *mut _, range.length as usize) } != 0 {
            return Err(os_error());
        }
        self.0.borrow_mut().releases.push(range);
        Ok(())
    }
}
fn map(range: Range, access: i32, flags: i32) -> Result<(), i32> {
    let pointer = unsafe {
        libc::mmap(
            range.address as *mut _,
            range.length as usize,
            access,
            flags | libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if pointer == libc::MAP_FAILED {
        Err(os_error())
    } else {
        assert_eq!(pointer as u64, range.address);
        Ok(())
    }
}
fn run(command: &mut Command) -> String {
    let result = command.output().unwrap();
    assert!(
        result.status.success(),
        "{command:?}: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8(result.stdout).unwrap()
}
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    directory: PathBuf,
    bytes: [Vec<u8>; 2],
    bases: [u64; 2],
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.directory).unwrap();
    }
}
impl Fixture {
    fn new(tls: bool) -> Self {
        let ordinal = NEXT.fetch_add(1, Ordering::Relaxed);
        let directory =
            std::env::temp_dir().join(format!("mochios-resident-{}-{ordinal}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/resident_library.c");
        // Use the real LLVM ELF linker. There is no GNU ld fallback.
        let sysroot = run(Command::new("rustc").args(["--print", "sysroot"]));
        let lld =
            Path::new(sysroot.trim()).join("lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld");
        for (root, name) in [(false, "libresident.so"), (true, "root.so")] {
            let object = directory.join(format!("{name}.o"));
            let mut cc = Command::new("clang");
            cc.args([
                "--target=x86_64-unknown-none-elf",
                "-mno-red-zone",
                "-O2",
                "-fPIC",
                "-ffreestanding",
                "-fno-stack-protector",
                "-nostdlib",
                "-c",
            ]);
            if root {
                cc.arg("-DROOT");
            } else if tls {
                cc.arg("-DDYNAMIC_TLS");
            }
            run(cc.arg(&source).arg("-o").arg(&object));
            let mut link = Command::new(&lld);
            link.args([
                "-flavor",
                "gnu",
                "-shared",
                "-z",
                "now",
                "-z",
                "relro",
                "-z",
                "noexecstack",
                "--hash-style=both",
                "-soname",
                name,
            ]);
            link.arg(&object);
            if root {
                link.arg("-L").arg(&directory).arg("-l:libresident.so");
            }
            run(link.arg("-o").arg(directory.join(name)));
        }
        let bytes =
            ["root.so", "libresident.so"].map(|name| std::fs::read(directory.join(name)).unwrap());
        let base = 0x280000000000 + ordinal * 0x1000000;
        Self {
            directory,
            bytes,
            bases: [base, base + 0x100000],
        }
    }
}
fn invoke(address: u64) -> Result<(), i32> {
    // SAFETY: the loader checks an executable LOAD in the retained scope;
    // fixture callbacks have exactly the C void(void) ABI and never unwind.
    unsafe { std::mem::transmute::<u64, unsafe extern "C" fn()>(address)() };
    Ok(())
}
fn access_at(address: u64) -> Option<String> {
    std::fs::read_to_string("/proc/self/maps")
        .unwrap()
        .lines()
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            let (start, end) = fields.next()?.split_once('-')?;
            let start = u64::from_str_radix(start, 16).ok()?;
            let end = u64::from_str_radix(end, 16).ok()?;
            (start <= address && address < end).then(|| fields.next().unwrap().to_owned())
        })
}
fn exercise(mut test: impl FnMut(&Scope<'_, '_>, &Fixture)) {
    exercise_with(|_| {}, |scope, fixture| test(scope, fixture));
}
fn exercise_with(
    mutate: impl FnOnce(&mut Fixture),
    mut test: impl FnMut(&Scope<'_, '_>, &Fixture),
) {
    let mut fixture = Fixture::new(false);
    mutate(&mut fixture);
    let images = fixture
        .bytes
        .each_ref()
        .map(|bytes| Pie::parse_object(bytes).unwrap());
    let objects = [
        Object {
            name: b"root.so",
            image: &images[0],
            bias: fixture.bases[0],
        },
        Object {
            name: b"libresident.so",
            image: &images[1],
            bias: fixture.bases[1],
        },
    ];
    let mut order = [0; 2];
    let scope = Scope::new(&objects, &mut order).unwrap();
    test(&scope, &fixture);
}

#[test]
fn failed_installation_cleanup_outlives_the_relocation_scratch_buffer() {
    exercise(|scope, fixture| {
        let host = Host::default();
        host.0.borrow_mut().fail.extend([2, 3, 4]);
        let mut slots = [const { None }; 2];
        let mut loader = Resident::new(scope, &mut slots).unwrap();
        let error = loader
            .install(&mut vec![0; 128 * 1024], || host.clone())
            .unwrap_err();
        assert!(matches!(
            error.operation,
            Operation::Memory(mochios_posix_client::elf_mapping::Error::Cleanup {
                operation: 5,
                release: 5
            })
        ));
        assert_eq!(error.cleanup, Some(5));
        assert_eq!(loader.retained(), 1);
        assert!(loader.symbol(b"evaluate", Version::Default).is_err());
        loader.close(&mut [0; 8], |_| panic!()).unwrap();
        assert_eq!(loader.retained(), 0);
        for base in fixture.bases {
            assert!(access_at(base).is_none());
        }
    });
}

#[test]
fn relro_preserves_execute_on_an_originally_executable_readable_load() {
    exercise_with(
        |fixture| {
            let bytes = &mut fixture.bytes[0];
            let table = u64::from_le_bytes(bytes[32..40].try_into().unwrap()) as usize;
            let count = u16::from_le_bytes(bytes[56..58].try_into().unwrap()) as usize;
            let mut relro = None;
            let mut file_size = None;
            for i in 0..count {
                let at = table + i * 56;
                let kind = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
                if kind == 0x6474e552 {
                    relro = Some(at);
                }
                if kind == 1 && u64::from_le_bytes(bytes[at + 16..at + 24].try_into().unwrap()) == 0
                {
                    file_size = Some(u64::from_le_bytes(
                        bytes[at + 32..at + 40].try_into().unwrap(),
                    ));
                    bytes[at + 4..at + 8].copy_from_slice(&5u32.to_le_bytes());
                    bytes[at + 40..at + 48].copy_from_slice(&4096u64.to_le_bytes());
                }
            }
            let at = relro.unwrap();
            bytes[at + 8..at + 32].fill(0);
            bytes[at + 32..at + 40].copy_from_slice(&file_size.unwrap().to_le_bytes());
            bytes[at + 40..at + 48].copy_from_slice(&4096u64.to_le_bytes());
        },
        |scope, fixture| {
            let host = Host::default();
            let mut slots = [const { None }; 2];
            let mut loader = Resident::new(scope, &mut slots).unwrap();
            loader
                .install(&mut vec![0; 128 * 1024], || host.clone())
                .unwrap();
            assert_eq!(access_at(fixture.bases[0]).as_deref(), Some("r-xp"));
            loader.initialize(&mut [0; 8], invoke).unwrap();
            let export = loader
                .symbol(b"evaluate", Version::Default)
                .unwrap()
                .unwrap();
            let function = unsafe {
                std::mem::transmute::<u64, unsafe extern "C" fn(i32) -> i32>(export.address())
            };
            assert_eq!(unsafe { function(7) }, 82);
            loader.close(&mut [0; 8], invoke).unwrap();
        },
    );
}

#[test]
fn constructors_cannot_replace_the_captured_finalizers_through_writable_arrays() {
    exercise_with(
        |fixture| {
            // A valid DSO need not place its fini array in RELRO. Remove only that
            // optional header so the test can change the live array after mapping.
            let root = &mut fixture.bytes[0];
            let offset = u64::from_le_bytes(root[32..40].try_into().unwrap()) as usize;
            let count = u16::from_le_bytes(root[56..58].try_into().unwrap()) as usize;
            for i in 0..count {
                let at = offset + i * 56;
                if u32::from_le_bytes(root[at..at + 4].try_into().unwrap()) == 0x6474e552 {
                    root[at..at + 4].fill(0);
                }
            }
        },
        |scope, _| {
            let host = Host::default();
            let mut slots = [const { None }; 2];
            let mut loader = Resident::new(scope, &mut slots).unwrap();
            loader
                .install(&mut vec![0; 128 * 1024], || host.clone())
                .unwrap();
            loader.initialize(&mut [0; 8], invoke).unwrap();
            let mut scratch = [0; 8];
            let plan = scope.lifecycle(&mut scratch).unwrap();
            let mut array = None;
            plan.finalizers(|step| {
                if let mochios_posix_client::pie::link_scope::Step::Array {
                    object: 0,
                    address,
                    ..
                } = step
                {
                    array = Some(address);
                }
            })
            .unwrap();
            let array = array.unwrap();
            assert!(access_at(array).unwrap().starts_with("rw"));
            unsafe {
                (array as *mut u64).write(0);
            }
            let mut finalized = 0;
            loader
                .close(&mut [0; 8], |address| {
                    finalized += 1;
                    invoke(address)
                })
                .unwrap();
            assert_eq!(
                finalized, 2,
                "use original callbacks despite the zeroed live fini array"
            );
        },
    );
}

#[test]
fn real_lld_libraries_initialize_resolve_execute_finalize_and_unmap() {
    exercise(|scope, fixture| {
        let host = Host::default();
        let mut slots = [const { None }; 2];
        let mut loader = Resident::new(scope, &mut slots).unwrap();
        let mut output = vec![0; 128 * 1024];
        assert!(loader.symbol(b"evaluate", Version::Default).is_err());
        loader.install(&mut output, || host.clone()).unwrap();
        output.fill(0xa5); // Mappings no longer borrow relocation scratch.
        assert_eq!(loader.phase(), Phase::Mapped);
        assert!(loader.symbol(b"evaluate", Version::Default).is_err());
        let mut called = Vec::new();
        loader
            .initialize(&mut [0; 8], |address| {
                called.push(address);
                invoke(address)
            })
            .unwrap();
        assert_eq!(
            called.len(),
            2,
            "callbacks={called:x?}; source sizes={:?}",
            fixture.bytes.each_ref().map(Vec::len)
        );
        let dependency = loader
            .symbol(b"library_value", Version::Default)
            .unwrap()
            .unwrap();
        assert_eq!(access_at(dependency.address()).as_deref(), Some("rw-p"));
        assert_eq!(unsafe { *(dependency.address() as *const i32) }, 32);
        let export = loader
            .symbol(b"evaluate", Version::Default)
            .unwrap()
            .unwrap();
        assert_eq!(access_at(export.address()).as_deref(), Some("r-xp"));
        let function = unsafe {
            std::mem::transmute::<u64, unsafe extern "C" fn(i32) -> i32>(export.address())
        };
        assert_eq!(unsafe { function(7) }, 82);
        assert!(
            loader
                .symbol(b"absent", Version::Default)
                .unwrap()
                .is_none()
        );
        assert!(loader.initialize(&mut [0; 8], invoke).is_err());
        loader
            .close(&mut [0; 8], |address| {
                called.push(address);
                invoke(address)
            })
            .unwrap();
        assert_eq!(called.len(), 4);
        assert_eq!(loader.phase(), Phase::Closed);
        assert_eq!(loader.retained(), 0);
        for base in fixture.bases {
            assert!(access_at(base).is_none());
        }
        assert!(loader.symbol(b"evaluate", Version::Default).is_err());
        assert!(loader.close(&mut [0; 8], invoke).is_err());
    });
}

#[test]
fn every_vm_failure_rolls_back_all_members_without_running_a_constructor() {
    exercise(|scope, fixture| {
        let host = Host::default();
        let mut slots: [Option<Member<Host>>; 2] = [const { None }; 2];
        let mut loader = Resident::new(scope, &mut slots).unwrap();
        loader
            .install(&mut vec![0; 128 * 1024], || host.clone())
            .unwrap();
        let operations = host.0.borrow().calls;
        loader
            .close(&mut [0; 8], |_| panic!("no init/fini before initialize"))
            .unwrap();
        for step in 1..=operations {
            let host = Host::default();
            host.0.borrow_mut().fail.insert(step);
            let mut slots = [const { None }; 2];
            let mut failed = Resident::new(scope, &mut slots).unwrap();
            assert!(
                failed
                    .install(&mut vec![0; 128 * 1024], || host.clone())
                    .is_err(),
                "operation {step}"
            );
            assert_eq!(failed.phase(), Phase::Failed);
            assert_eq!(failed.retained(), 0);
            for base in fixture.bases {
                assert!(access_at(base).is_none());
            }
        }
    });
}

#[test]
fn cleanup_failure_keeps_ownership_and_can_be_retried_without_reinitializing() {
    exercise(|scope, fixture| {
        let host = Host::default();
        let mut slots = [const { None }; 2];
        let mut loader = Resident::new(scope, &mut slots).unwrap();
        loader
            .install(&mut vec![0; 128 * 1024], || host.clone())
            .unwrap();
        let next = host.0.borrow().calls + 1;
        host.0.borrow_mut().fail.insert(next);
        let error = loader.close(&mut [0; 8], |_| panic!()).unwrap_err();
        assert!(matches!(error.operation, Operation::Memory(_)));
        assert_eq!(loader.retained(), 1);
        assert!(loader.symbol(b"evaluate", Version::Default).is_err());
        loader.close(&mut [0; 8], |_| panic!()).unwrap();
        assert_eq!(loader.retained(), 0);
        for base in fixture.bases {
            assert!(access_at(base).is_none());
        }
    });
}

#[test]
fn initialization_failure_retains_code_until_explicit_finalization() {
    exercise(|scope, _| {
        let host = Host::default();
        let mut slots = [const { None }; 2];
        let mut loader = Resident::new(scope, &mut slots).unwrap();
        loader
            .install(&mut vec![0; 128 * 1024], || host.clone())
            .unwrap();
        let error = loader.initialize(&mut [0; 8], |_| Err(14)).unwrap_err();
        assert_eq!(error.operation, Operation::Callback(14));
        assert_eq!(loader.phase(), Phase::Failed);
        assert_eq!(loader.retained(), 2);
        assert!(loader.symbol(b"evaluate", Version::Default).is_err());
        loader.close(&mut [0; 8], invoke).unwrap();
        assert_eq!(loader.retained(), 0);
    });
}

#[test]
fn late_tls_is_rejected_before_any_mapping_instead_of_publishing_bad_offsets() {
    let fixture = Fixture::new(true);
    let images = fixture
        .bytes
        .each_ref()
        .map(|bytes| Pie::parse_object(bytes).unwrap());
    let objects = [
        Object {
            name: b"root.so",
            image: &images[0],
            bias: fixture.bases[0],
        },
        Object {
            name: b"libresident.so",
            image: &images[1],
            bias: fixture.bases[1],
        },
    ];
    let mut order = [0; 2];
    let scope = Scope::new(&objects, &mut order).unwrap();
    let mut slots: [Option<Member<Host>>; 2] = [const { None }; 2];
    assert!(Resident::new(&scope, &mut slots).is_err());
    assert!(slots.iter().all(Option::is_none));
}
