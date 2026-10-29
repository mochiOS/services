use super::*;
use mochios_posix_client::pie::{
    Pie,
    link_scope::{Object, Scope},
};
use std::{collections::BTreeMap, path::PathBuf, process::Command};
struct Host;
fn system_error() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap()
}
impl Backend for Host {
    type Error = i32;
    fn critical<T>(f: impl FnOnce() -> T) -> T {
        f()
    }
    fn reserve(&self, r: Range) -> Result<(), i32> {
        map(r, 0, libc::MAP_FIXED_NOREPLACE)
    }
    fn populate(&self, r: Range) -> Result<(), i32> {
        map(r, 3, libc::MAP_FIXED)
    }
    fn write(&self, address: u64, bytes: &[u8]) -> Result<(), i32> {
        // SAFETY: tests retain the exclusively owned RW reservation. Source is
        // a separate captured Vec; the implementation itself never dereferences.
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), address as *mut u8, bytes.len()) };
        Ok(())
    }
    fn protect(&self, r: Range, access: u64) -> Result<(), i32> {
        assert_ne!(access & 6, 6);
        if unsafe { libc::mprotect(r.address as *mut _, r.length as usize, access as i32) } == 0 {
            Ok(())
        } else {
            Err(system_error())
        }
    }
    fn release(&self, r: Range) -> Result<(), i32> {
        if unsafe { libc::munmap(r.address as *mut _, r.length as usize) } == 0 {
            Ok(())
        } else {
            Err(system_error())
        }
    }
}
fn map(r: Range, access: i32, options: i32) -> Result<(), i32> {
    let p = unsafe {
        libc::mmap(
            r.address as *mut _,
            r.length as usize,
            access,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | options,
            -1,
            0,
        )
    };
    if p == libc::MAP_FAILED {
        Err(system_error())
    } else {
        assert_eq!(p as u64, r.address);
        Ok(())
    }
}
fn command(c: &mut Command) -> String {
    let o = c.output().unwrap();
    assert!(
        o.status.success(),
        "{c:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8(o.stdout).unwrap()
}
struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn fixture() -> Fixture {
    let f = Fixture(std::env::temp_dir().join(format!("mochios-map-{}", std::process::id())));
    std::fs::create_dir(&f.0).unwrap();
    let tests = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests");
    for (source, name, extra) in [
        (
            "elf_scope_dependency.c",
            "libscope.so",
            vec!["-Wl,-soname,libscope.so".to_owned()],
        ),
        (
            "elf_scope_root.c",
            "root.so",
            vec![
                "-Wl,-e,_start".to_owned(),
                format!("-L{}", f.0.display()),
                "-l:libscope.so".to_owned(),
            ],
        ),
    ] {
        command(
            Command::new("x86_64-elf-gcc")
                .args([
                    "-O2",
                    "-fPIC",
                    "-ffreestanding",
                    "-fno-stack-protector",
                    "-nostdlib",
                    "-Wl,-shared,-z,noexecstack",
                ])
                .arg(tests.join(source))
                .args(extra)
                .arg("-o")
                .arg(f.0.join(name)),
        );
    }
    f
}
fn symbols(path: PathBuf) -> BTreeMap<String, u64> {
    command(Command::new("x86_64-elf-nm").arg(path))
        .lines()
        .filter_map(|l| {
            let p: Vec<_> = l.split_whitespace().collect();
            (p.len() == 3).then(|| (p[2].to_owned(), u64::from_str_radix(p[0], 16).unwrap()))
        })
        .collect()
}
fn access_at(address: u64) -> Option<String> {
    std::fs::read_to_string("/proc/self/maps")
        .unwrap()
        .lines()
        .find_map(|l| {
            let mut fields = l.split_whitespace();
            let (start, end) = fields.next()?.split_once('-')?;
            let start = u64::from_str_radix(start, 16).ok()?;
            let end = u64::from_str_radix(end, 16).ok()?;
            (start <= address && address < end).then(|| fields.next().unwrap().to_owned())
        })
}
#[test]
fn real_gnu_scope_executes_after_seal_and_drop_releases_all_members() {
    let fixture = fixture();
    let bytes = [
        std::fs::read(fixture.0.join("root.so")).unwrap(),
        std::fs::read(fixture.0.join("libscope.so")).unwrap(),
    ];
    let pies = bytes
        .iter()
        .map(|b| Pie::parse_object(b).unwrap())
        .collect::<Vec<_>>();
    let bases = [0x200010000000, 0x200020000000];
    let objects = [
        Object {
            name: b"root.so",
            image: &pies[0],
            bias: bases[0],
        },
        Object {
            name: b"libscope.so",
            image: &pies[1],
            bias: bases[1],
        },
    ];
    let mut scratch = [0; 2];
    let scope = Scope::new(&objects, &mut scratch).unwrap();
    let mut prepared = Vec::new();
    for (i, pie) in pies.iter().enumerate() {
        let mut b = vec![0; pie.output_length().unwrap()];
        scope.write(i, &mut b).unwrap();
        prepared.push(b);
    }
    let mut owners = Vec::new();
    for b in &prepared {
        let mut o = Installation::new(Host);
        o.stage(Plan::new(b, 0).unwrap()).unwrap();
        owners.push(o);
    }
    let root = symbols(fixture.0.join("root.so"));
    let entry = bases[0] + root["_start"];
    assert_eq!(access_at(entry).as_deref(), Some("rw-p"));
    let mut mappings = Vec::new();
    for owner in &mut owners {
        owner.seal().unwrap();
        owner.commit(|mapping| mappings.push(mapping)).unwrap();
    }
    drop(owners);
    drop(prepared);
    assert_eq!(access_at(entry).as_deref(), Some("r-xp"));
    // SAFETY: the captured compiler fixture is local, syscall-free and now RX;
    // the whole validated linked scope remains owned throughout these calls.
    unsafe {
        let entry: unsafe extern "C" fn() = std::mem::transmute(entry as usize);
        entry();
        assert_eq!(*((bases[0] + root["root_override"]) as *const i32), 120);
        assert_eq!(*((bases[0] + root["root_weak_pointer"]) as *const u64), 0);
    }
    let ranges = mappings
        .iter()
        .map(|o| o.retained().unwrap())
        .collect::<Vec<_>>();
    drop(mappings);
    for r in ranges {
        assert_eq!(access_at(r.address), None);
    }
}
#[test]
fn occupied_native_range_is_never_replaced_on_reservation_failure() {
    let source = fixture::image(false, false, true);
    let plan = Plan::new(&source, 0x200030000000).unwrap();
    let mut first = Installation::new(Host);
    first.stage(plan).unwrap();
    first.seal().unwrap();
    let mut second = Installation::new(Host);
    assert!(matches!(second.stage(plan), Err(Error::Native(_))));
    drop(second);
    assert_eq!(access_at(plan.range().address).as_deref(), Some("r-xp"));
    assert_eq!(unsafe { *(plan.range().address as *const u8) }, 0x7f);
    first.release().unwrap();
    assert_eq!(access_at(plan.range().address), None);
}
