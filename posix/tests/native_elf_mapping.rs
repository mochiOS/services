//! Actual native reserve/populate/copy/protect/unmap operations, with bounded
//! admission and two linked DSO members. No native service or path is added.
#![cfg(target_os = "mochios")]
use mochi_user_platform as p;
use mochi_user_syscall::{SyscallNumber, call3};
use mochios_posix_client::elf_mapping::{
    Installation, Phase, Plan,
    native::{Critical, Memory},
};
use mochios_posix_client::pie::{
    Pie,
    link_scope::{Object, Scope},
};
use mochios_posix_client::{Client, SyscallEndpointTransport};
use mochios_posix_protocol as w;
// This Rust-only probe installs no callback that abandons Rust frames. A libc
// loader must supply the runtime's real native-delivery guard instead.
struct RustCallbacks;
impl Critical for RustCallbacks {
    fn run<T>(f: impl FnOnce() -> T) -> T {
        f()
    }
}
unsafe extern "C" {
    fn fork() -> i32;
    fn seteuid(uid: u32) -> i32;
    fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
    fn _exit(code: i32) -> !;
}
fn copy_fails(destination: u64, source: u64) {
    assert_eq!(
        call3(SyscallNumber::MemoryCopy, destination, source, 1)
            .unwrap_err()
            .native_error(),
        Some(mnu_abi::status::Error::InvalidAddress)
    );
}
fn probe(posix: u32, case: u8) {
    let client = Client::new(SyscallEndpointTransport::new(posix));
    let ceiling = client.resource_limit(0, w::RLIMIT_AS, None).unwrap().soft;
    let bytes = [
        std::fs::read("/system/tests/elf-mapping-297/root.so").unwrap(),
        std::fs::read("/system/tests/elf-mapping-297/libmapping.so").unwrap(),
    ];
    let images = bytes
        .iter()
        .map(|b| Pie::parse_object(b).unwrap())
        .collect::<Vec<_>>();
    let bases = [0x26000000, 0x27000000];
    let members = [
        Object {
            name: b"root.so",
            image: &images[0],
            bias: bases[0],
        },
        Object {
            name: b"libmapping.so",
            image: &images[1],
            bias: bases[1],
        },
    ];
    let mut order = [0; 2];
    let scope = Scope::new(&members, &mut order).unwrap();
    let mut prepared = Vec::new();
    for (i, image) in images.iter().enumerate() {
        let mut out = vec![0; image.output_length().unwrap()];
        scope.write(i, &mut out).unwrap();
        prepared.push(out);
    }
    let entry = images[0].executable(bases[0]).unwrap().entry;
    let mut byte = 0u8;
    copy_fails((&mut byte as *mut u8) as u64, entry);
    let mut denied = Installation::new(Memory::<RustCallbacks>::new(0));
    assert!(denied.stage(Plan::new(&prepared[0], 0).unwrap()).is_err());
    assert_eq!(denied.retained(), None);
    drop(denied);
    let mut owners = Vec::new();
    for image in &prepared {
        let mut owner = Installation::new(Memory::<RustCallbacks>::new(ceiling));
        owner.stage(Plan::new(image, 0).unwrap()).unwrap();
        assert_eq!(owner.phase(), Phase::Staged);
        owners.push(owner);
    }
    let mut collision = Installation::new(Memory::<RustCallbacks>::new(ceiling));
    assert!(
        collision
            .stage(Plan::new(&prepared[0], 0).unwrap())
            .is_err()
    );
    drop(collision);
    let mut mappings = Vec::new();
    for owner in &mut owners {
        owner.seal().unwrap();
        owner.commit(|mapping| mappings.push(mapping)).unwrap();
        assert_eq!(owner.phase(), Phase::Closed);
        assert!(owner.seal().is_err());
    }
    drop(owners);
    copy_fails(entry, (&byte as *const u8) as u64);
    // SAFETY: all captured members were relocated together, are now sealed,
    // and stay owned. The fixture is syscall-free C with a documented ABI.
    let run: unsafe extern "C" fn() -> i32 = unsafe { core::mem::transmute(entry as usize) };
    assert_eq!(unsafe { run() }, 120);
    let child = unsafe { fork() };
    assert!(child >= 0);
    if child == 0 {
        assert_eq!(unsafe { run() }, 121);
        unsafe { _exit(0) }
    }
    let mut status = -1;
    assert_eq!(unsafe { waitpid(child, &mut status, 0) }, child);
    assert_eq!(status, 0);
    assert_eq!(
        unsafe { run() },
        121,
        "child private data must not modify the parent"
    );
    for owner in &mut mappings {
        owner.release().unwrap();
        assert!(!owner.is_ready());
    }
    copy_fails((&mut byte as *mut u8) as u64, entry);
    // Reuse the same addresses after complete release, including sparse BSS.
    drop(mappings);
    let mut fresh = Vec::new();
    for image in &prepared {
        let mut owner = Installation::new(Memory::<RustCallbacks>::new(ceiling));
        owner.stage(Plan::new(image, 0).unwrap()).unwrap();
        owner.seal().unwrap();
        owner.commit(|mapping| fresh.push(mapping)).unwrap();
    }
    drop(prepared);
    assert_eq!(
        unsafe { run() },
        120,
        "fresh LOADs must have new zero-filled BSS"
    );
    drop(fresh);
    copy_fails((&mut byte as *mut u8) as u64, entry);
    println!(
        "elf-mapping-native: DSO scope/W^X/BSS/limit/collision/fork/release/reload PASS euid={}",
        if case == 0 { 0 } else { 501 }
    );
}
pub fn run(posix: u32) {
    for case in [0u8, 1] {
        let child = unsafe { fork() };
        assert!(child >= 0);
        if child == 0 {
            if case == 1 {
                assert_eq!(unsafe { seteuid(501) }, 0);
            }
            probe(posix, case);
            unsafe { _exit(0) }
        }
        let mut status = -1;
        assert_eq!(unsafe { waitpid(child, &mut status, 0) }, child);
        assert_eq!(status, 0);
    }
    p::io::stdout(b"elf-mapping-native: PASS native LOAD installation UID0/501\n").unwrap();
}
