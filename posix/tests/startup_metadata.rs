use mochios_posix_client::{
    ObjectHandleAttachment,
    image_preparation::{Backend, Source},
    newlib_errno::*,
    process_image::{self, Process},
    startup_metadata::{Layout, MAX_BYTES, Owner, READER_RIGHTS},
};
use std::cell::{Cell, RefCell};
thread_local! {
    static STATE: RefCell<State> = RefCell::new(State::default());
    static CRITICAL: Cell<usize> = const { Cell::new(0) };
}
#[derive(Default)]
struct State {
    created: usize,
    closed: Vec<u32>,
    bytes: Vec<u8>,
    failure: u8,
    rights: u64,
    writes: usize,
}
struct Fake;
unsafe impl Backend for Fake {
    fn critical<T>(f: impl FnOnce() -> T) -> T {
        CRITICAL.set(CRITICAL.get() + 1);
        let result = f();
        CRITICAL.set(CRITICAL.get() - 1);
        result
    }
    fn allocate(_: usize) -> *mut u8 {
        panic!("metadata transport does not allocate scratch")
    }
    unsafe fn deallocate(_: *mut u8) {
        panic!("no allocation")
    }
    fn close(h: u32) {
        assert!(CRITICAL.get() > 0);
        STATE.with_borrow_mut(|s| s.closed.push(h));
    }
    fn read_at(&self, _: u32, _: &mut [u8], _: usize) -> Result<usize, i32> {
        panic!("no source read")
    }
    fn open_library(&self, _: &[u8]) -> Result<ObjectHandleAttachment<u32>, i32> {
        panic!("no pathname lookup")
    }
    fn validate_library(&self, _: ObjectHandleAttachment<u32>) -> Result<(), i32> {
        panic!("no library")
    }
    fn validate_captured(&self, _: Source<'_>, _: &[u8]) -> Result<(), i32> {
        panic!("no validation substitution")
    }
    fn entropy(&self, _: &mut [u8]) -> Result<(), i32> {
        panic!("caller supplies randomness")
    }
    fn create_image(&self, length: usize) -> Result<u32, i32> {
        assert!(CRITICAL.get() > 0);
        STATE.with_borrow_mut(|s| {
            s.created += 1;
            if s.failure == 1 {
                return Err(ENOMEM);
            }
            s.bytes = vec![0; length];
            Ok(50)
        })
    }
    fn write_at(&self, h: u32, b: &[u8], offset: usize) -> Result<usize, i32> {
        assert_eq!(h, 50);
        assert_eq!(CRITICAL.get(), 0);
        STATE.with_borrow_mut(|s| {
            s.writes += 1;
            if s.failure == 2 {
                return Err(EIO);
            }
            if s.failure == 3 {
                return Ok(0);
            }
            if s.failure == 4 {
                return Ok(b.len() + 1);
            }
            let n = b.len().min(173);
            s.bytes[offset..offset + n].copy_from_slice(&b[..n]);
            Ok(n)
        })
    }
    fn readonly_image(&self, _: u32) -> Result<u32, i32> {
        panic!("mapping needs MAP authority")
    }
    fn readonly_metadata(&self, h: u32) -> Result<u32, i32> {
        assert_eq!(h, 50);
        assert!(CRITICAL.get() > 0);
        STATE.with_borrow_mut(|s| {
            s.rights = READER_RIGHTS;
            match s.failure {
                5 => Err(EACCES),
                6 => Ok(0),
                7 => Ok(50),
                _ => Ok(51),
            }
        })
    }
}
fn reset(failure: u8) {
    STATE.with_borrow_mut(|s| {
        *s = State {
            failure,
            ..Default::default()
        }
    });
}
fn encode(owner: &mut Owner<Fake>, process: Process<'_>, out: &mut [u8]) -> Result<usize, i32> {
    owner.encode(
        &Fake,
        &[b"/tool", b"argument"],
        &[b"KEEP=1"],
        b"/tool",
        [0; 16],
        &[],
        process,
        out,
    )
}
fn aux(stack: &[u8]) -> Vec<(u64, u64, usize)> {
    let word = |at| u64::from_le_bytes(stack[at..at + 8].try_into().unwrap());
    let mut at = (word(0) as usize + 2) * 8;
    while word(at) != 0 {
        at += 8;
    }
    at += 8;
    let mut result = Vec::new();
    while word(at) != 0 {
        result.push((word(at), word(at + 8), at + 8));
        at += 16;
    }
    result
}
#[test]
fn large_payloads_share_one_readonly_mapping_and_preserve_small_entry_vectors() {
    reset(0);
    let life = vec![1; 5001];
    let tls = vec![2; 5002];
    let indirect = vec![3; 5003];
    let process = Process {
        lifecycle: &life,
        tls: &tls,
        indirect: &indirect,
        ..Default::default()
    };
    let mut owner = Owner::<Fake>::default();
    let mut out = vec![0; mnu_abi::process_image::MAX_IMAGE_BYTES];
    let length = encode(&mut owner, process, &mut out).unwrap();
    let mapping = owner.mapping().unwrap();
    assert_eq!(mapping.length, 16384);
    assert_eq!(mapping.access, mnu_abi::MEMORY_ACCESS_READ);
    assert_eq!(mapping.options, mnu_abi::MEMORY_MAP_SHARED);
    assert_eq!(mapping.backing_handle, 51);
    let image = mnu_abi::process_image::decode(&out[..length]).unwrap();
    assert!(image.stack().len() < 1024);
    let entries = aux(image.stack());
    for (key, offset) in [
        (process_image::AT_LIFECYCLE_IMAGE, 0),
        (process_image::AT_TLS_IMAGE, 5008),
        (process_image::AT_INDIRECT_IMAGE, 10016),
    ] {
        let (_, address, at) = entries.iter().find(|e| e.0 == key).unwrap();
        assert_eq!(*address, mapping.address + offset);
        assert!(!image.relocations().any(|r| r.offset as usize == *at));
    }
    STATE.with_borrow(|s| {
        assert_eq!(
            s.rights,
            mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_MAP
        );
        assert_eq!(s.closed, [50]);
        assert_eq!(&s.bytes[..5001], &life);
        assert!(s.bytes[5001..5008].iter().all(|b| *b == 0));
        assert_eq!(&s.bytes[5008..10010], &tls);
        assert_eq!(&s.bytes[10016..15019], &indirect);
        assert!(s.bytes[15019..].iter().all(|b| *b == 0));
    });
    let length = owner.attach(&mut out, length, &[]).unwrap();
    assert_eq!(
        mnu_abi::process_image::decode(&out[..length])
            .unwrap()
            .mappings()
            .collect::<Vec<_>>(),
        [mapping]
    );
    drop(owner);
    STATE.with_borrow(|s| assert_eq!(s.closed, [50, 51]));
}
#[test]
fn small_metadata_keeps_the_inline_path_and_allocates_no_native_object() {
    reset(0);
    let mut owner = Owner::<Fake>::default();
    let mut out = [0; 9000];
    let n = encode(
        &mut owner,
        Process {
            lifecycle: b"small",
            ..Default::default()
        },
        &mut out,
    )
    .unwrap();
    assert!(owner.mapping().is_none());
    let image = mnu_abi::process_image::decode(&out[..n]).unwrap();
    let (_, value, at) = aux(image.stack())
        .into_iter()
        .find(|e| e.0 == process_image::AT_LIFECYCLE_IMAGE)
        .unwrap();
    assert_eq!(&image.stack()[value as usize..value as usize + 5], b"small");
    assert!(image.relocations().any(|r| r.offset as usize == at));
    drop(owner);
    STATE.with_borrow(|s| {
        assert_eq!(s.created, 0);
        assert!(s.closed.is_empty());
    });
}
#[test]
fn mapped_stack_preflight_does_not_hide_oversized_vectors_or_short_output() {
    reset(0);
    let bytes = vec![7; 6000];
    let mut owner = Owner::<Fake>::default();
    let mut out = [0; 9000];
    assert_eq!(
        owner.encode(
            &Fake,
            &[&bytes],
            &[],
            b"tool",
            [0; 16],
            &[],
            Process {
                indirect: &bytes,
                ..Default::default()
            },
            &mut out
        ),
        Err(E2BIG)
    );
    assert!(
        encode(
            &mut owner,
            Process {
                indirect: &bytes,
                ..Default::default()
            },
            &mut [0; 32]
        )
        .is_err()
    );
    STATE.with_borrow(|s| assert_eq!(s.created, 0));
}
#[test]
fn every_failed_creation_write_and_attenuation_remains_owned_until_cleanup() {
    let bytes = vec![8; 6000];
    for failure in 1..=7 {
        reset(failure);
        let mut owner = Owner::<Fake>::default();
        assert!(
            encode(
                &mut owner,
                Process {
                    indirect: &bytes,
                    ..Default::default()
                },
                &mut [0; 9000]
            )
            .is_err(),
            "stage={failure}"
        );
        assert!(owner.mapping().is_none());
        drop(owner);
        STATE.with_borrow(|s| {
            assert_eq!(
                s.closed,
                if failure == 1 { vec![] } else { vec![50] },
                "stage={failure}"
            )
        });
    }
}
#[test]
fn layout_checks_user_addresses_combined_capacity_and_payload_binding() {
    let bytes = vec![0; MAX_BYTES];
    let p = Process {
        indirect: &bytes,
        ..Default::default()
    };
    assert_eq!(Layout::new(0x3000_0000, p).unwrap().length(), MAX_BYTES);
    assert!(
        Layout::new(
            0x3000_0000,
            Process {
                lifecycle: b"x",
                ..p
            }
        )
        .is_err()
    );
    for base in [0, 4096, 0x3000_0001, 0x7fff_ffff_f000, u64::MAX - 4095] {
        assert!(Layout::new(base, p).is_err());
    }
    let layout = Layout::new(
        0x3000_0000,
        Process {
            indirect: b"abc",
            ..Default::default()
        },
    )
    .unwrap();
    assert!(
        process_image::encode_initial_stack_with_metadata(
            &[b"tool"],
            &[],
            b"tool",
            [0; 16],
            &[],
            p,
            layout,
            &mut [0; 9000]
        )
        .is_err()
    );
}
#[test]
fn metadata_mapping_composes_with_other_reservations_and_rejects_collisions_atomically() {
    reset(0);
    let bytes = vec![7; 6000];
    let mut owner = Owner::<Fake>::default();
    let mut out = [0; 10000];
    let n = encode(
        &mut owner,
        Process {
            indirect: &bytes,
            ..Default::default()
        },
        &mut out,
    )
    .unwrap();
    let mapping = owner.mapping().unwrap();
    let original = out;
    assert_eq!(owner.attach(&mut out, n, &[mapping]), Err(EIO));
    assert_eq!(out, original);
    let other = mnu_abi::process_image::InitialMapping {
        address: 0x4000_0000,
        length: 4096,
        access: 3,
        options: 0,
        backing_handle: 0,
        backing_offset: 0,
    };
    let n = owner.attach(&mut out, n, &[other]).unwrap();
    assert_eq!(
        mnu_abi::process_image::decode(&out[..n])
            .unwrap()
            .mappings()
            .collect::<Vec<_>>(),
        [other, mapping]
    );
}
