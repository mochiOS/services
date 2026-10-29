//! Independent v2 wire fixtures for resolver/COPY ordering and failure state.
use mochios_posix_client::indirect_image::{Access, Captured, Error, Fixup, Region, State, encode};
use std::cell::{Cell, RefCell};
const BASE: u64 = 0x600_0000;
const CODE: u64 = 0x800_0000;
const DATA: u64 = 0x900_0000;
const ROOT: u64 = 0xa00_0000;
fn put(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}
fn fixture(records: &[(u64, u64, u64, u64)]) -> Vec<u8> {
    let mut b = vec![0; 40 + 3 * 24 + records.len() * 32];
    b[..8].copy_from_slice(b"MIREL001");
    let length = b.len() as u64;
    for (at, v) in [(8, 2 | (3 << 32)), (16, records.len() as u64), (24, length)] {
        put(&mut b, at, v);
    }
    for (i, (a, n, f)) in [(CODE, 64, 5), (DATA, 1024, 6), (ROOT, 1024, 6)]
        .into_iter()
        .enumerate()
    {
        for (j, v) in [a, n, f].into_iter().enumerate() {
            put(&mut b, 40 + i * 24 + j * 8, v);
        }
    }
    for (i, (a, bv, n, k)) in records.iter().copied().enumerate() {
        for (j, v) in [a, bv, n, k].into_iter().enumerate() {
            put(&mut b, 112 + i * 32 + j * 8, v);
        }
    }
    b
}
fn sample() -> Vec<u8> {
    fixture(&[
        (DATA + 8, CODE, 5, 0),
        (ROOT, DATA, 600, 1),
        (ROOT + 600, CODE + 8, 0, 0),
    ])
}
fn capture<'a>(b: &[u8], f: &'a mut [Fixup]) -> Result<Captured<'a>, Error<i32>> {
    Captured::capture(BASE, b.len(), &mut [Region::EMPTY; 3], f, |a, out| {
        let at = a.checked_sub(BASE).ok_or(14)? as usize;
        out.copy_from_slice(b.get(at..at + out.len()).ok_or(14)?);
        Ok(())
    })
}
#[test]
fn producer_matches_tagged_wire_records_and_preserves_copy_position() {
    let r = [
        Region {
            address: CODE,
            length: 64,
            access: Access::ReadExecute,
        },
        Region {
            address: DATA,
            length: 1024,
            access: Access::ReadWrite,
        },
        Region {
            address: ROOT,
            length: 1024,
            access: Access::ReadWrite,
        },
    ];
    let mut f = [
        Fixup::new(DATA + 8, CODE, 5),
        Fixup::copy(ROOT, DATA, 600),
        Fixup::new(ROOT + 600, CODE + 8, 0),
    ];
    let mut out = vec![0; sample().len()];
    assert_eq!(encode(&r, &mut f, &mut out), Ok(out.len()));
    assert_eq!(out, sample());
    assert_eq!(f[1].copy_source(), Some((DATA, 600)));
    assert_eq!(f[1].width(), 600);
}
#[test]
fn copy_observes_final_provider_bytes_before_the_root_resolver_and_runs_once() {
    let mut b = sample();
    let mut f = [Fixup::EMPTY; 3];
    let image = capture(&b, &mut f).unwrap();
    b.fill(0xff);
    let source = RefCell::new([0x33u8; 1024]);
    let root = RefCell::new([0xccu8; 1024]);
    let events = RefCell::new(Vec::new());
    let state = State::new();
    // The old resolver-only API must reject before the first side effect.
    assert_eq!(
        state.apply::<i32>(
            &image,
            |_| panic!("legacy resolver"),
            |_, _| panic!("legacy writer")
        ),
        Err(Error::Invalid)
    );
    state
        .apply_with_copies(
            &image,
            |a, out| {
                events.borrow_mut().push(b'r');
                let at = (a - DATA) as usize;
                out.copy_from_slice(&source.borrow()[at..at + out.len()]);
                Ok(())
            },
            |a| -> Result<u64, i32> {
                events.borrow_mut().push(b'f');
                if a == CODE {
                    source.borrow_mut()[31] = 0x71;
                    Ok(68)
                } else {
                    assert_eq!(&root.borrow()[..600], &source.borrow()[..600]);
                    Ok(19)
                }
            },
            |a, bytes| {
                events.borrow_mut().push(b'w');
                if a < ROOT {
                    let at = (a - DATA) as usize;
                    source.borrow_mut()[at..at + bytes.len()].copy_from_slice(bytes);
                } else {
                    let at = (a - ROOT) as usize;
                    root.borrow_mut()[at..at + bytes.len()].copy_from_slice(bytes);
                }
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(&*events.borrow(), b"fwrwrwrwfw");
    assert_eq!(
        u64::from_le_bytes(root.borrow()[8..16].try_into().unwrap()),
        73
    );
    assert_eq!(
        u64::from_le_bytes(root.borrow()[600..608].try_into().unwrap()),
        19
    );
    assert!(root.borrow()[608..].iter().all(|b| *b == 0xcc));
    state
        .apply_with_copies::<i32>(
            &image,
            |_, _| panic!("read replay"),
            |_| panic!("resolver replay"),
            |_, _| panic!("write replay"),
        )
        .unwrap();
}
#[test]
fn byte_copies_include_partial_unaligned_resolver_results_and_readonly_sources() {
    let mut b = fixture(&[(ROOT + 1, DATA + 11, 3, 1)]);
    put(&mut b, 80, 4);
    let mut f = [Fixup::EMPTY];
    let image = capture(&b, &mut f).unwrap();
    let value = 0x1234_5678_9abc_def0u64.to_le_bytes();
    let mut writes = Vec::new();
    State::new()
        .apply_with_copies(
            &image,
            |a, out| {
                assert_eq!(a, DATA + 11);
                out.copy_from_slice(&value[3..6]);
                Ok::<(), i32>(())
            },
            |_| panic!("COPY calls no resolver"),
            |a, out| {
                writes.push((a, out.to_vec()));
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(writes, [(ROOT + 1, value[3..6].to_vec())]);
}
#[test]
fn validates_all_operations_regions_and_extents_before_any_execution() {
    for (at, v) in [
        (8, 1 | (3 << 32)),
        (8, 3 | (3 << 32)),
        (80, 2),
        (80, 3),
        (80, 7),
        (104, 4),
        (144, ROOT + 1020),
        (152, DATA + 1020),
        (160, 0),
        (160, u64::MAX),
        (168, 2),
        (144, DATA + 1),
        (144, DATA + 8),
        (176, ROOT + 599),
    ] {
        let mut b = sample();
        put(&mut b, at, v);
        assert!(
            capture(&b, &mut [Fixup::EMPTY; 3]).is_err(),
            "at={at} value={v:x}"
        );
    }
    let b = sample();
    for end in 0..b.len() {
        assert!(
            capture(&b[..end], &mut [Fixup::EMPTY; 3]).is_err(),
            "end={end}"
        );
    }
}
#[test]
fn copy_read_and_write_faults_stop_later_resolvers_and_are_terminal() {
    for fail_read in [false, true] {
        let b = sample();
        let mut f = [Fixup::EMPTY; 3];
        let image = capture(&b, &mut f).unwrap();
        let state = State::new();
        let calls = Cell::new(0);
        let writes = RefCell::new(Vec::new());
        let result = state.apply_with_copies(
            &image,
            |a, out| {
                if fail_read && a == DATA + 256 {
                    return Err(14);
                }
                out.fill(7);
                Ok(())
            },
            |_| -> Result<u64, i32> {
                calls.set(calls.get() + 1);
                Ok(1)
            },
            |a, out| {
                if !fail_read && a == ROOT + 256 {
                    return Err(71);
                }
                writes.borrow_mut().push((a, out.len()));
                Ok(())
            },
        );
        assert_eq!(
            result,
            Err(if fail_read {
                Error::Read(14)
            } else {
                Error::Write(71)
            })
        );
        assert_eq!(calls.get(), 1);
        assert_eq!(*writes.borrow(), [(DATA + 8, 8), (ROOT, 256)]);
        assert_eq!(
            state.apply_with_copies::<i32>(
                &image,
                |_, _| panic!("retry read"),
                |_| panic!("retry resolve"),
                |_, _| panic!("retry write")
            ),
            Err(Error::Failed)
        );
    }
}
#[test]
fn overlapping_copy_and_resolver_targets_are_rejected_without_reordering_records() {
    for second in ROOT..ROOT + 600 {
        let b = fixture(&[(ROOT, DATA, 600, 1), (second, CODE, 0, 0)]);
        assert!(
            capture(&b, &mut [Fixup::EMPTY; 2]).is_err(),
            "second={second:x}"
        );
    }
    let mut f = [Fixup::new(ROOT + 20, CODE, 0), Fixup::copy(ROOT, DATA, 600)];
    let r = [
        Region {
            address: CODE,
            length: 64,
            access: Access::Executable,
        },
        Region {
            address: DATA,
            length: 1024,
            access: Access::Readable,
        },
        Region {
            address: ROOT,
            length: 1024,
            access: Access::Writable,
        },
    ];
    let mut out = [0xcc; 256];
    assert_eq!(encode(&r, &mut f, &mut out), Err(Error::Invalid));
    assert_eq!(f[0].target(), ROOT + 20);
    assert_eq!(f[1].target(), ROOT);
    assert!(out.iter().all(|b| *b == 0xcc));
}

#[test]
fn copy_reentry_and_unwind_cannot_replay_completed_resolver_side_effects() {
    let b = sample();
    let mut fixups = [Fixup::EMPTY; 3];
    let image = capture(&b, &mut fixups).unwrap();
    let state = State::new();
    let calls = Cell::new(0);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        state.apply_with_copies(
            &image,
            |_, _| -> Result<(), i32> {
                assert_eq!(
                    state.apply_with_copies::<i32>(
                        &image,
                        |_, _| panic!("nested read"),
                        |_| panic!("nested resolver"),
                        |_, _| panic!("nested writer")
                    ),
                    Err(Error::Reentrant)
                );
                panic!("copy reader unwind");
            },
            |_| {
                calls.set(calls.get() + 1);
                Ok(1)
            },
            |_, _| Ok(()),
        )
    }));
    assert!(result.is_err());
    assert_eq!(calls.get(), 1);
    assert_eq!(
        state.apply_with_copies::<i32>(
            &image,
            |_, _| panic!("read retry"),
            |_| panic!("resolver retry"),
            |_, _| panic!("write retry")
        ),
        Err(Error::Failed)
    );
}
