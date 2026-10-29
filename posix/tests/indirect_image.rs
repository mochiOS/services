//! Deferred resolvers must never run while metadata is still being inspected.
use mochios_posix_client::indirect_image::{
    Access, Captured, Error, Fixup, Region, State, encode, encoded_length,
};
use std::cell::{Cell, RefCell};
use std::sync::{
    Barrier,
    atomic::{AtomicUsize, Ordering},
};

const BASE: u64 = 0x600_0000;
const CODE: u64 = 0x800_0000;
const DATA: u64 = 0x900_0000;
const END: u64 = 0x0000_8000_0000_0000;

fn put(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

// Independent wire fixture, including reserved words. Do not use the producer
// to generate the consumer's malformed-input and execution fixtures.
fn fixture(regions: &[(u64, u64, u64)], fixups: &[(u64, u64, u64)]) -> Vec<u8> {
    let size = 40 + regions.len() * 24 + fixups.len() * 32;
    let mut bytes = Vec::with_capacity(size);
    bytes.extend_from_slice(b"MIREL001");
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&(regions.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&(fixups.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&(size as u64).to_le_bytes());
    bytes.extend_from_slice(&0u64.to_le_bytes());
    for &(address, length, access) in regions {
        for value in [address, length, access] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
    }
    for &(target, resolver, addend) in fixups {
        for value in [target, resolver, addend, 0] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
    }
    assert_eq!(bytes.len(), size);
    bytes
}
fn sample() -> Vec<u8> {
    fixture(
        &[(CODE, 16, 1), (DATA, 32, 2)],
        &[(DATA + 16, CODE, 5), (DATA, CODE + 8, 0)],
    )
}
fn reader(bytes: &[u8]) -> impl FnMut(u64, &mut [u8]) -> Result<(), i32> + '_ {
    move |address, output| {
        let at = usize::try_from(address.checked_sub(BASE).ok_or(14)?).map_err(|_| 14)?;
        let end = at.checked_add(output.len()).ok_or(14)?;
        output.copy_from_slice(bytes.get(at..end).ok_or(14)?);
        Ok(())
    }
}
fn capture<'a>(bytes: &[u8], fixups: &'a mut [Fixup]) -> Result<Captured<'a>, Error<i32>> {
    Captured::capture(
        BASE,
        bytes.len(),
        &mut [Region::EMPTY; 8],
        fixups,
        reader(bytes),
    )
}
fn regions() -> [Region; 2] {
    [
        Region {
            address: CODE,
            length: 16,
            access: Access::Executable,
        },
        Region {
            address: DATA,
            length: 32,
            access: Access::Writable,
        },
    ]
}

#[test]
fn producer_matches_wire_fixture_and_preserves_resolver_order() {
    let mut fixups = [
        Fixup::new(DATA + 16, CODE, 5),
        Fixup::new(DATA, CODE + 8, 0),
    ];
    let original = fixups;
    let mut out = vec![0xcc; encoded_length(2, 2).unwrap() + 8];
    let length = encode(&regions(), &mut fixups, &mut out).unwrap();
    assert_eq!(&out[..length], sample());
    assert_eq!(&out[length..], &[0xcc; 8]);
    for (actual, expected) in fixups.iter().zip(original) {
        assert_eq!(
            (actual.target(), actual.resolver(), actual.addend()),
            (expected.target(), expected.resolver(), expected.addend())
        );
    }
    assert_eq!(encoded_length(0, 0), Ok(40));
    assert_eq!(encoded_length(usize::MAX, 0), Err(Error::TooLarge));
    assert_eq!(encoded_length(1, usize::MAX), Err(Error::TooLarge));
    assert_eq!(
        encoded_length(u32::MAX as usize, usize::MAX / 32),
        Err(Error::TooLarge)
    );
}

#[test]
fn invalid_producer_input_never_changes_output_or_reorders_fixups() {
    let mut fixups = [
        Fixup::new(DATA + 16, CODE, 1),
        Fixup::new(DATA, CODE, 2),
        Fixup::new(DATA + 1, CODE, 3),
    ];
    let mut out = vec![0xcc; 256];
    assert_eq!(
        encode(&regions(), &mut fixups, &mut out),
        Err(Error::Invalid)
    );
    assert!(out.iter().all(|b| *b == 0xcc));
    assert_eq!(fixups.map(|f| f.addend()), [1, 2, 3]);
    let mut bad = [Fixup::new(DATA, DATA, 0)];
    assert_eq!(encode(&regions(), &mut bad, &mut out), Err(Error::Invalid));
    assert!(out.iter().all(|b| *b == 0xcc));
    let mut short = [0xaa; 39];
    assert_eq!(encode(&[], &mut [], &mut short), Err(Error::BufferTooSmall));
    assert_eq!(short, [0xaa; 39]);
}

#[test]
fn empty_plan_is_valid_and_completes_without_callbacks() {
    let bytes = fixture(&[], &[]);
    let image = capture(&bytes, &mut []).unwrap();
    assert!(image.is_empty());
    assert_eq!(image.len(), 0);
    let state = State::default();
    for _ in 0..2 {
        state
            .apply::<i32>(
                &image,
                |_| panic!("empty resolver"),
                |_, _| panic!("empty write"),
            )
            .unwrap();
    }
}

#[test]
fn all_truncations_are_reported_as_faults_without_execution() {
    let bytes = sample();
    for end in 0..bytes.len() {
        let mut storage = [Fixup::EMPTY; 2];
        let result = Captured::capture(
            BASE,
            bytes.len(),
            &mut [Region::EMPTY; 2],
            &mut storage,
            reader(&bytes[..end]),
        );
        assert!(matches!(result, Err(Error::Read(14))), "end={end}");
    }
    assert_eq!(capture(&bytes, &mut [Fixup::EMPTY; 2]).unwrap().len(), 2);
}

#[test]
fn invalid_metadata_addresses_are_rejected_before_reading() {
    for base in [0, 8, 0x3f_fff8, BASE + 1, END - 32, END, u64::MAX - 7] {
        let result = Captured::capture(base, 4096, &mut [], &mut [], |_, _| -> Result<(), i32> {
            panic!("invalid base {base:x} was read")
        });
        assert!(matches!(result, Err(Error::Invalid)));
    }
    let result = Captured::capture(BASE, 39, &mut [], &mut [], |_, _| -> Result<(), i32> {
        panic!("short header was read")
    });
    assert!(matches!(result, Err(Error::Invalid)));
}

#[test]
fn header_version_reserved_length_and_count_overflow_are_validated() {
    for (at, value) in [
        (0, 0),
        (8, 0),
        (8, 2 | (2u64 << 32)),
        (24, 151),
        (24, 153),
        (24, u64::MAX),
        (32, 1),
    ] {
        let mut bytes = sample();
        put(&mut bytes, at, value);
        assert!(
            matches!(capture(&bytes, &mut [Fixup::EMPTY; 2]), Err(Error::Invalid)),
            "at={at} value={value}"
        );
    }
    let mut bytes = sample();
    put(&mut bytes, 16, u64::MAX);
    assert!(matches!(
        capture(&bytes, &mut [Fixup::EMPTY; 2]),
        Err(Error::TooLarge)
    ));
    put(&mut bytes, 16, 2);
    let mut storage = [Fixup::EMPTY; 2];
    let result = Captured::capture(
        BASE,
        bytes.len() - 1,
        &mut [Region::EMPTY; 2],
        &mut storage,
        reader(&bytes),
    );
    assert!(matches!(result, Err(Error::TooLarge)));
}

#[test]
fn full_metadata_extent_must_fit_user_address_space() {
    let bytes = sample();
    let base = END - 40;
    let mut storage = [Fixup::EMPTY; 2];
    let result = Captured::capture(
        base,
        bytes.len(),
        &mut [Region::EMPTY; 2],
        &mut storage,
        |address, out| -> Result<(), i32> {
            assert_eq!(address, base);
            assert_eq!(out.len(), 40);
            out.copy_from_slice(&bytes[..40]);
            Ok(())
        },
    );
    assert!(matches!(result, Err(Error::Invalid)));
}

#[test]
fn caller_capacity_is_checked_before_any_record_read() {
    let bytes = sample();
    for (r, f) in [(1, 2), (2, 1), (0, 0)] {
        let mut regions = vec![Region::EMPTY; r];
        let mut fixups = vec![Fixup::EMPTY; f];
        let mut reads = 0;
        let result = Captured::capture(
            BASE,
            bytes.len(),
            &mut regions,
            &mut fixups,
            |address, out| -> Result<(), i32> {
                reads += 1;
                assert_eq!(address, BASE);
                assert_eq!(out.len(), 40);
                out.copy_from_slice(&bytes[..40]);
                Ok(())
            },
        );
        assert!(matches!(result, Err(Error::BufferTooSmall)));
        assert_eq!(reads, 1);
    }
}

#[test]
fn rejects_unknown_access_reserved_fields_and_bad_regions() {
    for (at, value) in [
        (40, 0x3f_ffff),
        (48, 0),
        (48, u64::MAX),
        (56, 0),
        (56, 3),
        (56, 5),
        (56, u64::MAX),
        (64, CODE - 1),
        (64, CODE),
        (64, CODE + 8),
        (64, END - 8),
        (144, 1),
    ] {
        let mut bytes = sample();
        put(&mut bytes, at, value);
        assert!(
            matches!(capture(&bytes, &mut [Fixup::EMPTY; 2]), Err(Error::Invalid)),
            "at={at} value={value}"
        );
    }
    // Both declarations individually valid, but sorting them is the producer's
    // responsibility; accepting arbitrary order would break binary lookup.
    let bytes = fixture(&[(DATA, 32, 2), (CODE, 16, 1)], &[]);
    assert!(matches!(capture(&bytes, &mut []), Err(Error::Invalid)));
}

#[test]
fn targets_require_eight_writable_bytes_and_resolvers_require_executable_bytes() {
    for (target, resolver) in [
        (CODE, CODE),
        (DATA - 1, CODE),
        (DATA + 25, CODE),
        (END - 4, CODE),
        (DATA, DATA),
        (DATA, CODE - 1),
        (DATA, CODE + 16),
        (DATA, 0),
    ] {
        let bytes = fixture(&[(CODE, 16, 1), (DATA, 32, 2)], &[(target, resolver, 0)]);
        assert!(
            matches!(capture(&bytes, &mut [Fixup::EMPTY]), Err(Error::Invalid)),
            "target={target:x} resolver={resolver:x}"
        );
    }
    // No full eight-byte target may straddle separate LOAD declarations.
    let bytes = fixture(
        &[(CODE, 16, 1), (DATA, 4, 2), (DATA + 4, 4, 2)],
        &[(DATA, CODE, 0)],
    );
    assert!(matches!(
        capture(&bytes, &mut [Fixup::EMPTY]),
        Err(Error::Invalid)
    ));
}

#[test]
fn exact_user_bounds_and_unaligned_targets_are_accepted() {
    let bytes = fixture(
        &[(0x40_0000, 1, 1), (END - 9, 9, 2)],
        &[(END - 8, 0x40_0000, 0)],
    );
    assert_eq!(capture(&bytes, &mut [Fixup::EMPTY]).unwrap().len(), 1);
    let bytes = fixture(&[(CODE, 16, 1), (DATA, 32, 2)], &[(DATA + 1, CODE + 15, 0)]);
    assert_eq!(capture(&bytes, &mut [Fixup::EMPTY]).unwrap().len(), 1);
}

#[test]
fn duplicate_and_partial_overlap_targets_are_rejected_even_when_unsorted() {
    for second in DATA..DATA + 8 {
        let bytes = fixture(
            &[(CODE, 16, 1), (DATA, 32, 2)],
            &[(DATA + 16, CODE, 0), (second, CODE, 0), (DATA, CODE, 0)],
        );
        assert!(matches!(
            capture(&bytes, &mut [Fixup::EMPTY; 3]),
            Err(Error::Invalid)
        ));
    }
    let bytes = fixture(
        &[(CODE, 16, 1), (DATA, 32, 2)],
        &[(DATA + 16, CODE, 0), (DATA, CODE, 0), (DATA + 8, CODE, 0)],
    );
    assert_eq!(capture(&bytes, &mut [Fixup::EMPTY; 3]).unwrap().len(), 3);
}

#[test]
fn original_order_writes_results_addends_and_never_repeats() {
    let bytes = sample();
    let mut storage = [Fixup::EMPTY; 2];
    let image = capture(&bytes, &mut storage).unwrap();
    let state = State::new();
    let events = RefCell::new(Vec::new());
    state
        .apply(
            &image,
            |address| -> Result<u64, i32> {
                events.borrow_mut().push((b'r', address, 0));
                Ok(if address == CODE { u64::MAX - 2 } else { 0 })
            },
            |address, value| {
                assert_eq!(value.len(), 8);
                events.borrow_mut().push((
                    b'w',
                    address,
                    u64::from_le_bytes(value.try_into().unwrap()),
                ));
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(
        *events.borrow(),
        [
            (b'r', CODE, 0),
            (b'w', DATA + 16, 2),
            (b'r', CODE + 8, 0),
            (b'w', DATA, 0)
        ]
    );
    state
        .apply::<i32>(
            &image,
            |_| panic!("resolver replay"),
            |_, _| panic!("write replay"),
        )
        .unwrap();
}

#[test]
fn resolver_mutations_of_original_metadata_cannot_redirect_later_writes() {
    let bytes = RefCell::new(sample());
    let mut storage = [Fixup::EMPTY; 2];
    let mut regions = [Region::EMPTY; 2];
    let reads = Cell::new(0);
    let image = Captured::capture(
        BASE,
        bytes.borrow().len(),
        &mut regions,
        &mut storage,
        |address, out| -> Result<(), i32> {
            reads.set(reads.get() + 1);
            reader(&bytes.borrow())(address, out)
        },
    )
    .unwrap();
    assert_eq!(reads.get(), 5);
    let mut targets = Vec::new();
    State::new()
        .apply(
            &image,
            |_| -> Result<u64, i32> {
                bytes.borrow_mut().fill(0xff);
                // Region scratch is not retained and need not survive execution.
                regions.fill(Region::EMPTY);
                Ok(19)
            },
            |target, _| {
                targets.push(target);
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(targets, [DATA + 16, DATA]);
    assert_eq!(reads.get(), 5);
}

#[test]
fn final_bad_record_prevents_any_execution() {
    let mut bytes = sample();
    put(&mut bytes, 120 + 8, DATA);
    let mut storage = [Fixup::EMPTY; 2];
    let result = capture(&bytes, &mut storage);
    assert!(matches!(result, Err(Error::Invalid)));
}

#[test]
fn resolver_failure_is_terminal_and_preserves_prior_writes() {
    let bytes = sample();
    let mut storage = [Fixup::EMPTY; 2];
    let image = capture(&bytes, &mut storage).unwrap();
    let state = State::new();
    let calls = Cell::new(0);
    let mut writes = Vec::new();
    let result = state.apply(
        &image,
        |_| -> Result<u64, i32> {
            calls.set(calls.get() + 1);
            if calls.get() == 2 { Err(71) } else { Ok(42) }
        },
        |target, _| {
            writes.push(target);
            Ok(())
        },
    );
    assert_eq!(result, Err(Error::Resolve(71)));
    assert_eq!(calls.get(), 2);
    assert_eq!(writes, [DATA + 16]);
    assert_eq!(
        state.apply::<i32>(
            &image,
            |_| panic!("failed resolver replay"),
            |_, _| panic!("failed write replay")
        ),
        Err(Error::Failed)
    );
}

#[test]
fn write_failure_does_not_call_any_later_resolver_or_retry_the_first() {
    let bytes = sample();
    let mut storage = [Fixup::EMPTY; 2];
    let image = capture(&bytes, &mut storage).unwrap();
    let state = State::new();
    let calls = Cell::new(0);
    assert_eq!(
        state.apply(
            &image,
            |_| -> Result<u64, i32> {
                calls.set(calls.get() + 1);
                Ok(42)
            },
            |_, _| Err(14)
        ),
        Err(Error::Write(14))
    );
    assert_eq!(calls.get(), 1);
    assert_eq!(
        state.apply::<i32>(
            &image,
            |_| panic!("resolver retry"),
            |_, _| panic!("write retry")
        ),
        Err(Error::Failed)
    );
}

#[test]
fn reentrant_resolver_cannot_execute_the_plan_again() {
    let bytes = sample();
    let mut storage = [Fixup::EMPTY; 2];
    let image = capture(&bytes, &mut storage).unwrap();
    let state = State::new();
    let calls = Cell::new(0);
    state
        .apply(
            &image,
            |_| -> Result<u64, i32> {
                calls.set(calls.get() + 1);
                assert_eq!(
                    state.apply::<i32>(
                        &image,
                        |_| panic!("reentrant resolver"),
                        |_, _| panic!("reentrant write")
                    ),
                    Err(Error::Reentrant)
                );
                Ok(3)
            },
            |_, _| Ok(()),
        )
        .unwrap();
    assert_eq!(calls.get(), 2);
}

#[test]
fn competing_thread_cannot_run_resolvers_or_mark_the_plan_complete_early() {
    let bytes = sample();
    let mut storage = [Fixup::EMPTY; 2];
    let image = capture(&bytes, &mut storage).unwrap();
    let state = State::new();
    let entered = Barrier::new(2);
    let release = Barrier::new(2);
    let calls = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        scope.spawn(|| {
            state
                .apply(
                    &image,
                    |_| -> Result<u64, i32> {
                        if calls.fetch_add(1, Ordering::Relaxed) == 0 {
                            entered.wait();
                            release.wait();
                        }
                        Ok(123)
                    },
                    |_, _| Ok(()),
                )
                .unwrap();
        });
        entered.wait();
        assert_eq!(
            state.apply::<i32>(
                &image,
                |_| panic!("concurrent resolver"),
                |_, _| panic!("concurrent write")
            ),
            Err(Error::Reentrant)
        );
        release.wait();
    });
    assert_eq!(calls.load(Ordering::Relaxed), 2);
    state
        .apply::<i32>(
            &image,
            |_| panic!("completed replay"),
            |_, _| panic!("completed write"),
        )
        .unwrap();
}

#[test]
fn unwind_from_resolver_or_writer_leaves_a_terminal_failure() {
    let bytes = sample();
    let mut storage = [Fixup::EMPTY; 2];
    let image = capture(&bytes, &mut storage).unwrap();
    for fail_resolver in [false, true] {
        let state = State::new();
        let result = std::panic::catch_unwind(|| {
            state.apply::<i32>(
                &image,
                |_| {
                    assert!(!fail_resolver, "resolver panic");
                    Ok(0)
                },
                |_, _| panic!("writer panic"),
            )
        });
        assert!(result.is_err());
        assert_eq!(
            state.apply::<i32>(
                &image,
                |_| panic!("unwound replay"),
                |_, _| panic!("unwound write")
            ),
            Err(Error::Failed)
        );
    }
}
