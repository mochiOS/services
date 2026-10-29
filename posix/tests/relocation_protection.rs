use mochios_posix_client::{
    pie::Pie,
    relocation_protection::{self as policy, Error, Image, Range, State},
};
use std::cell::RefCell;
const BASE: u64 = 0x3000_0000;
fn put(b: &mut [u8], at: usize, value: u64) {
    b[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
fn fixture(inner: bool) -> Vec<u8> {
    // Independent envelope: two disjoint page ranges and an optional empty v1
    // resolver plan. Never use the producer for malformed consumer fixtures.
    let mut b = vec![0; 64 + usize::from(inner) * 40];
    for (at, v) in [
        (0, u64::from_le_bytes(*b"MRELRO01")),
        (8, 1 | (2 << 32)),
        (16, b.len() as u64),
        (24, if inner { 40 } else { 0 }),
        (32, 0x800000),
        (40, 4096),
        (48, 0x900000),
        (56, 8192),
    ] {
        put(&mut b, at, v);
    }
    if inner {
        b[64..72].copy_from_slice(b"MIREL001");
        put(&mut b, 72, 1);
        put(&mut b, 88, 40);
    }
    b
}
fn read(b: &[u8]) -> impl FnMut(u64, &mut [u8]) -> Result<(), i32> + '_ {
    move |address, out| {
        let at = address.checked_sub(BASE).ok_or(14)? as usize;
        let end = at.checked_add(out.len()).ok_or(14)?;
        out.copy_from_slice(b.get(at..end).ok_or(14)?);
        Ok(())
    }
}
#[test]
fn envelope_preserves_the_exact_inner_plan_and_checks_before_moving_output() {
    let expected = fixture(true);
    let ranges = [
        Range {
            address: 0x800000,
            length: 4096,
        },
        Range {
            address: 0x900000,
            length: 8192,
        },
    ];
    let mut out = vec![0xcc; expected.len() + 8];
    out[..40].copy_from_slice(&expected[64..]);
    assert_eq!(policy::wrap(40, &ranges, &mut out), Ok(expected.len()));
    assert_eq!(&out[..expected.len()], expected);
    assert_eq!(&out[expected.len()..], &[0xcc; 8]);
    for bad in [
        vec![ranges[1], ranges[0]],
        vec![ranges[0], ranges[0]],
        vec![Range {
            address: 0x800001,
            ..ranges[0]
        }],
        vec![Range {
            length: 0,
            ..ranges[0]
        }],
        vec![Range {
            length: u64::MAX,
            ..ranges[0]
        }],
    ] {
        let mut out = vec![0xaa; 256];
        assert!(policy::wrap(0, &bad, &mut out).is_err());
        assert!(out.iter().all(|b| *b == 0xaa));
    }
    assert!(policy::encoded_length(usize::MAX, 0).is_err());
    assert!(policy::encoded_length(1, usize::MAX).is_err());
}
#[test]
fn capture_rejects_every_truncation_and_malformed_range_before_side_effects() {
    let good = fixture(true);
    for end in 0..good.len() {
        assert!(
            policy::capture(BASE, good.len(), &mut [0; 256], read(&good[..end])).is_err(),
            "end={end}"
        );
    }
    for (at, v) in [
        (0, 0),
        (8, 2 | (2 << 32)),
        (8, 1),
        (16, 0),
        (24, 1),
        (24, 8),
        (32, 0),
        (32, 0x800001),
        (40, 1),
        (40, u64::MAX),
        (48, 0x800000),
        (48, 0x800000000000),
        (56, 0),
        (64, 0),
    ] {
        let mut b = good.clone();
        put(&mut b, at, v);
        assert!(Image::parse::<i32>(&b).is_err(), "at={at} value={v}");
    }
    for base in [0, BASE + 1, u64::MAX - 7, 0x800000000000 - 16] {
        assert!(policy::length::<i32>(base, good.len(), |_, _| panic!("invalid address")).is_err());
    }
    assert_eq!(
        policy::length(BASE, good.len() - 1, read(&good)),
        Err(Error::TooLarge)
    );
    let mut out = [0xcc; 63];
    assert_eq!(
        policy::capture(BASE, good.len(), &mut out, read(&good)),
        Err(Error::TooLarge)
    );
    assert_eq!(out, [0xcc; 63]);
    let mut changed = good.clone();
    put(&mut changed, 8, 1 | (3 << 32));
    put(&mut changed, 16, (good.len() + 16) as u64);
    assert_eq!(
        policy::capture(
            BASE,
            good.len() + 16,
            &mut vec![0; good.len()],
            read(&changed)
        ),
        Err(Error::TooLarge)
    );
}
#[test]
fn relocation_precedes_all_protection_and_success_is_once_only() {
    let b = fixture(true);
    let image = Image::parse::<i32>(&b).unwrap();
    let state = State::new();
    let events = RefCell::new(Vec::new());
    state
        .apply::<i32>(
            &image,
            |inner| {
                assert_eq!(inner, &b[64..]);
                events.borrow_mut().push(0);
                assert_eq!(state.status::<i32>(), Err(Error::Reentrant));
                Ok(())
            },
            |r| {
                events.borrow_mut().push(r.address);
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(*events.borrow(), [0, 0x800000, 0x900000]);
    assert_eq!(state.status::<i32>(), Ok(true));
    state
        .apply::<i32>(
            &image,
            |_| panic!("replayed relocation"),
            |_| panic!("replayed protection"),
        )
        .unwrap();
    let b = fixture(false);
    let image = Image::parse::<i32>(&b).unwrap();
    State::new()
        .apply::<i32>(&image, |_| panic!("absent plan"), |_| Ok(()))
        .unwrap();
}
#[test]
fn partial_protection_relocation_failure_and_unwind_are_terminal() {
    let b = fixture(true);
    let image = Image::parse::<i32>(&b).unwrap();
    for fail in [0, 1, 2] {
        let state = State::new();
        let mut protected = 0;
        assert!(
            state
                .apply(
                    &image,
                    |_| if fail == 0 { Err(5) } else { Ok(()) },
                    |_| {
                        protected += 1;
                        if protected == fail { Err(13) } else { Ok(()) }
                    }
                )
                .is_err()
        );
        assert_eq!(protected, fail);
        assert_eq!(state.status::<i32>(), Err(Error::Failed));
        assert_eq!(
            state.apply::<i32>(&image, |_| panic!("retry"), |_| panic!("retry")),
            Err(Error::Failed)
        );
    }
    let state = State::new();
    assert!(
        std::panic::catch_unwind(|| {
            let _ = state.apply::<i32>(
                &image,
                |_| panic!("resolver abandoned frame"),
                |_| panic!("protected after unwind"),
            );
        })
        .is_err()
    );
    assert_eq!(state.status::<i32>(), Err(Error::Failed));
}
fn elf() -> Vec<u8> {
    let mut b = vec![0; 0x3800];
    b[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
    b[16..18].copy_from_slice(&3u16.to_le_bytes());
    b[18..20].copy_from_slice(&62u16.to_le_bytes());
    b[20..24].copy_from_slice(&1u32.to_le_bytes());
    put(&mut b, 24, 0x180);
    put(&mut b, 32, 64);
    for (at, v) in [(52, 64u16), (54, 56), (56, 3)] {
        b[at..at + 2].copy_from_slice(&v.to_le_bytes());
    }
    for (i, (kind, flags, offset, address, file, memory)) in [
        (1u32, 5u32, 0, 0, 0x200, 0x200),
        (1, 6, 0x1000, 0x2000, 0x2800, 0x3800),
        (0x6474e552, 4, 0x1780, 0x2780, 0x1080, 0x1080),
    ]
    .into_iter()
    .enumerate()
    {
        let at = 64 + i * 56;
        b[at..at + 4].copy_from_slice(&kind.to_le_bytes());
        b[at + 4..at + 8].copy_from_slice(&flags.to_le_bytes());
        for (j, v) in [offset, address, 0, file, memory, 0x1000]
            .into_iter()
            .enumerate()
        {
            put(&mut b, at + 8 + j * 8, v);
        }
    }
    b
}
#[test]
fn elf_relro_uses_gnu_page_rounding_and_stays_inside_the_source_load() {
    let b = elf();
    let mut fixed = b.clone();
    fixed[16..18].copy_from_slice(&2u16.to_le_bytes());
    put(&mut fixed, 24, 0x400180);
    for i in 0..3 {
        let at = 64 + i * 56 + 16;
        let address = u64::from_le_bytes(fixed[at..at + 8].try_into().unwrap());
        put(&mut fixed, at, address + 0x400000);
    }
    Pie::parse_object(&fixed).unwrap();
    assert_eq!(
        mochios_posix_client::image_preparation::needs_preparation_bytes(&fixed),
        Ok(true)
    );
    let image = Pie::parse(&b).unwrap();
    let mut ranges = Vec::new();
    image
        .relro(0x20000000, |r| {
            ranges.push(r);
            Ok(())
        })
        .unwrap();
    assert_eq!(
        ranges,
        [Range {
            address: 0x20002000,
            length: 4096
        }]
    );
    for (at, v) in [
        (64 + 2 * 56 + 40, 0x8000),
        (64 + 2 * 56 + 16, u64::MAX - 0x107f),
        (64 + 2 * 56 + 40, 0),
    ] {
        let mut b = b.clone();
        put(&mut b, at, v);
        assert!(Pie::parse(&b).and_then(|image| image.has_relro()).is_err());
    }
    assert!(image.relro(1, |_| panic!("misaligned bias")).is_err());
    let mut small = b.clone();
    put(&mut small, 64 + 2 * 56 + 32, 0x100);
    put(&mut small, 64 + 2 * 56 + 40, 0x100);
    assert!(!Pie::parse(&small).unwrap().has_relro().unwrap());
}
