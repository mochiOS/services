use mochios_posix_client::lifecycle_image::{
    Error, Image, State,
    deferred::{self, Plan},
};
#[path = "support/lifecycle_fixture.rs"]
mod flat_fixture;
const BASE: u64 = 0x7000_0000;
const CODE: u64 = 0x800_0000;
const ARRAY: u64 = 0x900_0000;
fn put(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}
fn recipe() -> Vec<u8> {
    // Independent v2 fixture: two objects, two regions, six callback recipes.
    let mut b = vec![0; 256];
    b[..8].copy_from_slice(b"MLIFE001");
    for (at, v) in [
        (8, 2 | (2u64 << 32)),
        (16, 256),
        (24, 1),
        (32, 2),
        (48, 176),
        (56, 2),
        (64, 208),
        (72, 1),
        (80, 224),
        (88, 1),
        (96, 240),
        (104, 1),
        (112, CODE),
        (120, 64),
        (128, 5),
        (136, ARRAY),
        (144, 32),
        (152, 6),
    ] {
        put(&mut b, at, v);
    }
    for (i, (kind, v)) in [
        (0, CODE),
        (0, CODE + 1),
        (1, ARRAY + 8),
        (1, ARRAY + 16),
        (1, ARRAY + 24),
        (0, CODE + 6),
    ]
    .into_iter()
    .enumerate()
    {
        put(&mut b, 160 + i * 16, kind);
        put(&mut b, 168 + i * 16, v);
    }
    b
}
fn expected() -> Vec<u8> {
    flat_fixture::encode(
        &[CODE],
        &[
            (&[CODE + 1, CODE + 2], &[CODE + 3]),
            (&[CODE + 4], &[CODE + 6]),
        ],
    )
}
fn metadata<'a>(b: &'a [u8]) -> impl FnMut(u64, &mut [u8]) -> Result<(), i32> + 'a {
    move |address, out| {
        let at = address.checked_sub(BASE).ok_or(14)? as usize;
        let end = at.checked_add(out.len()).ok_or(14)?;
        out.copy_from_slice(b.get(at..end).ok_or(14)?);
        Ok(())
    }
}
fn array(address: u64, out: &mut [u8]) -> Result<(), i32> {
    let value = match address {
        a if a == ARRAY + 8 => CODE + 2,
        a if a == ARRAY + 16 => CODE + 3,
        a if a == ARRAY + 24 => CODE + 4,
        _ => return Err(14),
    };
    assert_eq!(out.len(), 8);
    out.copy_from_slice(&value.to_le_bytes());
    Ok(())
}
#[test]
fn recipes_are_not_dereferenced_until_resolution_then_match_the_flat_contract() {
    let b = recipe();
    let mut private = vec![0; 4096];
    let len = deferred::capture(BASE, 4096, &mut private, metadata(&b)).unwrap();
    assert_eq!(len, b.len());
    let plan = Plan::parse::<i32>(&private[..len]).unwrap();
    let mut out = vec![0xcc; plan.flat_length() + 8];
    let length = plan.resolve(&mut out, array).unwrap();
    assert_eq!(&out[..length], expected());
    assert_eq!(&out[length..], &[0xcc; 8]);
    let image = Image::read(BASE, length, metadata(&out[..length])).unwrap();
    let state = State::new();
    let mut calls = Vec::new();
    state
        .initialize(&image, metadata(&out[..length]), |p| {
            calls.push(p);
            Ok(())
        })
        .unwrap();
    state
        .finalize(&image, metadata(&out[..length]), |p| {
            calls.push(p);
            Ok(())
        })
        .unwrap();
    assert_eq!(
        calls,
        [CODE, CODE + 1, CODE + 2, CODE + 4, CODE + 6, CODE + 3]
    );
}
#[test]
fn all_truncated_metadata_is_faulted_before_an_array_value_is_read() {
    let b = recipe();
    for end in 0..b.len() {
        assert!(
            matches!(
                deferred::capture(BASE, b.len(), &mut [0; 4096], metadata(&b[..end])),
                Err(Error::Read(14))
            ),
            "end={end}"
        );
    }
    let mut calls = 0;
    for base in [0, 8, BASE + 1, u64::MAX - 7, 0x0000_8000_0000_0000 - 16] {
        assert!(
            deferred::capture(base, 4096, &mut [0; 4096], |_, _| -> Result<(), i32> {
                calls += 1;
                Err(14)
            })
            .is_err()
        );
    }
    assert_eq!(calls, 0);
}
#[test]
fn rejects_malformed_header_layout_regions_and_callback_recipes() {
    for (at, v) in [
        (0, 0),
        (8, 3 | (2 << 32)),
        (8, 2),
        (16, 255),
        (16, 257),
        (24, u64::MAX),
        (32, u64::MAX),
        (40, 1),
        (48, 160),
        (56, u64::MAX),
        (64, 224),
        (96, 224),
        (112, 0),
        (120, 0),
        (120, u64::MAX),
        (128, 3),
        (128, 8),
        (136, CODE + 1),
        (144, u64::MAX),
        (152, 3),
        (160, 2),
        (168, ARRAY),
        (200, ARRAY + 1),
        (200, ARRAY + 28),
        (248, 0),
    ] {
        let mut b = recipe();
        put(&mut b, at, v);
        assert!(Plan::parse::<i32>(&b).is_err(), "at={at} value={v}");
    }
}
#[test]
fn resolution_checks_every_final_pointer_and_reports_copy_errors() {
    let b = recipe();
    let plan = Plan::parse::<i32>(&b).unwrap();
    for value in [0, u64::MAX, ARRAY, CODE + 64] {
        let mut out = vec![0; plan.flat_length()];
        assert!(matches!(
            plan.resolve(&mut out, |p, b| {
                if p == ARRAY + 24 {
                    b.copy_from_slice(&value.to_le_bytes());
                    Ok(())
                } else {
                    array(p, b)
                }
            }),
            Err(Error::Invalid)
        ));
    }
    let mut reads = Vec::new();
    assert_eq!(
        plan.resolve(&mut vec![0; plan.flat_length()], |p, b| {
            reads.push(p);
            if p == ARRAY + 24 {
                Err(71)
            } else {
                array(p, b)
            }
        }),
        Err(Error::Read(71))
    );
    assert_eq!(reads, [ARRAY + 8, ARRAY + 16, ARRAY + 24]);
}
#[test]
fn short_output_or_capture_capacity_is_rejected_before_body_reads() {
    let b = recipe();
    let plan = Plan::parse::<i32>(&b).unwrap();
    let mut out = vec![0xcc; plan.flat_length() - 1];
    assert_eq!(
        plan.resolve::<i32>(&mut out, |_, _| panic!("short output read")),
        Err(Error::TooLarge)
    );
    assert!(out.iter().all(|b| *b == 0xcc));
    for (maximum, capacity) in [(255, 4096), (4096, 255)] {
        let mut reads = 0;
        assert_eq!(
            deferred::capture(BASE, maximum, &mut vec![0; capacity], |p, out| {
                reads += 1;
                assert_eq!(p, BASE);
                assert_eq!(out.len(), 32);
                metadata(&b)(p, out)
            }),
            Err(Error::TooLarge)
        );
        assert_eq!(reads, 1);
    }
}
#[test]
fn private_capture_ignores_later_recipe_changes_but_observes_final_array_values() {
    let mut b = recipe();
    let mut private = vec![0; 4096];
    let len = deferred::capture(BASE, b.len(), &mut private, metadata(&b)).unwrap();
    b.fill(0xff);
    let plan = Plan::parse::<i32>(&private[..len]).unwrap();
    let mut out = vec![0; plan.flat_length()];
    plan.resolve(&mut out, array).unwrap();
    assert_eq!(out, expected());
}
#[test]
fn flat_v1_is_also_captured_and_validated_without_rereading_original_metadata() {
    let mut b = expected();
    let mut out = vec![0; 4096];
    let length = deferred::capture(BASE, b.len(), &mut out, metadata(&b)).unwrap();
    b.fill(0xff);
    assert_eq!(&out[..length], expected());
    for (at, v) in [(8, 9), (16, 31), (24, u64::MAX), (32, 0), (40, u64::MAX)] {
        let mut b = expected();
        put(&mut b, at, v);
        assert!(deferred::capture(BASE, b.len(), &mut [0; 4096], metadata(&b)).is_err());
    }
}

#[test]
fn captures_header_once_and_resolves_a_deferred_preinit_like_other_array_entries() {
    let mut source = recipe();
    put(&mut source, 160, 1);
    put(&mut source, 168, ARRAY);
    let mut private = vec![0; 4096];
    let mut reads = 0;
    let length = deferred::capture(BASE, source.len(), &mut private, |p, out| {
        reads += 1;
        metadata(&source)(p, out)?;
        if reads == 1 {
            // The later body copy must not recapture a changed size/version.
            source[..32].fill(0xff);
        }
        Ok::<(), i32>(())
    })
    .unwrap();
    assert_eq!(reads, 2);
    let plan = Plan::parse::<i32>(&private[..length]).unwrap();
    let mut output = vec![0; plan.flat_length()];
    plan.resolve(&mut output, |p, out| {
        if p == ARRAY {
            out.copy_from_slice(&CODE.to_le_bytes());
            Ok(())
        } else {
            array(p, out)
        }
    })
    .unwrap();
    assert_eq!(output, expected());
}

#[test]
fn allocation_preflight_never_allows_header_growth_to_escape_private_storage() {
    let bytes = recipe();
    assert_eq!(
        deferred::encoded_length(BASE, bytes.len(), metadata(&bytes)),
        Ok(bytes.len())
    );
    assert_eq!(
        deferred::encoded_length(BASE, bytes.len() - 1, metadata(&bytes)),
        Err(Error::TooLarge)
    );
    assert_eq!(
        deferred::encoded_length(BASE, bytes.len(), metadata(&bytes[..31])),
        Err(Error::Read(14))
    );
    for base in [0, BASE + 1, u64::MAX - 7, 0x8000_0000_0000 - 16] {
        assert!(
            deferred::encoded_length::<i32>(base, bytes.len(), |_, _| panic!("invalid base"))
                .is_err()
        );
    }
    for (offset, value) in [(0, 0), (8, 3), (16, 0), (16, u64::MAX)] {
        let mut bad = bytes.clone();
        put(&mut bad, offset, value);
        assert!(deferred::encoded_length(BASE, bytes.len(), metadata(&bad)).is_err());
    }
    let mut changed = bytes.clone();
    put(&mut changed, 16, (bytes.len() + 16) as u64);
    let mut output = vec![0xcc; bytes.len()];
    assert_eq!(
        deferred::capture(BASE, bytes.len() + 16, &mut output, metadata(&changed)),
        Err(Error::TooLarge)
    );
    assert!(output.iter().all(|b| *b == 0xcc));
}
