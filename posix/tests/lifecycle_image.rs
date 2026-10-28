use mochios_posix_client::lifecycle_image::{Error, Image, State};
#[path = "support/lifecycle_fixture.rs"]
mod fixture;
fn read(bytes: &[u8]) -> impl FnMut(u64, &mut [u8]) -> Result<(), i32> + '_ {
    |address, output| {
        let offset = address.checked_sub(0x10000).ok_or(14)? as usize;
        output.copy_from_slice(bytes.get(offset..offset + output.len()).ok_or(14)?);
        Ok(())
    }
}
#[test]
fn codec_obeys_extent_version_canonical_offsets_and_faults() {
    let bytes = fixture::encode(&[1], &[(&[10, 11], &[12]), (&[20], &[22, 21])]);
    assert!(Image::read(0x10000, bytes.len(), read(&bytes)).is_ok());
    for length in 0..bytes.len() {
        assert!(
            Image::read(0x10000, bytes.len(), read(&bytes[..length])).is_err(),
            "length={length}"
        );
    }
    for (offset, value) in [
        (0, 0),
        (8, 0),
        (8, 1),
        (16, u64::MAX),
        (24, u64::MAX),
        (32, 0),
        (40, u64::MAX),
        (48, 0),
        (56, u64::MAX),
        (64, 104),
        (80, 104),
    ] {
        let mut bad = bytes.clone();
        bad[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        assert!(
            Image::read(0x10000, bytes.len(), read(&bad)).is_err(),
            "offset={offset} value={value}"
        );
    }
    assert!(matches!(
        Image::read(0x10000, bytes.len() - 1, read(&bytes)),
        Err(Error::TooLarge)
    ));
    let mut calls = 0;
    for base in [0, 1, u64::MAX - 7] {
        assert!(
            Image::read(base, bytes.len(), |_, _| {
                calls += 1;
                Err(14)
            })
            .is_err()
        );
    }
    assert_eq!(calls, 0);
}
#[test]
fn objects_initialize_once_and_finalize_in_reverse_once_even_with_reentry() {
    let bytes = fixture::encode(&[1], &[(&[10, 11], &[12]), (&[20], &[22, 21])]);
    let image = Image::read(0x10000, bytes.len(), read(&bytes)).unwrap();
    let state = State::new();
    let mut events = Vec::new();
    state
        .finalize(&image, read(&bytes), |_| panic!("not initialized"))
        .unwrap();
    state
        .initialize(&image, read(&bytes), |address| {
            events.push(address);
            Ok(())
        })
        .unwrap();
    state
        .initialize(&image, read(&bytes), |_| panic!("initialized twice"))
        .unwrap();
    state
        .finalize(&image, read(&bytes), |address| {
            state
                .finalize(&image, read(&bytes), |_| panic!("reentrant finalization"))
                .unwrap();
            events.push(address);
            Ok(())
        })
        .unwrap();
    state
        .finalize(&image, read(&bytes), |_| panic!("finalized twice"))
        .unwrap();
    assert_eq!(events, [1, 10, 11, 20, 22, 21, 12]);
    assert!(matches!(
        state.initialize(&image, read(&bytes), |_| Ok(())),
        Err(Error::Invalid)
    ));
}
#[test]
fn interrupted_initialization_finalizes_only_started_objects() {
    let bytes = fixture::encode(&[1], &[(&[10], &[12]), (&[20], &[22]), (&[30], &[32])]);
    let image = Image::read(0x10000, bytes.len(), read(&bytes)).unwrap();
    let state = State::new();
    let mut events = Vec::new();
    assert_eq!(
        state.initialize(&image, read(&bytes), |address| {
            events.push(address);
            if address == 20 { Err(9) } else { Ok(()) }
        }),
        Err(Error::Read(9))
    );
    state
        .finalize(&image, read(&bytes), |address| {
            events.push(address);
            Ok(())
        })
        .unwrap();
    assert_eq!(events, [1, 10, 20, 22, 12]);
    let state = State::new();
    assert!(
        state
            .initialize(&image, read(&bytes), |_| {
                state
                    .finalize(&image, read(&bytes), |_| {
                        panic!("preinit has no started objects")
                    })
                    .unwrap();
                Ok(())
            })
            .is_err()
    );
}
#[test]
fn faulted_or_zero_callbacks_never_execute_and_do_not_allow_restart() {
    let zero = fixture::encode(&[], &[(&[0], &[12])]);
    assert!(matches!(
        Image::read(0x10000, zero.len(), read(&zero)),
        Err(Error::Invalid)
    ));
    for bytes in [fixture::encode(&[], &[(&[10], &[12])])] {
        let image = Image::read(0x10000, bytes.len(), read(&bytes)).unwrap();
        let state = State::new();
        let mut reader = read(&bytes);
        let result = state.initialize(
            &image,
            |address, output| {
                if address == 0x10040 && bytes[0x40] == 10 {
                    return Err(14);
                }
                reader(address, output)
            },
            |_| panic!("invalid callback executed"),
        );
        assert!(result.is_err());
        assert!(state.initialize(&image, read(&bytes), |_| Ok(())).is_err());
    }
}
