use mnu_abi::process_image::{self, Error, Relocation, RelocationKind};

fn sample() -> ([u8; 64], [Relocation; 3]) {
    let mut stack = [0u8; 64];
    stack[16..24].copy_from_slice(&40u64.to_le_bytes());
    (
        stack,
        [
            Relocation {
                offset: 16,
                kind: RelocationKind::StackAddress,
            },
            Relocation {
                offset: 24,
                kind: RelocationKind::ElfProgramHeaders,
            },
            Relocation {
                offset: 32,
                kind: RelocationKind::ElfEntry,
            },
        ],
    )
}

#[test]
fn startup_image_round_trips_without_exposing_posix_vectors() {
    let (stack, relocations) = sample();
    let mut encoded = [0u8; 256];
    let length = process_image::encode(8, &stack, &relocations, &mut encoded).unwrap();
    let decoded = process_image::decode(&encoded[..length]).unwrap();
    assert_eq!(decoded.initial_stack_pointer(), 8);
    assert_eq!(decoded.stack(), stack);
    assert_eq!(decoded.relocations().collect::<Vec<_>>(), relocations);
}

#[test]
fn decoder_rejects_trailing_data_duplicate_patches_and_unknown_kinds() {
    let (stack, relocations) = sample();
    let mut encoded = [0u8; 256];
    let length = process_image::encode(8, &stack, &relocations, &mut encoded).unwrap();
    assert_eq!(
        process_image::decode(&encoded[..length + 1]),
        Err(Error::InvalidLength)
    );

    let mut duplicate = encoded;
    duplicate[process_image::HEADER_LEN + process_image::RELOCATION_LEN
        ..process_image::HEADER_LEN + process_image::RELOCATION_LEN + 4]
        .copy_from_slice(&16u32.to_le_bytes());
    assert_eq!(
        process_image::decode(&duplicate[..length]),
        Err(Error::DuplicateRelocation)
    );

    let mut unknown = encoded;
    unknown[process_image::HEADER_LEN + 4..process_image::HEADER_LEN + 6]
        .copy_from_slice(&99u16.to_le_bytes());
    assert_eq!(
        process_image::decode(&unknown[..length]),
        Err(Error::InvalidRelocation)
    );
}

#[test]
fn stack_address_relocations_are_aligned_and_confined_to_the_stack_image() {
    let (mut stack, relocations) = sample();
    let mut encoded = [0u8; 256];
    stack[16..24].copy_from_slice(&64u64.to_le_bytes());
    assert_eq!(
        process_image::encode(8, &stack, &relocations, &mut encoded),
        Err(Error::InvalidRelocation)
    );

    let invalid = [Relocation {
        offset: 15,
        kind: RelocationKind::ElfEntry,
    }];
    assert_eq!(
        process_image::encode(8, &[0u8; 64], &invalid, &mut encoded),
        Err(Error::InvalidRelocation)
    );
}
