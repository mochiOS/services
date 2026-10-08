use mnu_abi::process_image::{self, Error, Relocation, RelocationKind};
use mochios_posix_client::process_image::{EncodeError, encode_initial_stack};

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

#[test]
fn posix_client_owns_system_v_argument_and_environment_layout() {
    let argv: &[&[u8]] = &[b"/bin/tool", b"--check"];
    let envp: &[&[u8]] = &[b"HOME=/home/testuser", b"LANG=ja_JP.UTF-8"];
    let random = *b"0123456789abcdef";
    let mut encoded = [0u8; 9_000];
    let length = encode_initial_stack(argv, envp, b"/bin/tool", random, &mut encoded).unwrap();
    let image = process_image::decode(&encoded[..length]).unwrap();
    assert_eq!(image.initial_stack_pointer(), 0);
    assert_eq!(image.stack().len() & 15, 0);

    let mut stack = image.stack().to_vec();
    let image_base = 0x7fff_0000u64;
    for relocation in image.relocations() {
        let offset = relocation.offset as usize;
        let stored = u64::from_le_bytes(stack[offset..offset + 8].try_into().unwrap());
        let resolved = match relocation.kind {
            RelocationKind::StackAddress => image_base + stored,
            RelocationKind::ElfProgramHeaders => 0x400040,
            RelocationKind::ElfProgramHeaderSize => 56,
            RelocationKind::ElfProgramHeaderCount => 9,
            RelocationKind::ElfEntry => 0x401000,
            RelocationKind::PageSize => 4096,
        };
        stack[offset..offset + 8].copy_from_slice(&resolved.to_le_bytes());
    }

    let word = |offset: usize| {
        u64::from_le_bytes(stack[offset..offset + 8].try_into().unwrap())
    };
    assert_eq!(word(0), 2);
    let argv0 = (word(8) - image_base) as usize;
    let argv1 = (word(16) - image_base) as usize;
    assert_eq!(&stack[argv0..argv0 + 10], b"/bin/tool\0");
    assert_eq!(&stack[argv1..argv1 + 8], b"--check\0");
    assert_eq!(word(24), 0);
    let env0 = (word(32) - image_base) as usize;
    assert_eq!(&stack[env0..env0 + 20], b"HOME=/home/testuser\0");
    assert_eq!(word(48), 0);

    let auxiliary_vector = 56;
    assert_eq!(word(auxiliary_vector), 3);
    assert_eq!(word(auxiliary_vector + 8), 0x400040);
    assert_eq!(word(auxiliary_vector + 16), 4);
    assert_eq!(word(auxiliary_vector + 24), 56);
}

#[test]
fn posix_stack_encoder_rejects_invalid_or_oversized_vectors() {
    let mut encoded = [0u8; 9_000];
    assert_eq!(
        encode_initial_stack(&[], &[], b"/bin/tool", [0; 16], &mut encoded),
        Err(EncodeError::EmptyArgumentVector)
    );
    assert_eq!(
        encode_initial_stack(&[b"bad\0arg"], &[], b"/bin/tool", [0; 16], &mut encoded),
        Err(EncodeError::InvalidText)
    );
    let oversized = [b'x'; process_image::MAX_STACK_BYTES];
    assert_eq!(
        encode_initial_stack(&[&oversized], &[], b"/bin/tool", [0; 16], &mut encoded),
        Err(EncodeError::ImageTooLarge)
    );
}

#[test]
fn native_process_image_replacement_uses_the_post_posix_syscall_range() {
    assert_eq!(mnu_abi::SyscallNumber::ProcessImageReplace as u64, 665);
}
