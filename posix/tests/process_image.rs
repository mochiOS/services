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

    let word = |offset: usize| u64::from_le_bytes(stack[offset..offset + 8].try_into().unwrap());
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

#[test]
fn userspace_loader_metadata_describes_the_program_instead_of_the_native_container() {
    use mochios_posix_client::process_image::{Executable, encode_initial_stack_for_image};
    let image = Executable {
        entry: 0x20123456,
        program_headers: 0x20000040,
        program_header_size: 56,
        program_header_count: 4,
        interpreter_base: 0x70000000,
        load_bias: 0x20000000,
    };
    let mut output = [0u8; process_image::MAX_IMAGE_BYTES];
    let length = encode_initial_stack_for_image(
        &[b"program"],
        &[b"A=B"],
        b"program",
        [7; 16],
        &[],
        Some(image),
        &mut output,
    )
    .unwrap();
    let startup = process_image::decode(&output[..length]).unwrap();
    let words = startup
        .stack()
        .chunks_exact(8)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
        .collect::<Vec<_>>();
    let aux = words[5..]
        .chunks_exact(2)
        .take_while(|pair| pair[0] != 0)
        .map(|pair| (pair[0], pair[1]))
        .collect::<Vec<_>>();
    for pair in [
        (3, image.program_headers),
        (4, 56),
        (5, 4),
        (7, image.interpreter_base),
        (9, image.entry),
        (
            mochios_posix_client::process_image::AT_IMAGE_LOAD_BIAS,
            image.load_bias,
        ),
    ] {
        assert_eq!(
            aux.iter()
                .filter(|value| value.0 == pair.0)
                .copied()
                .collect::<Vec<_>>(),
            [pair]
        );
    }
    assert!(!startup.relocations().any(|r| matches!(
        r.kind,
        RelocationKind::ElfProgramHeaders
            | RelocationKind::ElfProgramHeaderSize
            | RelocationKind::ElfProgramHeaderCount
            | RelocationKind::ElfEntry
    )));
    assert!(
        startup
            .relocations()
            .any(|r| r.kind == RelocationKind::StackAddress)
    );
    assert!(
        startup
            .relocations()
            .any(|r| r.kind == RelocationKind::PageSize)
    );
}

#[test]
fn loader_bias_is_distinct_from_interpreter_base_and_cannot_be_shadowed() {
    use mochios_posix_client::process_image::{AT_IMAGE_LOAD_BIAS, encode_initial_stack_with_aux};
    let mut output = [0u8; process_image::MAX_IMAGE_BYTES];
    assert_eq!(
        encode_initial_stack_with_aux(
            &[b"program"],
            &[],
            b"program",
            [0; 16],
            &[(AT_IMAGE_LOAD_BIAS, 123)],
            &mut output
        ),
        Err(EncodeError::InvalidText)
    );
    let length =
        encode_initial_stack(&[b"program"], &[], b"program", [0; 16], &mut output).unwrap();
    let startup = process_image::decode(&output[..length]).unwrap();
    let aux = startup.stack()[32..]
        .chunks_exact(16)
        .map(|pair| {
            (
                u64::from_le_bytes(pair[..8].try_into().unwrap()),
                u64::from_le_bytes(pair[8..].try_into().unwrap()),
            )
        })
        .take_while(|pair| pair.0 != 0)
        .collect::<Vec<_>>();
    assert_eq!(
        aux.iter()
            .filter(|pair| pair.0 == AT_IMAGE_LOAD_BIAS)
            .copied()
            .collect::<Vec<_>>(),
        [(AT_IMAGE_LOAD_BIAS, 0)]
    );
}

#[test]
fn process_entry_identity_is_literal_userspace_data_before_any_runtime_patch() {
    use mochios_posix_client::process_image::{
        Identity, Process, encode_initial_stack_for_process,
    };
    for identity in [
        Identity {
            real_uid: 501,
            effective_uid: 501,
            real_gid: 20,
            effective_gid: 20,
        },
        Identity {
            real_uid: 0,
            effective_uid: 501,
            real_gid: 20,
            effective_gid: 20,
        },
        Identity {
            real_uid: u32::MAX,
            effective_uid: u32::MAX,
            real_gid: 20,
            effective_gid: 21,
        },
    ] {
        let mut output = [0u8; process_image::MAX_IMAGE_BYTES];
        let length = encode_initial_stack_for_process(
            &[b"program"],
            &[],
            b"/program",
            [0; 16],
            &[],
            Process {
                image: None,
                identity,
                lifecycle: &[],
                tls: &[],
                indirect: &[],
            },
            &mut output,
        )
        .unwrap();
        let decoded = process_image::decode(&output[..length]).unwrap();
        let words: Vec<_> = decoded
            .stack()
            .chunks_exact(8)
            .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()))
            .collect();
        let auxiliary: Vec<_> = words[4..]
            .chunks_exact(2)
            .take_while(|pair| pair[0] != 0)
            .collect();
        let expected = [
            (11, identity.real_uid as u64),
            (12, identity.effective_uid as u64),
            (13, identity.real_gid as u64),
            (14, identity.effective_gid as u64),
            (23, if identity.real_uid == 501 { 0 } else { 1 }),
        ];
        for (key, value) in expected {
            let matches: Vec<_> = auxiliary.iter().filter(|pair| pair[0] == key).collect();
            assert_eq!(matches.len(), 1);
            assert_eq!(matches[0][1], value);
            let offset = 4 * 8 + auxiliary.iter().position(|pair| pair[0] == key).unwrap() * 16 + 8;
            assert!(
                !decoded
                    .relocations()
                    .any(|relocation| relocation.offset as usize == offset)
            );
        }
        assert_eq!(
            encode_initial_stack_for_process(
                &[b"program"],
                &[],
                b"/program",
                [0; 16],
                &[(11, 0)],
                Process {
                    image: None,
                    identity,
                    lifecycle: &[],
                    tls: &[],
                    indirect: &[],
                },
                &mut output
            ),
            Err(EncodeError::InvalidText)
        );
    }
}

#[test]
fn lifecycle_bytes_are_aligned_opaque_stack_data_with_one_generic_relocation() {
    use mochios_posix_client::process_image::{
        AT_LIFECYCLE_IMAGE, Process, encode_initial_stack_for_process,
    };
    let payload = b"\0binary\xfflifecycle\0";
    let mut output = [0; process_image::MAX_IMAGE_BYTES];
    let length = encode_initial_stack_for_process(
        &[b"program"],
        &[b"X=1"],
        b"/program",
        [7; 16],
        &[],
        Process {
            lifecycle: payload,
            ..Process::default()
        },
        &mut output,
    )
    .unwrap();
    let decoded = process_image::decode(&output[..length]).unwrap();
    let stack = decoded.stack();
    let words: Vec<_> = stack
        .chunks_exact(8)
        .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()))
        .collect();
    let slot = words[5..]
        .chunks_exact(2)
        .position(|pair| pair[0] == AT_LIFECYCLE_IMAGE)
        .unwrap()
        * 2
        + 5;
    let offset = words[slot + 1] as usize;
    assert_eq!(offset % 8, 0);
    assert_eq!(&stack[offset..offset + payload.len()], payload);
    assert_eq!(
        decoded
            .relocations()
            .filter(|relocation| relocation.offset as usize == (slot + 1) * 8
                && relocation.kind == RelocationKind::StackAddress)
            .count(),
        1
    );
    assert_eq!(
        encode_initial_stack_for_process(
            &[b"program"],
            &[],
            b"program",
            [0; 16],
            &[(AT_LIFECYCLE_IMAGE, 0)],
            Process::default(),
            &mut output
        ),
        Err(EncodeError::InvalidText)
    );
    let oversized = vec![0; process_image::MAX_STACK_BYTES];
    assert_eq!(
        encode_initial_stack_for_process(
            &[b"program"],
            &[],
            b"program",
            [0; 16],
            &[],
            Process {
                lifecycle: &oversized,
                ..Process::default()
            },
            &mut output
        ),
        Err(EncodeError::ImageTooLarge)
    );
}

#[test]
fn loader_payloads_are_separate_aligned_and_share_the_total_stack_limit() {
    use mochios_posix_client::process_image::{
        AT_INDIRECT_IMAGE, AT_LIFECYCLE_IMAGE, AT_TLS_IMAGE, Process,
        encode_initial_stack_for_process,
    };
    let lifecycle = b"abc";
    let tls = b"\0TLS\xff\0";
    let indirect = b"irel\0\xfe\0";
    let mut output = [0; process_image::MAX_IMAGE_BYTES];
    let length = encode_initial_stack_for_process(
        &[b"program"],
        &[],
        b"program",
        [0; 16],
        &[],
        Process {
            lifecycle,
            tls,
            indirect,
            ..Process::default()
        },
        &mut output,
    )
    .unwrap();
    let decoded = process_image::decode(&output[..length]).unwrap();
    let stack = decoded.stack();
    let mut offsets = Vec::new();
    for (index, pair) in stack[4 * 8..].chunks_exact(16).enumerate() {
        let key = u64::from_le_bytes(pair[..8].try_into().unwrap());
        if key == 0 {
            break;
        }
        if let Some(payload) = match key {
            AT_LIFECYCLE_IMAGE => Some(&lifecycle[..]),
            AT_TLS_IMAGE => Some(&tls[..]),
            AT_INDIRECT_IMAGE => Some(&indirect[..]),
            _ => None,
        } {
            let offset = u64::from_le_bytes(pair[8..].try_into().unwrap()) as usize;
            assert_eq!(offset % 8, 0);
            assert_eq!(&stack[offset..offset + payload.len()], payload);
            assert_eq!(
                decoded
                    .relocations()
                    .filter(
                        |relocation| relocation.offset as usize == (4 + index * 2 + 1) * 8
                            && relocation.kind == RelocationKind::StackAddress
                    )
                    .count(),
                1
            );
            offsets.push((offset, payload.len()));
        }
    }
    assert_eq!(offsets.len(), 3);
    assert!(offsets.windows(2).all(|p| p[0].0 + p[0].1 <= p[1].0));
    assert_eq!(
        encode_initial_stack_for_process(
            &[b"program"],
            &[],
            b"program",
            [0; 16],
            &[(AT_TLS_IMAGE, 0)],
            Process::default(),
            &mut output
        ),
        Err(EncodeError::InvalidText)
    );
    let payload = [0u8; process_image::MAX_STACK_BYTES / 2];
    assert_eq!(
        encode_initial_stack_for_process(
            &[b"program"],
            &[],
            b"program",
            [0; 16],
            &[],
            Process {
                lifecycle: &payload,
                tls: &payload,
                ..Process::default()
            },
            &mut output
        ),
        Err(EncodeError::ImageTooLarge)
    );
    for key in [AT_LIFECYCLE_IMAGE, AT_TLS_IMAGE, AT_INDIRECT_IMAGE] {
        assert_eq!(
            encode_initial_stack_for_process(
                &[b"program"],
                &[],
                b"program",
                [0; 16],
                &[(key, 0)],
                Process::default(),
                &mut output
            ),
            Err(EncodeError::InvalidText)
        );
    }
    assert_eq!(
        encode_initial_stack_for_process(
            &[b"program"],
            &[],
            b"program",
            [0; 16],
            &[],
            Process {
                indirect: &[0; process_image::MAX_STACK_BYTES],
                ..Process::default()
            },
            &mut output
        ),
        Err(EncodeError::ImageTooLarge)
    );
}

#[test]
fn common_encoder_filters_secure_loader_environment_before_sizing_and_preserves_order() {
    use mochios_posix_client::process_image::{
        Identity, Process, encode_initial_stack_for_process,
    };
    let huge = vec![b'x'; process_image::MAX_STACK_BYTES];
    let mut excluded = b"LD_LIBRARY_PATH=".to_vec();
    excluded.extend_from_slice(&huge);
    let environment: &[&[u8]] = &[
        &excluded,
        b"KEEP=first",
        b"LD_PRELOAD=one",
        b"LD_AUDIT=two",
        b"LD_LIBRARY_PATH_SUFFIX=retained",
        b"KEEP=second",
        b"raw=\xff",
    ];
    let mut output = [0; process_image::MAX_IMAGE_BYTES];
    let process = Process {
        identity: Identity {
            real_uid: 501,
            effective_uid: 0,
            real_gid: 20,
            effective_gid: 20,
        },
        ..Process::default()
    };
    let length = encode_initial_stack_for_process(
        &[b"program"],
        environment,
        b"program",
        [0; 16],
        &[],
        process,
        &mut output,
    )
    .unwrap();
    let decoded = process_image::decode(&output[..length]).unwrap();
    let stack = decoded.stack();
    let mut values = Vec::new();
    for index in 3.. {
        let offset =
            u64::from_le_bytes(stack[index * 8..index * 8 + 8].try_into().unwrap()) as usize;
        if offset == 0 {
            break;
        }
        let text = &stack[offset..];
        values.push(&text[..text.iter().position(|&byte| byte == 0).unwrap()]);
    }
    assert_eq!(
        values,
        [
            b"KEEP=first".as_slice(),
            b"LD_LIBRARY_PATH_SUFFIX=retained",
            b"KEEP=second",
            b"raw=\xff"
        ]
    );
    assert!(!stack.windows(huge.len()).any(|window| window == huge));
    assert_eq!(
        encode_initial_stack_for_process(
            &[b"program"],
            environment,
            b"program",
            [0; 16],
            &[],
            Process::default(),
            &mut output
        ),
        Err(EncodeError::ImageTooLarge)
    );
    assert_eq!(
        encode_initial_stack_for_process(
            &[b"program"],
            &[b"LD_PRELOAD=bad\0value"],
            b"program",
            [0; 16],
            &[],
            process,
            &mut output
        ),
        Err(EncodeError::InvalidText)
    );
}
