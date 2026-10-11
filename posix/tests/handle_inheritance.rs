use mnu_abi::{
    process_create, HandleInfo, HANDLE_RIGHT_ALL, HANDLE_RIGHT_READ, HANDLE_RIGHT_TRANSFER,
};
use mochios_posix_client::inheritance::{prepare, Error};

const SENTINEL: process_create::HandleGrant = process_create::HandleGrant {
    key: 999,
    source: 999,
    target: 999,
    rights: 0,
};

fn record(handle: u32, rights: u64) -> HandleInfo {
    HandleInfo {
        handle,
        reserved: 0,
        rights,
    }
}

#[test]
fn preserves_unsorted_slots_and_full_width_rights_without_touching_tail() {
    let records = [
        record(41, HANDLE_RIGHT_ALL),
        record(1, HANDLE_RIGHT_TRANSFER | HANDLE_RIGHT_READ),
    ];
    let mut output = [SENTINEL; 3];
    assert_eq!(prepare(&records, &[], &mut output), Ok(2));
    for (grant, source) in output.iter().zip(records) {
        assert_eq!(grant.key, u64::from(source.handle));
        assert_eq!(grant.source, source.handle);
        assert_eq!(grant.target, source.handle);
        assert_eq!(grant.rights, source.rights);
    }
    assert_eq!(output[2], SENTINEL);
}

#[test]
fn non_transferable_reference_fails_atomically_instead_of_disappearing() {
    for rights in [0, HANDLE_RIGHT_READ] {
        let mut output = [SENTINEL; 2];
        assert_eq!(
            prepare(
                &[record(1, HANDLE_RIGHT_ALL), record(2, rights)],
                &[],
                &mut output
            ),
            Err(Error::NonTransferable(2))
        );
        assert_eq!(output, [SENTINEL; 2]);
    }
}

#[test]
fn explicit_transient_exclusion_does_not_omit_other_slots() {
    let mut output = [SENTINEL; 3];
    assert_eq!(
        prepare(
            &[
                record(8, 0),
                record(41, HANDLE_RIGHT_ALL),
                record(1, HANDLE_RIGHT_ALL)
            ],
            &[8],
            &mut output
        ),
        Ok(2)
    );
    assert_eq!(output[0].target, 41);
    assert_eq!(output[1].target, 1);
    assert_eq!(output[2], SENTINEL);
}

#[test]
fn malformed_records_and_duplicate_slots_are_rejected_even_if_excluded() {
    for records in [
        vec![record(0, HANDLE_RIGHT_ALL)],
        vec![HandleInfo {
            reserved: 1,
            ..record(8, HANDLE_RIGHT_ALL)
        }],
        vec![record(8, HANDLE_RIGHT_ALL | (1 << 61))],
    ] {
        let mut output = [SENTINEL; 2];
        assert_eq!(
            prepare(&records, &[records[0].handle], &mut output),
            Err(Error::InvalidRecord)
        );
        assert_eq!(output, [SENTINEL; 2]);
    }
    let mut output = [SENTINEL; 2];
    assert_eq!(
        prepare(&[record(8, HANDLE_RIGHT_ALL); 2], &[], &mut output),
        Err(Error::DuplicateHandle)
    );
    assert_eq!(output, [SENTINEL; 2]);
}

#[test]
fn exclusions_must_be_distinct_existing_references() {
    for exclusions in [&[0][..], &[2][..], &[1, 1][..]] {
        let mut output = [SENTINEL; 2];
        assert_eq!(
            prepare(&[record(1, HANDLE_RIGHT_ALL)], exclusions, &mut output),
            Err(Error::InvalidExclusion)
        );
        assert_eq!(output, [SENTINEL; 2]);
    }
}

#[test]
fn capacity_and_protocol_limit_never_truncate() {
    let records: Vec<_> = (1..=process_create::MAX_HANDLES as u32 + 1)
        .map(|handle| record(handle, HANDLE_RIGHT_ALL))
        .collect();
    let mut output = vec![SENTINEL; records.len()];
    assert_eq!(
        prepare(&records, &[], &mut output),
        Err(Error::TooManyHandles)
    );
    assert!(output.iter().all(|grant| *grant == SENTINEL));
    assert_eq!(
        prepare(&records[..256], &[], &mut output[..255]),
        Err(Error::BufferTooSmall)
    );
    assert!(output.iter().all(|grant| *grant == SENTINEL));
    assert_eq!(prepare(&records[..256], &[], &mut output), Ok(256));
    assert_eq!(output[255].target, 256);
    assert_eq!(output[256], SENTINEL);
}

#[test]
fn empty_or_explicitly_empty_inheritance_is_supported() {
    assert_eq!(prepare(&[], &[], &mut []), Ok(0));
    assert_eq!(prepare(&[record(1, 0)], &[1], &mut []), Ok(0));
}

#[test]
fn prepared_grants_survive_actual_native_creation_codec() {
    let mut grants = [SENTINEL; 2];
    prepare(
        &[
            record(41, HANDLE_RIGHT_ALL),
            record(1, HANDLE_RIGHT_TRANSFER),
        ],
        &[],
        &mut grants,
    )
    .unwrap();
    let context = mnu_abi::ThreadCreateContext {
        entry: 0x1000,
        stack_pointer: 0x8000,
        argument: 0,
        thread_local_base: 0,
        flags: 0,
        reserved: [0; 3],
        registers: mnu_abi::ThreadInitialRegisters::default(),
    };
    let mut bytes = vec![0; process_create::MAX_REQUEST_BYTES];
    let length =
        process_create::encode_context("image", "child", &context, &grants, &[], &mut bytes)
            .unwrap();
    let decoded = process_create::decode(&bytes[..length]).unwrap();
    assert_eq!(decoded.handles().collect::<Vec<_>>(), grants);
}
