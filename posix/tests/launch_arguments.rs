extern crate alloc;

#[path = "../../service-manager/src/launch_arguments.rs"]
mod production;

use production::{encode_spawn_args, EncodeError};

#[test]
fn launch_metadata_preserves_identity_and_handles_past_the_old_512_byte_limit() {
    let inherited = format!("{}7:19:12", mnu_abi::exec::INHERITED_HANDLE_PREFIX);
    let items = ["a".repeat(700), inherited.clone()];
    let bytes = encode_spawn_args(&items).unwrap();
    assert_eq!(bytes.len(), 4096);
    assert_eq!(&bytes[..700], items[0].as_bytes());
    assert_eq!(&bytes[701..701 + inherited.len()], inherited.as_bytes());
    assert!(bytes[701 + inherited.len()..].iter().all(|byte| *byte == 0));
}

#[test]
fn launch_metadata_accepts_exact_limits_without_truncation() {
    assert_eq!(
        encode_spawn_args(&["x".repeat(4094)]).unwrap()[4094..],
        [0, 0]
    );
    let entries = vec!["x".to_string(); 64];
    let bytes = encode_spawn_args(&entries).unwrap();
    assert_eq!(bytes[..128], b"x\0".repeat(64));
    assert_eq!(bytes[128], 0);
}

#[test]
fn launch_metadata_rejects_oversized_or_ambiguous_lists_instead_of_dropping_entries() {
    assert_eq!(
        encode_spawn_args(&["x".repeat(4095)]),
        Err(EncodeError::TooLarge)
    );
    assert_eq!(
        encode_spawn_args(&vec!["x".into(); 65]),
        Err(EncodeError::TooLarge)
    );
    assert_eq!(
        encode_spawn_args(&["".into()]),
        Err(EncodeError::InvalidEntry)
    );
    assert_eq!(
        encode_spawn_args(&["a\0b".into()]),
        Err(EncodeError::InvalidEntry)
    );
    assert!(encode_spawn_args(&[])
        .unwrap()
        .iter()
        .all(|byte| *byte == 0));
}
