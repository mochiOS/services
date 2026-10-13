extern crate alloc;

#[path = "../../drivers/src/launch_arguments.rs"]
mod arguments;

use arguments::{EncodeError, encode_spawn_args};

#[test]
fn identity_and_arguments_beyond_the_old_limit_are_preserved() {
    let items = vec![
        "__MNU_EXEC_PACKAGE_ID=org.mochios.driver".to_owned(),
        "x".repeat(1024),
        "42".to_owned(),
    ];
    let encoded = encode_spawn_args(&items).unwrap();
    assert_eq!(encoded.len(), 4096);
    let decoded: Vec<_> = encoded
        .split(|byte| *byte == 0)
        .filter(|item| !item.is_empty())
        .collect();
    assert_eq!(
        decoded,
        items.iter().map(|item| item.as_bytes()).collect::<Vec<_>>()
    );
}

#[test]
fn entire_payload_must_fit_with_both_terminators() {
    let encoded = encode_spawn_args(&["x".repeat(4094)]).unwrap();
    assert_eq!(&encoded[4094..], &[0, 0]);
    assert_eq!(
        encode_spawn_args(&["x".repeat(4095)]),
        Err(EncodeError::TooLarge)
    );
    assert_eq!(
        encode_spawn_args(&["x".repeat(4093), "y".into()]),
        Err(EncodeError::TooLarge)
    );
}

#[test]
fn entry_count_and_invalid_delimiters_are_rejected_not_truncated() {
    assert!(encode_spawn_args(&vec!["x".into(); 64]).is_ok());
    assert_eq!(
        encode_spawn_args(&vec!["x".into(); 65]),
        Err(EncodeError::TooLarge)
    );
    assert_eq!(
        encode_spawn_args(&[String::new()]),
        Err(EncodeError::InvalidEntry)
    );
    assert_eq!(
        encode_spawn_args(&["identity\0forged".into()]),
        Err(EncodeError::InvalidEntry)
    );
    assert_eq!(encode_spawn_args(&[]).unwrap(), vec![0; 4096]);
}

#[test]
fn driver_launch_propagates_encoding_failure_before_the_syscall() {
    let source = include_str!("../../drivers/src/driver_spawn.rs");
    let encode = source
        .find("let args_nul = encode_spawn_args(&spawn_args)")
        .unwrap();
    let launch = source.find("platform::service::spawn_manifest(").unwrap();
    assert!(
        source[encode..launch].contains(".map_err(|_| sys_error(mochi_user_syscall::EINVAL))?")
    );
    assert!(!include_str!("../../drivers/src/spawn_support.rs").contains("fn encode_spawn_args"));
}
