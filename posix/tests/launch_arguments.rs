extern crate alloc;

#[path = "../../service-manager/src/launch_arguments.rs"]
mod production;

use production::{EncodeError, encode_native_launch, encode_spawn_args};

fn native(items: &[String]) -> Result<Vec<u8>, EncodeError> {
    encode_native_launch(
        "/system/services/example.service",
        "example.service",
        items,
        [17; 16],
    )
}

fn stack_word(stack: &[u8], index: usize) -> usize {
    u64::from_le_bytes(stack[index * 8..index * 8 + 8].try_into().unwrap()) as usize
}

fn stack_text(stack: &[u8], pointer: usize) -> &[u8] {
    let text = &stack[pointer..];
    &text[..text.iter().position(|byte| *byte == 0).unwrap()]
}

#[test]
fn native_launch_builds_argv_env_and_inheritance_in_user_space() {
    use mnu_abi::exec::{ENVIRONMENT_PREFIX, INHERITED_HANDLE_PREFIX, INHERITED_VALUE_PREFIX};
    let rights = mnu_abi::HANDLE_RIGHT_SEND | mnu_abi::HANDLE_RIGHT_TRANSFER;
    let items = [
        "argument".into(),
        format!("{ENVIRONMENT_PREFIX}HOME=/home/test"),
        format!("{INHERITED_HANDLE_PREFIX}7:19:{rights}"),
        format!("{INHERITED_VALUE_PREFIX}7:{}", u64::MAX),
        "".into(),
    ];
    let bytes = native(&items).unwrap();
    let request = mnu_abi::process_create::decode(&bytes).unwrap();
    assert_eq!(request.identity, "/system/services/example.service");
    assert_eq!(request.label, "example.service");
    assert_eq!(
        request.handles().collect::<Vec<_>>(),
        [mnu_abi::process_create::HandleGrant {
            key: 7,
            source: 19,
            target: 0,
            rights,
        }]
    );
    assert_eq!(
        request.values().collect::<Vec<_>>(),
        [mnu_abi::process_create::Value {
            key: 7,
            value: u64::MAX,
        }]
    );
    let mnu_abi::process_create::InitialState::Image(startup) = request.startup else {
        panic!("expected image")
    };
    let stack = startup.stack();
    assert_eq!(stack_word(stack, 0), 3);
    assert_eq!(stack_text(stack, stack_word(stack, 1)), b"example.service");
    assert_eq!(stack_text(stack, stack_word(stack, 2)), b"argument");
    assert_eq!(stack_text(stack, stack_word(stack, 3)), b"");
    assert_eq!(stack_word(stack, 4), 0);
    assert_eq!(stack_text(stack, stack_word(stack, 5)), b"HOME=/home/test");
    assert_eq!(stack_word(stack, 6), 0);
    assert!(!stack.windows(11).any(|bytes| bytes == b"__MNU_EXEC_"));
}

#[test]
fn native_launch_rejects_invalid_or_duplicate_handle_grants() {
    for value in [
        "",
        "1:2",
        "1:2:1:4",
        "1:0:1",
        "1:4294967296:1",
        "1:2:512",
        "+1:2:1",
        "1:-2:1",
        "1:2:18446744073709551616",
        " 1:2:1",
    ] {
        assert_eq!(
            native(&[format!("{}{value}", mnu_abi::exec::INHERITED_HANDLE_PREFIX)]),
            Err(EncodeError::InvalidEntry),
            "{value}"
        );
    }
    let grant = format!("{}1:2:1", mnu_abi::exec::INHERITED_HANDLE_PREFIX);
    assert_eq!(
        native(&[grant.clone(), grant]),
        Err(EncodeError::InvalidEntry)
    );
}

#[test]
fn native_launch_rejects_invalid_values_and_environment_without_truncation() {
    for value in ["1", "1:2:3", "1:+2", "1:18446744073709551616"] {
        assert_eq!(
            native(&[format!("{}{value}", mnu_abi::exec::INHERITED_VALUE_PREFIX)]),
            Err(EncodeError::InvalidEntry)
        );
    }
    let value = format!("{}1:2", mnu_abi::exec::INHERITED_VALUE_PREFIX);
    assert_eq!(
        native(&[value.clone(), value]),
        Err(EncodeError::InvalidEntry)
    );
    for value in ["", "HOME", "=value", "HOME=a\0b"] {
        assert_eq!(
            native(&[format!("{}{value}", mnu_abi::exec::ENVIRONMENT_PREFIX)]),
            Err(EncodeError::InvalidEntry)
        );
    }
    assert!(native(&[format!("{}HOME=", mnu_abi::exec::ENVIRONMENT_PREFIX)]).is_ok());
    assert_eq!(native(&["a\0b".into()]), Err(EncodeError::InvalidEntry));
}

#[test]
fn native_launch_does_not_accept_security_policy_from_argument_strings() {
    for prefix in [
        mnu_abi::exec::SECURITY_IDENTITY_PREFIX,
        mnu_abi::exec::APPLICATION_PACKAGE_ID_PREFIX,
        mnu_abi::exec::EXECUTABLE_DIGEST_PREFIX,
        mnu_abi::exec::EXEC_AUTHORIZATION_KIND_PREFIX,
        "__MNU_EXEC_UNKNOWN=",
    ] {
        assert_eq!(
            native(&[format!("{prefix}forged")]),
            Err(EncodeError::InvalidEntry)
        );
    }
}

#[test]
fn native_launch_bounds_inheritance_and_startup_images() {
    let grants = (0..mnu_abi::process_create::MAX_HANDLES)
        .map(|key| {
            format!(
                "{}{key}:{}:0",
                mnu_abi::exec::INHERITED_HANDLE_PREFIX,
                u32::MAX
            )
        })
        .collect::<Vec<_>>();
    assert!(native(&grants).is_ok());
    let mut grant_overflow = grants;
    grant_overflow.push(format!("{}256:1:0", mnu_abi::exec::INHERITED_HANDLE_PREFIX));
    assert_eq!(native(&grant_overflow), Err(EncodeError::TooLarge));
    let values = (0..mnu_abi::process_create::MAX_VALUES)
        .map(|key| format!("{}{key}:0", mnu_abi::exec::INHERITED_VALUE_PREFIX))
        .collect::<Vec<_>>();
    assert!(native(&values).is_ok());
    let mut overflow = values;
    overflow.push(format!("{}256:0", mnu_abi::exec::INHERITED_VALUE_PREFIX));
    assert_eq!(native(&overflow), Err(EncodeError::TooLarge));
    let oversized = "x".repeat(mnu_abi::process_image::MAX_STACK_BYTES + 1);
    assert!(matches!(native(&[oversized]), Err(EncodeError::Startup(_))));
    assert_eq!(
        encode_native_launch("x", "", &[], [0; 16]),
        Err(EncodeError::InvalidEntry)
    );
}

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
    assert!(
        encode_spawn_args(&[])
            .unwrap()
            .iter()
            .all(|byte| *byte == 0)
    );
}
