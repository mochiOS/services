extern crate alloc;

#[path = "../../service-manager/src/launch_arguments.rs"]
mod production;

use mochios_posix_client::launch_arguments::EncodeError;
use production::encode_native_launch;

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
fn service_launcher_uses_the_shared_client_encoder_without_a_private_copy() {
    let source = include_str!("../../service-manager/src/launch_arguments.rs");
    assert!(source.contains(
        "pub(crate) use mochios_posix_client::launch_arguments::encode_native_launch"
    ));
    assert!(!source.contains("fn encode_native_launch("));
    assert!(!source.contains("fn decimal("));
    let items = vec!["argument".into(), "".into()];
    assert_eq!(
        native(&items).unwrap(),
        mochios_posix_client::launch_arguments::encode_native_launch(
            "/system/services/example.service",
            "example.service",
            &items,
            [17; 16]
        )
        .unwrap()
    );
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
fn legacy_launch_wrapper_and_fixed_argument_block_are_removed() {
    let platform = include_str!("../../../user/crates/platform/src/lib.rs");
    let launcher = include_str!("../../service-manager/src/launch_arguments.rs");
    for source in [platform, launcher] {
        for obsolete in [
            "spawn_manifest",
            "spawn_arguments",
            "encode_spawn_args",
            "SPAWN_ARGUMENT_BYTES",
        ] {
            assert!(
                !source.contains(obsolete),
                "legacy launch dependency: {obsolete}"
            );
        }
    }
}
