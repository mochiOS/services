use mochios_capability_protocol::{ProtocolError, application_launch as wire};

fn encoded(arguments: &[&str], environment: &[&str]) -> Vec<u8> {
    let mut bytes = vec![0xcc; wire::MAX_BYTES];
    let length = wire::encode(
        &wire::Request {
            path: "/system/bin/msh",
            arguments,
            environment,
            stdio_metadata: [11, 22, 33],
        },
        &mut bytes,
    )
    .unwrap();
    bytes.truncate(length);
    bytes
}

#[test]
fn argv_and_environment_have_separate_exact_boundaries_including_empty_arguments() {
    let arguments = [
        "custom argv0",
        "",
        "__MNU_EXEC_ENV=LD_PRELOAD=/untrusted",
        "日本語",
    ];
    let environment = ["HOME=/home/test", "VALUE=a=b", "EMPTY="];
    let bytes = encoded(&arguments, &environment);
    let decoded = wire::decode(&bytes).unwrap();
    assert_eq!(decoded.path, "/system/bin/msh");
    assert_eq!(decoded.arguments.iter().collect::<Vec<_>>(), arguments);
    assert_eq!(decoded.environment.iter().collect::<Vec<_>>(), environment);
    assert_eq!(decoded.stdio_metadata, [11, 22, 33]);
    let no_environment = encoded(&["msh"], &[]);
    assert_eq!(
        wire::decode(&no_environment)
            .unwrap()
            .environment
            .iter()
            .count(),
        0
    );
}

#[test]
fn missing_terminators_trailing_data_unknown_version_reserved_fields_and_counts_are_rejected() {
    let original = encoded(&["msh", ""], &["HOME=/home/test"]);
    for length in 0..original.len() {
        assert!(wire::decode(&original[..length]).is_err(), "{length}");
    }
    for (offset, value, expected) in [
        (0, 0, ProtocolError::UnknownOpcode),
        (4, 2, ProtocolError::UnsupportedVersion),
        (12, 1, ProtocolError::InvalidField),
        (8, 0, ProtocolError::InvalidLength),
        (10, 65, ProtocolError::InvalidLength),
        (wire::HEADER_BYTES, 0xff, ProtocolError::InvalidUtf8),
    ] {
        let mut bytes = original.clone();
        bytes[offset] = value;
        assert_eq!(wire::decode(&bytes).unwrap_err(), expected);
    }
    let mut bytes = original.clone();
    bytes.push(0);
    assert_eq!(
        wire::decode(&bytes).unwrap_err(),
        ProtocolError::TrailingBytes
    );
    let mut bytes = original;
    *bytes.last_mut().unwrap() = b'x';
    assert!(wire::decode(&bytes).is_err());
}

#[test]
fn encoder_checks_bounds_and_c_text_before_changing_output() {
    for (path, arguments, environment) in [
        ("relative", vec!["msh"], vec![]),
        ("/msh", vec![], vec![]),
        ("/msh", vec!["nul\0arg"], vec![]),
        ("/msh", vec!["msh"], vec!["not-an-assignment"]),
        ("/msh", vec!["msh"], vec!["=value"]),
        ("/msh", vec!["msh"; wire::MAX_ITEMS + 1], vec![]),
    ] {
        let mut bytes = [0xcc; wire::MAX_BYTES];
        assert!(
            wire::encode(
                &wire::Request {
                    path,
                    arguments: &arguments,
                    environment: &environment,
                    stdio_metadata: [0; 3]
                },
                &mut bytes
            )
            .is_err()
        );
        assert_eq!(bytes, [0xcc; wire::MAX_BYTES]);
    }
    let value = "x".repeat(wire::MAX_BYTES);
    let mut bytes = [0xcc; wire::MAX_BYTES];
    assert!(
        wire::encode(
            &wire::Request {
                path: "/msh",
                arguments: &[&value],
                environment: &[],
                stdio_metadata: [0; 3]
            },
            &mut bytes
        )
        .is_err()
    );
    assert_eq!(bytes, [0xcc; wire::MAX_BYTES]);
}
