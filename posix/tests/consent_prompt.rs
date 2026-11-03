use mochios_capability_protocol::consent::{
    Choice, Choices, Correlation, Error, Ticket, prompt::*,
};

fn prompt() -> Prompt<'static> {
    Prompt {
        correlation: Correlation {
            ticket: Ticket {
                id: 7,
                challenge: [0x91; 32],
            },
            display: 23,
        },
        deadline: 900,
        choices: Choices::new(Choices::ONCE).unwrap(),
        source_digest: [0x23; 32],
        package: "org.mochios.example",
        requirements: b"fs.read.user\0net.connect\0",
    }
}

fn encoded() -> Vec<u8> {
    let mut bytes = vec![0; MAX_MESSAGE_BYTES];
    let length = encode(prompt(), &mut bytes).unwrap();
    bytes.truncate(length);
    bytes
}

#[test]
fn text_and_graphical_presenters_receive_one_exact_broker_description() {
    let bytes = encoded();
    let decoded = decode(&bytes).unwrap();
    assert_eq!(decoded, prompt());
    assert_eq!(
        decoded.capabilities().collect::<Vec<_>>(),
        ["fs.read.user", "net.connect"]
    );
    assert_eq!(decoded.label(Choice::Deny), Some("Don't Allow"));
    assert_eq!(decoded.label(Choice::AllowOnce), Some("Allow Once"));
    assert_eq!(decoded.label(Choice::AllowPersistently), None);
    let mut text = String::new();
    decoded.write_text(&mut text).unwrap();
    assert!(text.contains("  fs.read.user\n  net.connect\n"));
    assert!(text.contains(&"23".repeat(32)));
    assert!(!text.contains("Always Allow"));
    assert!(!text.contains("Allow for This Process"));
}

#[test]
fn every_truncation_trailing_byte_and_reserved_field_is_rejected() {
    let bytes = encoded();
    for end in 0..bytes.len() {
        assert!(decode(&bytes[..end]).is_err(), "truncation at {end}");
    }
    let mut long = bytes.clone();
    long.push(0);
    assert!(decode(&long).is_err());
    for offset in (11..16).chain(110..112) {
        let mut invalid = bytes.clone();
        invalid[offset] = 1;
        assert!(decode(&invalid).is_err());
    }
    for offset in [8, 10, 104, 106, 108] {
        let mut invalid = bytes.clone();
        invalid[offset] = 0xff;
        assert!(decode(&invalid).is_err());
    }
}

#[test]
fn terminal_control_bidi_and_multiline_subjects_cannot_be_displayed() {
    for package in [
        "app\x1b[2J",
        "app\nAllow",
        "app\r",
        "app\0x",
        "app\u{202e}exe",
        "",
        "app name",
    ] {
        let bad = Prompt {
            package,
            ..prompt()
        };
        let mut bytes = [0; MAX_MESSAGE_BYTES];
        assert_eq!(encode(bad, &mut bytes), Err(Error::Invalid));
        assert!(bad.write_text(&mut String::new()).is_err());
    }
    for requirements in [
        b"net.connect\x1b\0".as_slice(),
        b"fs.read.user\n\0",
        b"\xff\0",
        b"\0",
        b"net.connect\0\0",
    ] {
        assert_eq!(
            encode(
                Prompt {
                    requirements,
                    ..prompt()
                },
                &mut [0; MAX_MESSAGE_BYTES]
            ),
            Err(Error::Invalid)
        );
    }
}

#[test]
fn requirements_must_be_unique_sorted_and_terminated() {
    for requirements in [
        b"net.connect\0net.connect\0".as_slice(),
        b"net.connect\0fs.read.user\0",
        b"net.connect",
    ] {
        assert_eq!(
            encode(
                Prompt {
                    requirements,
                    ..prompt()
                },
                &mut [0; MAX_MESSAGE_BYTES]
            ),
            Err(Error::Invalid)
        );
    }
    let mut bytes = [0; MAX_MESSAGE_BYTES];
    let length = encode(
        Prompt {
            requirements: b"",
            ..prompt()
        },
        &mut bytes,
    )
    .unwrap();
    assert_eq!(decode(&bytes[..length]).unwrap().capabilities().count(), 0);
}

#[test]
fn empty_correlation_deadline_and_unknown_choices_never_default() {
    let mut invalid = prompt();
    invalid.deadline = 0;
    assert!(encode(invalid, &mut [0; MAX_MESSAGE_BYTES]).is_err());
    for index in [16, 24, 56] {
        let mut bytes = encoded();
        bytes[index..index + if index == 24 { 32 } else { 8 }].fill(0);
        assert!(decode(&bytes).is_err());
    }
    let mut bytes = encoded();
    bytes[10] = 8;
    assert!(decode(&bytes).is_err());
}

#[test]
fn maximum_bounded_message_roundtrips_without_allocation_in_the_codec() {
    let package = "p".repeat(MAX_PACKAGE_BYTES);
    let requirements = (0..128).map(|i| format!("a{i:06}\0")).collect::<String>();
    assert_eq!(requirements.len(), MAX_REQUIREMENTS_BYTES);
    let maximum = Prompt {
        package: &package,
        requirements: requirements.as_bytes(),
        ..prompt()
    };
    let mut bytes = [0; MAX_MESSAGE_BYTES];
    let length = encode(maximum, &mut bytes).unwrap();
    assert_eq!(length, MAX_MESSAGE_BYTES);
    assert_eq!(decode(&bytes).unwrap(), maximum);
    assert_eq!(
        encode(maximum, &mut bytes[..MAX_MESSAGE_BYTES - 1]),
        Err(Error::BufferTooSmall)
    );
}

#[test]
fn fetch_request_contains_only_the_exact_correlation_not_a_claimed_identity() {
    let bytes = encode_fetch(prompt().correlation).unwrap();
    assert_eq!(
        u32::from_le_bytes(bytes[..4].try_into().unwrap()),
        FETCH_OPCODE
    );
    assert_eq!(decode_fetch(&bytes), Ok(prompt().correlation));
    for end in 0..FETCH_BYTES {
        assert!(decode_fetch(&bytes[..end]).is_err());
    }
    for offset in 10..16 {
        let mut invalid = bytes;
        invalid[offset] = 1;
        assert!(decode_fetch(&invalid).is_err());
    }
    assert!(decode_fetch(&[bytes.as_slice(), &[0]].concat()).is_err());
}
