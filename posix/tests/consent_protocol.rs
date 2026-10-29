use mochios_capability_protocol::consent::*;

fn correlation() -> Correlation {
    Correlation {
        ticket: Ticket {
            id: 7,
            challenge: [0x91; 32],
        },
        display: 23,
    }
}
fn encoded(feedback: Feedback) -> [u8; FEEDBACK_BYTES] {
    let mut bytes = [0; FEEDBACK_BYTES];
    assert_eq!(
        encode(correlation(), feedback, &mut bytes),
        Ok(FEEDBACK_BYTES)
    );
    bytes
}

#[test]
fn text_and_gui_feedback_use_the_same_exact_format() {
    for feedback in [
        Feedback::Presented,
        Feedback::Dismissed,
        Feedback::Decision {
            choice: Choice::Deny,
            gesture: 0,
        },
        Feedback::Decision {
            choice: Choice::AllowOnce,
            gesture: 17,
        },
        Feedback::Decision {
            choice: Choice::AllowForProcess,
            gesture: u64::MAX,
        },
        Feedback::Decision {
            choice: Choice::AllowPersistently,
            gesture: 1,
        },
    ] {
        let bytes = encoded(feedback);
        assert_eq!(decode(&bytes), Ok((correlation(), feedback)));
        assert_eq!(
            u32::from_le_bytes(bytes[..4].try_into().unwrap()),
            FEEDBACK_OPCODE
        );
        assert_eq!(&bytes[16..24], &7u64.to_le_bytes());
        assert_eq!(&bytes[56..64], &23u64.to_le_bytes());
    }
}

#[test]
fn malformed_feedback_never_defaults_to_an_allow_choice() {
    let valid = encoded(Feedback::Presented);
    for len in 0..FEEDBACK_BYTES {
        assert!(decode(&valid[..len]).is_err());
    }
    let mut long = valid.to_vec();
    long.push(0);
    assert!(decode(&long).is_err());
    for index in (12..16).chain(65..72) {
        let mut bytes = valid;
        bytes[index] = 1;
        assert_eq!(decode(&bytes), Err(Error::Invalid));
    }
    for kind in [0u16, 4, u16::MAX] {
        let mut bytes = valid;
        bytes[10..12].copy_from_slice(&kind.to_le_bytes());
        assert_eq!(decode(&bytes), Err(Error::UnknownKind));
    }
    let mut bytes = valid;
    bytes[8..10].copy_from_slice(&2u16.to_le_bytes());
    assert_eq!(decode(&bytes), Err(Error::UnsupportedVersion));
    for choice in [4, 0xff] {
        let mut bytes = encoded(Feedback::Decision {
            choice: Choice::AllowOnce,
            gesture: 1,
        });
        bytes[64] = choice;
        assert_eq!(decode(&bytes), Err(Error::Invalid));
    }
    for (start, end) in [(16, 24), (24, 56), (56, 64)] {
        let mut bytes = valid;
        bytes[start..end].fill(0);
        assert_eq!(decode(&bytes), Err(Error::Invalid));
    }
    for kind in [1u16, 3] {
        let mut bytes = encoded(Feedback::Decision {
            choice: Choice::AllowOnce,
            gesture: 1,
        });
        bytes[10..12].copy_from_slice(&kind.to_le_bytes());
        assert_eq!(decode(&bytes), Err(Error::Invalid));
    }
}

#[test]
fn denial_has_no_input_claim_and_positive_choices_have_no_zero_serial() {
    for (choice, gesture) in [
        (Choice::Deny, 1),
        (Choice::AllowOnce, 0),
        (Choice::AllowForProcess, 0),
        (Choice::AllowPersistently, 0),
    ] {
        let mut output = [0xaa; FEEDBACK_BYTES];
        assert_eq!(
            encode(
                correlation(),
                Feedback::Decision { choice, gesture },
                &mut output
            ),
            Err(Error::Invalid)
        );
        assert_eq!(output, [0xaa; FEEDBACK_BYTES]);
        let mut bytes = encoded(Feedback::Decision {
            choice: Choice::Deny,
            gesture: 0,
        });
        bytes[64] = choice as u8;
        bytes[72..80].copy_from_slice(&gesture.to_le_bytes());
        assert_eq!(decode(&bytes), Err(Error::Invalid));
    }
}

#[test]
fn explicit_choices_never_imply_an_allow_all_permission() {
    for bits in 0..=u8::MAX {
        let choices = Choices::new(bits);
        if bits & !7 != 0 {
            assert_eq!(choices, Err(Error::Invalid));
            continue;
        }
        let choices = choices.unwrap();
        assert_eq!(choices.bits(), bits);
        assert!(choices.contains(Choice::Deny));
        for (choice, bit) in [
            (Choice::AllowOnce, 1),
            (Choice::AllowForProcess, 2),
            (Choice::AllowPersistently, 4),
        ] {
            assert_eq!(choices.contains(choice), bits & bit != 0);
        }
    }
}

#[test]
fn invalid_correlation_and_short_output_do_not_partially_write() {
    for correlation in [
        Correlation {
            display: 0,
            ..correlation()
        },
        Correlation {
            ticket: Ticket {
                id: 0,
                challenge: [1; 32],
            },
            ..correlation()
        },
        Correlation {
            ticket: Ticket {
                id: 1,
                challenge: [0; 32],
            },
            ..correlation()
        },
    ] {
        let mut bytes = [0xaa; FEEDBACK_BYTES];
        assert_eq!(
            encode(correlation, Feedback::Presented, &mut bytes),
            Err(Error::Invalid)
        );
        assert_eq!(bytes, [0xaa; FEEDBACK_BYTES]);
    }
    for len in 0..FEEDBACK_BYTES {
        let mut bytes = [0xaa; FEEDBACK_BYTES];
        assert_eq!(
            encode(correlation(), Feedback::Presented, &mut bytes[..len]),
            Err(Error::BufferTooSmall)
        );
        assert_eq!(bytes, [0xaa; FEEDBACK_BYTES]);
    }
}
