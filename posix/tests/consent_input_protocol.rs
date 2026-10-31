use mochios_capability_protocol::{
    consent::{Correlation, Ticket},
    input_authority as w,
};

fn correlation() -> Correlation {
    Correlation {
        ticket: Ticket {
            id: 7,
            challenge: [9; 32],
        },
        display: 11,
    }
}
#[test]
fn exact_commands_bind_generation_ticket_and_display_without_claimed_peers() {
    for command in [
        w::Command::Register,
        w::Command::Arm {
            generation: 3,
            correlation: correlation(),
        },
        w::Command::Cancel {
            generation: 3,
            correlation: correlation(),
        },
        w::Command::Status {
            generation: 3,
            correlation: correlation(),
        },
    ] {
        let bytes = w::encode_command(command).unwrap();
        assert_eq!(w::decode_command(&bytes), Ok(command));
        for n in 0..bytes.len() {
            assert!(w::decode_command(&bytes[..n]).is_err());
        }
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert!(w::decode_command(&trailing).is_err());
    }
    let mut bytes = w::encode_command(w::Command::Register).unwrap();
    bytes[8] = 1;
    assert!(w::decode_command(&bytes).is_err());
    for offset in [8, 16, 56] {
        let mut bytes = w::encode_command(w::Command::Arm {
            generation: 3,
            correlation: correlation(),
        })
        .unwrap();
        bytes[offset..offset + 8].fill(0);
        assert!(w::decode_command(&bytes).is_err());
    }
}
#[test]
fn failed_replies_cannot_smuggle_a_snapshot_and_reserved_fields_are_rejected() {
    for reply in [
        w::Reply::failure(13),
        w::Reply {
            status: 0,
            generation: 5,
            serial: 0,
            all_released: true,
        },
    ] {
        let bytes = w::encode_reply(reply).unwrap();
        assert_eq!(w::decode_reply(&bytes), Ok(reply));
        for offset in [0, 4, 6, 12, 32, 39] {
            let mut changed = bytes;
            changed[offset] = 0xff;
            assert!(w::decode_reply(&changed).is_err(), "{offset}");
        }
        for n in 0..bytes.len() {
            assert!(w::decode_reply(&bytes[..n]).is_err());
        }
    }
    assert!(
        w::encode_reply(w::Reply {
            status: 13,
            generation: 1,
            serial: 0,
            all_released: false
        })
        .is_err()
    );
    assert!(
        w::encode_reply(w::Reply {
            status: 0,
            generation: 0,
            serial: 0,
            all_released: false
        })
        .is_err()
    );
}
#[test]
fn every_observation_has_exact_boundaries_and_a_nonzero_serial_and_control() {
    for transition in [
        w::Transition::AllReleased,
        w::Transition::PhysicalPress,
        w::Transition::Repeat,
        w::Transition::Synthetic,
        w::Transition::Release,
    ] {
        let event = w::Event {
            generation: 3,
            correlation: correlation(),
            observation: w::Observation {
                serial: 5,
                transition,
                control: 258,
            },
        };
        let bytes = w::encode_event(event).unwrap();
        assert_eq!(w::decode_event(&bytes), Ok(event));
        for n in 0..bytes.len() {
            assert!(w::decode_event(&bytes[..n]).is_err());
        }
        for offset in [0, 4, 6, 74, 79] {
            let mut changed = bytes;
            changed[offset] = 0xff;
            assert!(w::decode_event(&changed).is_err());
        }
        for offset in [8, 16, 56, 64, 72] {
            let mut changed = bytes;
            changed[offset..offset + if offset == 72 { 2 } else { 8 }].fill(0);
            assert!(w::decode_event(&changed).is_err(), "{offset}");
        }
    }
}
