use mochios_capability_protocol::{
    consent::{Correlation, Ticket},
    presentation as w,
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
fn context() -> w::Context {
    w::Context {
        session: 3,
        generation: 5,
        active: true,
    }
}
fn receipt() -> w::Receipt {
    w::Receipt {
        status: 0,
        stage: w::Stage::Presented,
        registration: 13,
        context: context(),
        focus_generation: 17,
        surface: 19,
        content_generation: 23,
        renderer: w::Image {
            process: 29,
            revision: 0,
            digest: [31; 32],
        },
    }
}
#[test]
fn exact_context_and_command_encodings_reject_trailing_bytes_reserved_fields_and_missing_bindings()
{
    for active in [false, true] {
        let context = w::Context {
            active,
            ..context()
        };
        let bytes = w::encode_session(context).unwrap();
        assert_eq!(w::decode_session(&bytes), Ok(context));
        for n in 0..bytes.len() {
            assert!(w::decode_session(&bytes[..n]).is_err());
        }
        for at in [0, 4, 6, 24, 25, 31] {
            let mut bad = bytes;
            bad[at] = 255;
            assert!(w::decode_session(&bad).is_err());
        }
    }
    for command in [
        w::Command::Register {
            context: context(),
            correlation: correlation(),
            kind: w::Kind::SecureOverlay,
        },
        w::Command::Register {
            context: context(),
            correlation: correlation(),
            kind: w::Kind::Window,
        },
        w::Command::Bind {
            correlation: correlation(),
            surface: 19,
        },
        w::Command::Status {
            correlation: correlation(),
            registration: 13,
        },
        w::Command::Cancel {
            correlation: correlation(),
            registration: 13,
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
        for at in [0, 4, 6] {
            let mut bad = bytes;
            bad[at] = 255;
            assert!(w::decode_command(&bad).is_err());
        }
        for range in [24..32, 32..64, 64..72] {
            let mut bad = bytes;
            bad[range].fill(0);
            assert!(w::decode_command(&bad).is_err());
        }
        if !matches!(command, w::Command::Register { .. }) {
            for at in [8, 16, 80] {
                let mut bad = bytes;
                bad[at] = 1;
                assert!(w::decode_command(&bad).is_err());
            }
        }
    }
}
#[test]
fn failure_receipts_cannot_smuggle_display_evidence_and_presented_receipts_need_a_real_frame() {
    for value in [
        receipt(),
        w::Receipt {
            stage: w::Stage::Pending,
            ..receipt()
        },
        w::Receipt {
            stage: w::Stage::Revoked,
            ..receipt()
        },
        w::Receipt::failure(13),
    ] {
        let bytes = w::encode_receipt(value).unwrap();
        assert_eq!(w::decode_receipt(&bytes), Ok(value));
        for n in 0..bytes.len() {
            assert!(w::decode_receipt(&bytes[..n]).is_err());
        }
        for at in [0, 4, 6, 112, 127] {
            let mut bad = bytes;
            bad[at] = 255;
            assert!(w::decode_receipt(&bad).is_err());
        }
    }
    let bytes = w::encode_receipt(receipt()).unwrap();
    for at in [16, 24, 32, 40, 48, 56, 64] {
        let mut bad = bytes;
        bad[at..at + 8].fill(0);
        assert!(w::decode_receipt(&bad).is_err(), "{at}");
    }
    assert!(
        w::encode_receipt(w::Receipt {
            status: 13,
            ..receipt()
        })
        .is_err()
    );
    let mut bad = w::encode_receipt(w::Receipt::failure(13)).unwrap();
    bad[80] = 1;
    assert!(w::decode_receipt(&bad).is_err());
}
