use mnu_abi::provider;
use mochios_posix_client::terminal_read::{self, Attempt, Error};
use mochios_posix_protocol as wire;
use posix_service::pty::{EINVAL, ENOTSUP, PtyManager};

fn settings(minimum: u8, deciseconds: u8) -> wire::TerminalReadSettings {
    wire::TerminalReadSettings {
        noncanonical: true,
        minimum,
        deciseconds,
    }
}

#[test]
fn read_settings_codec_rejects_unknown_or_noncanonical_record_fields() {
    for minimum in [0, 1, 255] {
        for time in [0, 1, 255] {
            let value = settings(minimum, time);
            let mut bytes = [0xcc; 5];
            wire::encode_terminal_read_settings(value, &mut bytes).unwrap();
            assert_eq!(bytes[4], 0xcc);
            assert_eq!(wire::decode_terminal_read_settings(&bytes[..4]), Ok(value));
        }
    }
    for bytes in [
        &[][..],
        &[1, 1, 0][..],
        &[1, 1, 0, 0, 0][..],
        &[2, 1, 0, 0][..],
        &[1, 2, 0, 0][..],
        &[1, 0, 1, 0][..],
        &[1, 0, 0, 1][..],
    ] {
        assert!(wire::decode_terminal_read_settings(bytes).is_err());
    }
    let mut bytes = [0; 4];
    assert!(wire::encode_terminal_read_settings(settings(0, 0), &mut bytes[..3]).is_err());
    assert!(
        wire::encode_terminal_read_settings(
            wire::TerminalReadSettings {
                noncanonical: false,
                minimum: 1,
                deciseconds: 0,
            },
            &mut bytes
        )
        .is_err()
    );
}

#[test]
fn read_queries_are_observations_not_a_control_or_queue_access_bypass() {
    let mut ptys = PtyManager::new();
    let pair = ptys.open().unwrap();
    let mut raw = wire::TerminalAttributes::sane();
    raw.local_flags = 0;
    raw.input_flags = 0;
    raw.output_flags = 0;
    raw.control_characters[wire::TERMINAL_CC_VMIN] = 7;
    raw.control_characters[wire::TERMINAL_CC_VTIME] = 3;
    ptys.set_attributes(pair.slave_object_id, raw).unwrap();
    let query = |ptys: &mut PtyManager, id, code, input: &[u8], capacity| {
        let mut request = vec![0; provider::REQUEST_HEADER_LEN + input.len()];
        let len = provider::RequestHeader {
            opcode: provider::OP_QUERY,
            object_id: id,
            argument: 0,
            basis: code,
            length: capacity,
            data_length: input.len() as u32,
        }
        .encode(input, &mut request)
        .unwrap();
        let mut response = [0; provider::RESPONSE_HEADER_LEN + 4];
        let len = posix_service::pty::handle_provider_request(ptys, &request[..len], &mut response)
            .unwrap();
        let (header, payload) = provider::ResponseHeader::decode(&response[..len]).unwrap();
        (header.status, payload.to_vec())
    };
    ptys.write(pair.master_object_id, b"kept").unwrap();
    let (status, bytes) = query(
        &mut ptys,
        pair.slave_object_id,
        wire::PTY_QUERY_READ_SETTINGS,
        &[],
        4,
    );
    assert_eq!(status, 0);
    assert_eq!(
        wire::decode_terminal_read_settings(&bytes),
        Ok(settings(7, 3))
    );
    let (_, bytes) = query(
        &mut ptys,
        pair.master_object_id,
        wire::PTY_QUERY_READ_SETTINGS,
        &[],
        4,
    );
    assert_eq!(
        wire::decode_terminal_read_settings(&bytes),
        Ok(wire::TerminalReadSettings {
            noncanonical: false,
            minimum: 0,
            deciseconds: 0,
        })
    );
    assert_eq!(
        query(
            &mut ptys,
            pair.slave_object_id,
            wire::PTY_QUERY_READ_SETTINGS,
            &[],
            3
        )
        .0,
        -i64::from(EINVAL)
    );
    assert_eq!(
        query(
            &mut ptys,
            pair.slave_object_id,
            wire::PTY_QUERY_READ_SETTINGS,
            &[1],
            4
        )
        .0,
        -i64::from(EINVAL)
    );
    for code in [
        wire::PTY_CONTROL_SET_ATTRIBUTES_NOW,
        wire::PTY_CONTROL_SET_ATTRIBUTES_DRAIN,
        wire::PTY_CONTROL_SET_ATTRIBUTES_FLUSH,
        wire::PTY_CONTROL_FLUSH,
        wire::PTY_CONTROL_DRAIN,
        wire::PTY_CONTROL_FLOW,
        wire::PTY_CONTROL_SET_WINDOW_SIZE,
        u64::MAX,
    ] {
        assert_eq!(
            query(&mut ptys, pair.slave_object_id, code, &[0; 4], 4).0,
            -i64::from(ENOTSUP)
        );
        assert_eq!(ptys.attributes(pair.slave_object_id), Ok(raw));
    }
    assert_eq!(ptys.read(pair.slave_object_id, 32), Ok(b"kept".to_vec()));
    assert_eq!(
        ptys.read(pair.master_object_id, 32),
        Err(posix_service::pty::EAGAIN)
    );
}

#[test]
fn batching_caps_minimum_and_returns_admitted_prefix_after_backend_or_clock_failure() {
    for capacity in [1usize, 2, 7, 255, 1024] {
        for min in [1, 2, 7, 255] {
            let mut calls = 0;
            let count = terminal_read::read(
                settings(min, 0),
                capacity,
                false,
                11,
                |offset, remaining| {
                    assert_eq!(offset, calls);
                    assert_eq!(remaining, capacity - calls);
                    calls += 1;
                    Ok(Attempt::Bytes(1))
                },
                || panic!("untimed read needs no clock"),
                |_| panic!("queued data needs no wait"),
            );
            assert_eq!(count, Ok(capacity.min(usize::from(min))));
        }
    }
    let mut first = true;
    let count = terminal_read::read(
        settings(5, 0),
        32,
        false,
        11,
        |_, _| {
            if std::mem::take(&mut first) {
                Ok(Attempt::Bytes(2))
            } else {
                Err(4)
            }
        },
        || panic!(),
        |_| panic!(),
    );
    assert_eq!(count, Ok(2));
    assert_eq!(
        terminal_read::read(
            settings(0, 1),
            32,
            false,
            11,
            |_, _| panic!("failed initial clock cannot admit input"),
            || Err(5),
            |_| panic!()
        ),
        Err(Error::Io(5))
    );
    assert_eq!(
        terminal_read::read(
            settings(5, 1),
            32,
            false,
            11,
            |_, _| Ok(Attempt::Bytes(2)),
            || Err(5),
            |_| panic!()
        ),
        Ok(2)
    );
    assert_eq!(
        terminal_read::read(
            settings(5, 0),
            2,
            false,
            11,
            |_, _| Ok(Attempt::Bytes(3)),
            || panic!(),
            |_| panic!()
        ),
        Err(Error::InvalidResult)
    );
    assert_eq!(
        terminal_read::read(
            settings(5, 0),
            2,
            false,
            11,
            |_, _| Ok(Attempt::Unavailable),
            || panic!(),
            |_| Ok(false)
        ),
        Err(Error::InvalidResult)
    );
}

#[test]
fn deadline_overflow_never_becomes_infinite_and_expiry_can_precede_wait() {
    let result = terminal_read::read(
        settings(0, 255),
        32,
        false,
        11,
        |_, _| Ok(Attempt::Unavailable),
        || Ok(u64::MAX - 100),
        |end| {
            assert_eq!(end, Some(u64::MAX - 1));
            Ok(false)
        },
    );
    assert_eq!(result, Ok(0));
    let mut calls = 0;
    assert_eq!(
        terminal_read::read(
            settings(0, 1),
            32,
            false,
            11,
            |_, _| Ok(Attempt::Unavailable),
            || {
                calls += 1;
                Ok(if calls == 1 { 0 } else { 100_000_000 })
            },
            |_| panic!("already expired")
        ),
        Ok(0)
    );
}
