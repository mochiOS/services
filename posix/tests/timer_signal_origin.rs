use mochios_posix_client::{
    Client, Transport,
    signal_context::{InfoError, SI_TIMER, SigInfo},
};
use mochios_posix_protocol::{self as protocol, signal_origin as origin, signal_wait};

fn timer() -> origin::Origin {
    origin::Origin {
        source: origin::TIMER,
        timer: Some(origin::TimerStatus {
            timer_id: 71,
            value_token: 0xdead,
            overrun: 4,
        }),
        ..origin::Origin::system()
    }
}

#[test]
fn timer_origin_has_exact_typed_versioned_detail_and_no_pid_or_pointer_payload() {
    let value = timer();
    let mut bytes = [0xa5; origin::MAX_LEN];
    origin::encode(value, &mut bytes).unwrap();
    assert_eq!(origin::encoded_len(value), 48);
    assert_eq!(origin::decode(&bytes).unwrap(), value);
    assert_eq!(&bytes[..4], &origin::TIMER.to_le_bytes());
    assert_eq!(&bytes[4..24], &[0; 20]);
    assert_eq!(&bytes[24..28], &1u32.to_le_bytes());
    assert_eq!(&bytes[28..32], &4u32.to_le_bytes());
    assert_eq!(&bytes[32..40], &71u64.to_le_bytes());
    assert_eq!(&bytes[40..], &0xdeadu64.to_le_bytes());
    for length in 0..origin::MAX_LEN {
        assert!(origin::decode(&bytes[..length]).is_err());
    }
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert!(origin::decode(&trailing).is_err());
    for (offset, value) in [(24, 2), (25, 1), (31, 255)] {
        let mut bad = bytes;
        bad[offset] = value;
        assert!(origin::decode(&bad).is_err());
    }
    let mut zero_id = bytes;
    zero_id[32..40].fill(0);
    assert!(origin::decode(&zero_id).is_err());
}

#[test]
fn ordinary_origins_remain_exact_common_records_and_cannot_smuggle_timer_detail() {
    let values = [
        origin::Origin::system(),
        origin::Origin {
            source: origin::USER,
            process_id: 91,
            real_uid: 501,
            ..origin::Origin::system()
        },
        origin::Origin {
            source: origin::FAULT,
            ..origin::Origin::system()
        },
        origin::Origin {
            source: origin::CHILD,
            process_id: 91,
            real_uid: 501,
            child: origin::ChildStatus {
                event: origin::EXITED,
                status: 37,
            },
            ..origin::Origin::system()
        },
    ];
    for value in values {
        let mut bytes = [0; origin::MAX_LEN];
        origin::encode(value, &mut bytes).unwrap();
        assert_eq!(origin::encoded_len(value), origin::LEN);
        assert_eq!(origin::decode(&bytes[..origin::LEN]), Ok(value));
        assert!(origin::decode(&bytes).is_err());
        let mut mixed = value;
        mixed.timer = timer().timer;
        assert!(origin::encode(mixed, &mut bytes).is_err());
    }
    for value in [
        origin::Origin {
            timer: None,
            ..timer()
        },
        origin::Origin {
            real_uid: 1,
            ..timer()
        },
        origin::Origin {
            process_id: 1,
            ..timer()
        },
        origin::Origin {
            child: origin::ChildStatus {
                event: 1,
                status: 0,
            },
            ..timer()
        },
        origin::Origin {
            timer: Some(origin::TimerStatus {
                timer_id: 71,
                value_token: 1,
                overrun: u32::MAX,
            }),
            ..timer()
        },
    ] {
        assert!(origin::encode(value, &mut [0; origin::MAX_LEN]).is_err());
    }
}

struct Reply;
impl Transport for Reply {
    type Error = ();
    fn call(&self, request: &[u8], response: &mut [u8]) -> Result<usize, ()> {
        let (header, payload) = protocol::decode(request).map_err(|_| ())?;
        let mut body = [0; signal_wait::MAX_LEN];
        let length = match header.opcode {
            protocol::OP_SIGNAL_DELIVERY_ORIGIN => {
                assert_eq!(protocol::decode_signal_delivery(payload).unwrap().token, 17);
                origin::encode(timer(), &mut body).unwrap();
                origin::encoded_len(timer())
            }
            protocol::OP_SIGNAL_THREAD_WAIT_INFO => {
                assert_eq!(
                    protocol::decode_signal_wait_request(payload).unwrap(),
                    (1 << 13, 7)
                );
                let value = signal_wait::Accepted {
                    signal: protocol::SIGNAL_ALRM,
                    origin: timer(),
                };
                signal_wait::encode(value, &mut body).unwrap();
                signal_wait::encoded_len(value)
            }
            _ => panic!("unexpected timer provenance request"),
        };
        protocol::encode(
            protocol::Header {
                opcode: protocol::OP_STATUS,
                request_id: header.request_id,
                payload_len: length as u32,
                ..Default::default()
            },
            &body[..length],
            response,
        )
        .map_err(|_| ())
    }
}

#[test]
fn delivery_and_synchronous_wait_clients_receive_complete_timer_provenance() {
    let client = Client::new(Reply);
    assert_eq!(
        client
            .signal_delivery_origin(protocol::SignalDelivery {
                signal: protocol::SIGNAL_ALRM,
                token: 17,
            })
            .unwrap(),
        timer()
    );
    let accepted = client.wait_thread_signal_info_since(1 << 13, 7).unwrap();
    assert_eq!(accepted.origin, timer());
    assert_eq!(accepted.signal, protocol::SIGNAL_ALRM);
    let mut body = [0; signal_wait::MAX_LEN];
    signal_wait::encode(accepted, &mut body).unwrap();
    assert_eq!(signal_wait::decode(&body), Ok(accepted));
    assert!(signal_wait::decode(&body[..signal_wait::LEN]).is_err());
    body[4] = 1;
    assert!(signal_wait::decode(&body).is_err());
}

#[test]
fn c_siginfo_requires_local_value_resolution_instead_of_turning_a_token_into_a_pointer() {
    let value = timer();
    assert!(matches!(
        SigInfo::from_origin(protocol::SIGNAL_ALRM, value),
        Err(InfoError::MissingDetail)
    ));
    let local = 0x12345678usize;
    let info = SigInfo::from_timer_origin(protocol::SIGNAL_ALRM, value, local).unwrap();
    assert_eq!(info.si_code, SI_TIMER);
    assert_eq!(unsafe { info.si_value.sival_ptr }, local);
    assert_ne!(
        unsafe { info.si_value.sival_ptr } as u64,
        value.timer.unwrap().value_token
    );
    assert_eq!(
        (info.si_pid, info.si_uid, info.si_status, info.si_addr),
        (0, 0, 0, 0)
    );
    assert!(matches!(
        SigInfo::from_timer_origin(0, value, local),
        Err(InfoError::InvalidSignal)
    ));
    assert!(matches!(
        SigInfo::from_timer_origin(14, origin::Origin::system(), local),
        Err(InfoError::MissingDetail)
    ));
}
