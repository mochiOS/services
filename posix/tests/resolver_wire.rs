use mochios_net_device_protocol::resolver as w;
const NAME: &[u8] = b"\x07example\x03com\0";
fn name(bytes: &[u8]) -> w::Name<'_> {
    w::Name::decode(bytes).unwrap()
}
fn success(kind: w::Kind, values: &[&[u8]]) -> Vec<u8> {
    let mut out = vec![0; 32768];
    let n = w::encode_result(
        kind,
        0,
        name(NAME),
        Some(name(NAME)),
        false,
        core::iter::empty(),
        values.iter().copied(),
        &mut out,
    )
    .unwrap();
    out.truncate(n);
    out
}

#[test]
fn names_are_bounded_binary_dns_names_and_case_comparison_is_label_preserving() {
    for n in [NAME, &b"\0"[..], &b"\x04a.\0\xff\0"[..]] {
        assert_eq!(name(n).bytes(), n);
    }
    assert!(name(NAME).matches(name(b"\x07EXAMPLE\x03COM\0")));
    assert!(!name(b"\x03a.b\0").matches(name(b"\x01a\x01b\0")));
    for n in [
        &b""[..],
        &b"\x01a"[..],
        &b"\0\0"[..],
        &b"\xc0\x0c"[..],
        &b"\x40a\0"[..],
    ] {
        assert!(w::Name::decode(n).is_err());
    }
    let mut long = vec![1, b'x'];
    long = long.repeat(128);
    long.push(0);
    assert!(w::Name::decode(&long).is_err());
}

#[test]
fn scoped_requests_require_known_nonzero_rights_and_deadline_attenuation() {
    let all = w::Limits {
        scopes: w::ALL_SCOPES,
        maximum_timeout: w::MAX_TIMEOUT,
    };
    let read = w::Limits {
        scopes: w::A_SCOPE,
        maximum_timeout: 100,
    };
    assert!(all.contains(read));
    assert!(!read.contains(all));
    for op in [w::ACQUIRE, w::DERIVE] {
        let bytes = w::scoped(op, read).unwrap();
        assert_eq!(&bytes[..8], &w::header(op));
        assert_eq!(w::decode_scoped(&bytes), Ok(read));
    }
    for limits in [
        w::Limits { scopes: 0, ..all },
        w::Limits { scopes: 8, ..all },
        w::Limits {
            maximum_timeout: 0,
            ..all
        },
        w::Limits {
            maximum_timeout: w::MAX_TIMEOUT + 1,
            ..all
        },
    ] {
        assert!(w::scoped(w::ACQUIRE, limits).is_err());
        assert!(!all.contains(limits));
    }
    let mut out = [0; w::LIMITS_LEN];
    read.encode(&mut out).unwrap();
    assert_eq!(w::Limits::decode(&out), Ok(read));
    for position in [0, 2, 8] {
        let mut bad = out;
        bad[position] ^= 0x80;
        assert!(w::Limits::decode(&bad).is_err());
    }
}

#[test]
fn query_requests_carry_only_kind_deadline_and_explicit_name_bytes() {
    for kind in [w::Kind::A, w::Kind::Aaaa, w::Kind::Ptr] {
        let query = w::Request {
            kind,
            timeout: 123,
            name: name(NAME),
        };
        let mut bytes = [0xaa; 512];
        let n = query.encode(&mut bytes).unwrap();
        assert_eq!(w::Request::decode(&bytes[..n]), Ok(query));
        assert_eq!(&bytes[..8], &w::header(w::OPEN));
        assert_eq!(&bytes[24..n], NAME);
        for prefix in 0..n {
            assert!(w::Request::decode(&bytes[..prefix]).is_err());
        }
        for position in [4, 10, 11, 18, 19, 20, 21, 22, 23] {
            let mut bad = bytes;
            bad[position] ^= 1;
            assert!(w::Request::decode(&bad[..n]).is_err());
        }
        bytes[n] = 0;
        assert!(w::Request::decode(&bytes[..n + 1]).is_err());
    }
    assert!(
        w::Request {
            kind: w::Kind::A,
            timeout: 0,
            name: name(NAME)
        }
        .encode(&mut [0; 512])
        .is_err()
    );
}

#[test]
fn replies_and_observations_cannot_smuggle_positive_errors_or_pending_results() {
    for status in [0, -2, -6, -125] {
        let mut bytes = [0; w::REPLY_LEN];
        w::reply(w::OPEN, status, &mut bytes).unwrap();
        assert_eq!(w::reply_status(w::OPEN, &bytes), Ok(status));
        assert!(w::reply_status(w::DERIVE, &bytes).is_err());
        bytes[15] = 1;
        assert!(w::reply_status(w::OPEN, &bytes).is_err());
    }
    for status in [1, i32::MAX, i32::MIN] {
        assert!(w::reply(w::OPEN, status, &mut [0; w::REPLY_LEN]).is_err());
    }
    let pending = w::Observation {
        ready: false,
        kind: w::Kind::Ptr,
        status: 0,
        length: 0,
    };
    let ready = w::Observation {
        ready: true,
        kind: w::Kind::Ptr,
        status: -6,
        length: 40 + NAME.len() as u64,
    };
    for v in [pending, ready] {
        let mut bytes = [0; w::OBSERVATION_LEN];
        v.encode(&mut bytes).unwrap();
        assert_eq!(w::Observation::decode(&bytes), Ok(v));
        for p in [0, 6, 7, 12, 13, 14, 15] {
            let mut bad = bytes;
            bad[p] ^= 0x40;
            assert!(w::Observation::decode(&bad).is_err());
        }
    }
    for v in [
        w::Observation {
            status: -5,
            ..pending
        },
        w::Observation {
            length: 41,
            ..pending
        },
        w::Observation {
            length: u64::MAX,
            ..ready
        },
        w::Observation {
            length: 40,
            ..ready
        },
    ] {
        assert!(v.encode(&mut [0; w::OBSERVATION_LEN]).is_err());
    }
}

#[test]
fn snapshots_cover_every_value_type_nodata_and_error_without_pointer_fields() {
    let four = [192, 0, 2, 1];
    let six = [1; 16];
    let binary = b"\x03a\0\xff\0";
    for (kind, values) in [
        (w::Kind::A, vec![four.as_slice(), &[192, 0, 2, 2]]),
        (w::Kind::Aaaa, vec![six.as_slice()]),
        (w::Kind::Ptr, vec![NAME, binary]),
    ] {
        let bytes = success(kind, &values);
        let r = w::decode_result(&bytes).unwrap();
        assert_eq!(r.kind, kind);
        assert_eq!(r.status, 0);
        assert_eq!(r.question.bytes(), NAME);
        assert_eq!(r.canonical.unwrap().bytes(), NAME);
        assert_eq!(r.values().collect::<Vec<_>>(), values);
        for n in 0..bytes.len() {
            assert!(w::decode_result(&bytes[..n]).is_err());
        }
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(w::decode_result(&extra).is_err());
    }
    let empty = success(w::Kind::A, &[]);
    assert_eq!(w::decode_result(&empty).unwrap().values().len(), 0);
    let mut error = [0; 512];
    let n = w::encode_failure(w::Kind::A, -6, name(NAME), &mut error).unwrap();
    let r = w::decode_result(&error[..n]).unwrap();
    assert_eq!(r.status, -6);
    assert!(r.canonical.is_none());
    assert_eq!(r.values().len(), 0);
    for size in 0..n {
        assert!(w::encode_failure(w::Kind::A, -6, name(NAME), &mut error[..size]).is_err());
    }
}

#[test]
fn snapshot_validation_rejects_bad_reserved_bits_lengths_types_and_alias_cycles() {
    let good = success(w::Kind::A, &[&[1; 4]]);
    for position in [
        8, 9, 16, 17, 18, 19, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
    ] {
        let mut bad = good.clone();
        bad[position] ^= 0x80;
        assert!(w::decode_result(&bad).is_err(), "byte {position}");
    }
    for (kind, value) in [
        (w::Kind::A, &b"123"[..]),
        (w::Kind::Aaaa, &b"123456789012345"[..]),
        (w::Kind::Ptr, &b"\xc0\x0c"[..]),
    ] {
        let mut out = [0; 512];
        assert!(
            w::encode_result(
                kind,
                0,
                name(NAME),
                Some(name(NAME)),
                false,
                core::iter::empty(),
                [value].into_iter(),
                &mut out
            )
            .is_err()
        );
    }
    let canonical: &[u8] = b"\x04host\x04test\0";
    let mut out = [0; 1024];
    let n = w::encode_result(
        w::Kind::A,
        0,
        name(NAME),
        Some(name(canonical)),
        true,
        [NAME].into_iter(),
        [&[1; 4][..]].into_iter(),
        &mut out,
    )
    .unwrap();
    let r = w::decode_result(&out[..n]).unwrap();
    assert_eq!(r.aliases().collect::<Vec<_>>(), [NAME]);
    assert!(r.cached);
    for aliases in [vec![], vec![canonical], vec![NAME, NAME]] {
        assert!(
            w::encode_result(
                w::Kind::A,
                0,
                name(NAME),
                Some(name(canonical)),
                false,
                aliases.into_iter(),
                core::iter::empty(),
                &mut out
            )
            .is_err()
        );
    }
    let too_many = vec![NAME; 17];
    assert!(
        w::encode_result(
            w::Kind::A,
            0,
            name(NAME),
            Some(name(canonical)),
            false,
            too_many.into_iter(),
            core::iter::empty(),
            &mut out
        )
        .is_err()
    );
}

#[test]
fn large_results_preserve_the_complete_set_and_respect_the_advertised_bound() {
    let mut out = vec![0; w::MAX_RESULT_LEN];
    let values = vec![&[1; 16][..]; 1024];
    let n = w::encode_result(
        w::Kind::Aaaa,
        0,
        name(NAME),
        Some(name(NAME)),
        false,
        core::iter::empty(),
        values.into_iter(),
        &mut out,
    )
    .unwrap();
    assert!(n > 4096);
    assert_eq!(w::decode_result(&out[..n]).unwrap().values().len(), 1024);
    let too_many = vec![&[1; 4][..]; w::MAX_RECORDS + 1];
    assert!(
        w::encode_result(
            w::Kind::A,
            0,
            name(NAME),
            Some(name(NAME)),
            false,
            core::iter::empty(),
            too_many.into_iter(),
            &mut out
        )
        .is_err()
    );
    assert!(w::decode_result(&vec![0; w::MAX_RESULT_LEN + 1]).is_err());
}
