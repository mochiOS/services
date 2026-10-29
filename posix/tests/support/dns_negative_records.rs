//! Independent DNS bytes exercise the production decoder and shared cache.
use super::*;
fn soa(minimum: u32) -> Vec<u8> {
    let mut data = wire("ns.example");
    data.extend(wire("hostmaster.example"));
    for value in [0x12345678, 3600, 600, 86400, minimum] {
        data.extend(value.to_be_bytes());
    }
    data
}
fn response(
    name: &str,
    kind: DnsRecordType,
    rcode: u16,
    owner: &str,
    ttl: u32,
    minimum: u32,
) -> Message {
    let mut m = Message::new(name, kind as u16);
    m.bytes[2..4].copy_from_slice(&(0x8180 | rcode).to_be_bytes());
    m.record(1, &wire(owner), 6, 1, ttl, &soa(minimum));
    m
}
fn answer(m: &Message, name: &str, kind: DnsRecordType) -> DnsRecordSet {
    decode_dns_answer(&m.bytes, 0x1234, &domain(name), kind).unwrap()
}
fn positive(name: &str, kind: DnsRecordType) -> DnsRecordSet {
    let mut m = Message::new(name, kind as u16);
    m.answer(
        name,
        kind as u16,
        100,
        &match kind {
            DnsRecordType::A => vec![1; 4],
            DnsRecordType::Aaaa => vec![1; 16],
            DnsRecordType::Ptr => wire("target.example"),
        },
    );
    m.decode(name, kind).unwrap()
}

#[test]
fn soa_fields_compressed_names_and_negative_ttl_are_retained() {
    let mut data = b"\x02ns\xc0\x14\x0ahostmaster\xc0\x14".to_vec();
    for value in [1u32, 2, 3, 4, 30] {
        data.extend(value.to_be_bytes());
    }
    let mut m = Message::new("missing.example", 1);
    m.bytes[3] = 0x83;
    m.record(1, &wire("example"), 6, 1, 90, &data);
    let a = answer(&m, "missing.example", DnsRecordType::A);
    let n = a.negative().unwrap();
    assert_eq!(n.kind, DnsNegativeKind::NameError);
    assert_eq!(a.ttl_seconds(), 30);
    let s = n.soa.as_ref().unwrap();
    assert_eq!(s.owner, domain("example"));
    assert_eq!(s.primary, domain("ns.example"));
    assert_eq!(s.mailbox, domain("hostmaster.example"));
    assert_eq!(
        (
            s.serial,
            s.refresh,
            s.retry,
            s.expire,
            s.minimum,
            s.ttl_seconds()
        ),
        (1, 2, 3, 4, 30, 30)
    );
    assert_eq!(
        m.decode("missing.example", DnsRecordType::A),
        Err(DnsError::Response(DnsResponseCode::NameError))
    );
}
#[test]
fn nxdomain_is_name_wide_but_nodata_is_type_specific() {
    for (rcode, negative) in [
        (3, DnsNegativeKind::NameError),
        (0, DnsNegativeKind::NoData),
    ] {
        let m = response("absent.example", DnsRecordType::A, rcode, "example", 90, 30);
        let a = answer(&m, "absent.example", DnsRecordType::A);
        let mut c = DnsCache::new(8);
        c.insert_records(&a, 100).unwrap();
        let hit = c
            .lookup_records(&domain("ABSENT.EXAMPLE"), DnsRecordType::A, 1100)
            .unwrap();
        assert_eq!(hit.negative().unwrap().kind, negative);
        assert_eq!(hit.ttl_seconds(), 29);
        assert_eq!(
            hit.negative().unwrap().soa.as_ref().unwrap().ttl_seconds(),
            29
        );
        for kind in [DnsRecordType::Aaaa, DnsRecordType::Ptr] {
            let other = c.lookup_records(&domain("absent.example"), kind, 1100);
            if rcode == 3 {
                assert_eq!(other.unwrap().record_type(), kind);
            } else {
                assert!(other.is_none());
            }
        }
        assert!(
            c.lookup_records(&domain("child.absent.example"), DnsRecordType::A, 1100)
                .is_none()
        );
        assert!(
            c.lookup_records(&domain("absent.example"), DnsRecordType::A, 30100)
                .is_none()
        );
    }
}
#[test]
fn only_authority_in_class_soa_for_a_label_ancestor_supplies_lifetime() {
    for (section, class, owner) in [
        (0, 1, "example"),
        (2, 1, "example"),
        (1, 3, "example"),
        (1, 1, "other.example"),
        (1, 1, "ample"),
    ] {
        let mut m = Message::new("absent.example", 1);
        m.bytes[3] = 0x83;
        m.record(section, &wire(owner), 6, class, 100, &soa(50));
        let a = answer(&m, "absent.example", DnsRecordType::A);
        assert!(a.negative().unwrap().soa.is_none());
        assert_eq!(a.ttl_seconds(), 0);
        let mut c = DnsCache::new(8);
        c.insert_records(&a, 0).unwrap();
        assert!(c.is_empty());
    }
    let m = response(
        "host.badexample.test",
        DnsRecordType::A,
        3,
        "example.test",
        100,
        20,
    );
    assert!(
        answer(&m, "host.badexample.test", DnsRecordType::A)
            .negative()
            .unwrap()
            .soa
            .is_none()
    );
    let mut m = response("host.sub.example", DnsRecordType::A, 0, ".", 100, 1);
    m.record(1, &wire("example"), 6, 1, 100, &soa(2));
    m.record(1, &wire("sub.example"), 6, 1, 100, &soa(30));
    let a = answer(&m, "host.sub.example", DnsRecordType::A);
    assert_eq!(a.ttl_seconds(), 30);
    assert_eq!(
        a.negative().unwrap().soa.as_ref().unwrap().owner,
        domain("sub.example")
    );
}
#[test]
fn type_one_nodata_with_ns_is_distinct_from_an_uncacheable_referral() {
    let mut m = response("absent.example", DnsRecordType::Aaaa, 0, "example", 100, 30);
    m.record(1, &wire("example"), 2, 1, 10, &wire("ns.example"));
    let a = answer(&m, "absent.example", DnsRecordType::Aaaa);
    assert_eq!(a.negative().unwrap().kind, DnsNegativeKind::NoData);
    assert_eq!(a.ttl_seconds(), 30);
    let mut m = Message::new("absent.example", 28);
    m.record(1, &wire("example"), 2, 1, 10, &wire("ns.example"));
    let a = answer(&m, "absent.example", DnsRecordType::Aaaa);
    let mut c = DnsCache::new(8);
    c.insert_records(&a, 0).unwrap();
    assert!(c.is_empty());
}
#[test]
fn malformed_soa_rdata_and_conflicting_soa_rrsets_are_rejected() {
    let data = soa(30);
    for size in 0..data.len() {
        let mut m = Message::new("absent.example", 1);
        m.record(1, &wire("example"), 6, 1, 60, &data[..size]);
        assert!(
            decode_dns_answer(
                &m.bytes,
                0x1234,
                &domain("absent.example"),
                DnsRecordType::A
            )
            .is_err(),
            "SOA cut {size}"
        );
    }
    let mut long = data.clone();
    long.push(0);
    let mut m = Message::new("absent.example", 1);
    m.record(1, &wire("example"), 6, 1, 60, &long);
    assert_eq!(
        m.decode("absent.example", DnsRecordType::A),
        Err(DnsError::InvalidRecordLength)
    );
    let mut m = response("absent.example", DnsRecordType::A, 3, "example", 60, 30);
    m.record(1, &wire("example"), 6, 1, 10, &data);
    assert_eq!(
        answer(&m, "absent.example", DnsRecordType::A).ttl_seconds(),
        10
    );
    let mut conflict = data;
    conflict[wire("ns.example").len() + wire("hostmaster.example").len()] ^= 1;
    m.record(1, &wire("example"), 6, 1, 10, &conflict);
    assert!(
        decode_dns_answer(
            &m.bytes,
            0x1234,
            &domain("absent.example"),
            DnsRecordType::A
        )
        .is_err()
    );
    let mut m = Message::new("absent.example", 1);
    let mut bad = b"\xc0\x01\0".to_vec();
    bad.extend([0; 20]);
    m.record(1, &wire("example"), 6, 1, 60, &bad);
    assert_eq!(
        m.decode("absent.example", DnsRecordType::A),
        Err(DnsError::InvalidPointer)
    );
}
#[test]
fn soa_ttl_minimum_zero_high_bit_and_expiration_do_not_refresh() {
    for (ttl, minimum, expected) in [
        (50, 30, 30),
        (20, 30, 20),
        (0, 30, 0),
        (30, 0, 0),
        (0x80000001, 30, 0),
        (30, 0x80000001, 0),
    ] {
        let m = response(
            "absent.example",
            DnsRecordType::A,
            3,
            "example",
            ttl,
            minimum,
        );
        let a = answer(&m, "absent.example", DnsRecordType::A);
        assert_eq!(a.ttl_seconds(), expected);
        let mut c = DnsCache::new(2);
        c.insert_records(&a, 17).unwrap();
        if expected == 0 {
            assert!(c.is_empty());
            continue;
        }
        let at = 17 + u64::from(expected) * 1000;
        assert_eq!(
            c.lookup_records(&domain("absent.example"), DnsRecordType::A, at - 1)
                .unwrap()
                .ttl_seconds(),
            0
        );
        assert!(
            c.lookup_records(&domain("absent.example"), DnsRecordType::A, at)
                .is_none()
        );
    }
}
#[test]
fn aliases_cache_only_their_own_type_and_never_shorten_terminal_soa_lifetime() {
    for rcode in [0, 3] {
        let mut m = Message::new("alias.test", 1);
        m.bytes[3] = 0x80 | rcode;
        m.answer("alias.test", 5, 3, &wire("absent.example"));
        m.record(1, &wire("example"), 6, 1, 90, &soa(7));
        let a = answer(&m, "alias.test", DnsRecordType::A);
        assert_eq!(a.ttl_seconds(), 3);
        assert_eq!(a.canonical_name(), &domain("absent.example"));
        let mut c = DnsCache::new(8);
        c.insert_records(&a, 0).unwrap();
        assert_eq!(c.len(), 2);
        let cached = c
            .lookup_records(&domain("alias.test"), DnsRecordType::A, 1000)
            .unwrap();
        assert_eq!(cached.ttl_seconds(), 2);
        assert_eq!(
            cached
                .negative()
                .unwrap()
                .soa
                .as_ref()
                .unwrap()
                .ttl_seconds(),
            6
        );
        assert!(
            c.lookup_records(&domain("alias.test"), DnsRecordType::Aaaa, 1000)
                .is_none()
        );
        assert!(
            c.lookup_records(&domain("alias.test"), DnsRecordType::A, 3000)
                .is_none()
        );
        assert!(
            c.lookup_records(&domain("absent.example"), DnsRecordType::A, 6999)
                .is_some()
        );
        assert_eq!(
            c.lookup_records(&domain("absent.example"), DnsRecordType::Aaaa, 6999)
                .is_some(),
            rcode == 3
        );
        assert!(
            c.lookup_records(&domain("absent.example"), DnsRecordType::A, 7000)
                .is_none()
        );
        let mut c = DnsCache::new(1);
        c.insert_records(&a, 0).unwrap();
        assert_eq!(c.len(), 1);
        assert!(
            c.lookup_records(&domain("absent.example"), DnsRecordType::A, 0)
                .is_some()
        );
    }
}
#[test]
fn cross_message_alias_aging_keeps_terminal_negative_proof_separate() {
    let mut m = Message::new("alias.test", 1);
    m.answer("alias.test", 5, 3, &wire("absent.example"));
    let prefix = m.decode("alias.test", DnsRecordType::A).unwrap();
    let m = response("absent.example", DnsRecordType::A, 3, "example", 90, 7);
    let terminal = answer(&m, "absent.example", DnsRecordType::A);
    let a = prefix.follow_answer(terminal, 2000).unwrap();
    assert_eq!(a.ttl_seconds(), 1);
    let mut c = DnsCache::new(8);
    c.insert_records(&a, 2000).unwrap();
    assert!(
        c.lookup_records(&domain("alias.test"), DnsRecordType::A, 3000)
            .is_none()
    );
    assert!(
        c.lookup_records(&domain("absent.example"), DnsRecordType::A, 8999)
            .is_some()
    );
}
#[test]
fn contradictory_positive_and_negative_cache_entries_replace_by_proven_scope() {
    let mut c = DnsCache::new(8);
    for kind in [DnsRecordType::A, DnsRecordType::Aaaa] {
        c.insert_records(&positive("absent.example", kind), 0)
            .unwrap();
    }
    let m = response("absent.example", DnsRecordType::A, 0, "example", 100, 30);
    c.insert_records(&answer(&m, "absent.example", DnsRecordType::A), 1)
        .unwrap();
    assert!(
        c.lookup_records(&domain("absent.example"), DnsRecordType::A, 1)
            .unwrap()
            .negative()
            .is_some()
    );
    assert!(
        c.lookup_records(&domain("absent.example"), DnsRecordType::Aaaa, 1)
            .unwrap()
            .negative()
            .is_none()
    );
    let m = response("absent.example", DnsRecordType::A, 3, "example", 100, 30);
    c.insert_records(&answer(&m, "absent.example", DnsRecordType::A), 2)
        .unwrap();
    assert_eq!(c.len(), 1);
    c.insert_records(&positive("absent.example", DnsRecordType::Aaaa), 3)
        .unwrap();
    assert_eq!(c.len(), 1);
    assert!(
        c.lookup_records(&domain("absent.example"), DnsRecordType::A, 3)
            .is_none()
    );
    assert!(
        c.lookup_records(&domain("absent.example"), DnsRecordType::Aaaa, 3)
            .unwrap()
            .negative()
            .is_none()
    );
}
#[test]
fn terminal_denial_invalidates_cached_alias_data_and_positive_alias_clears_old_denial() {
    let mut m = Message::new("alias.test", 28);
    m.answer("alias.test", 5, 100, &wire("absent.example"));
    m.answer("absent.example", 28, 100, &[1; 16]);
    let positive = m.decode("alias.test", DnsRecordType::Aaaa).unwrap();
    let mut c = DnsCache::new(8);
    c.insert_records(&positive, 0).unwrap();
    let m = response("absent.example", DnsRecordType::A, 3, "example", 100, 30);
    c.insert_records(&answer(&m, "absent.example", DnsRecordType::A), 1)
        .unwrap();
    assert!(
        c.lookup_records(&domain("alias.test"), DnsRecordType::Aaaa, 1)
            .is_none()
    );
    c.insert_records(&positive, 2).unwrap();
    assert!(
        c.lookup_records(&domain("absent.example"), DnsRecordType::A, 2)
            .is_none()
    );
}
#[test]
fn errors_truncation_and_nxdomain_with_terminal_data_cannot_be_cached() {
    for code in [1, 2, 4, 5] {
        let m = response("absent.example", DnsRecordType::A, code, "example", 100, 30);
        assert!(
            decode_dns_answer(
                &m.bytes,
                0x1234,
                &domain("absent.example"),
                DnsRecordType::A
            )
            .is_err()
        );
    }
    let mut m = response("absent.example", DnsRecordType::A, 3, "example", 100, 30);
    m.bytes[2] |= 2;
    assert_eq!(
        decode_dns_answer(
            &m.bytes,
            0x1234,
            &domain("absent.example"),
            DnsRecordType::A
        ),
        Err(DnsError::TruncatedResponse)
    );
    let mut m = Message::new("absent.example", 1);
    m.bytes[3] = 0x83;
    m.answer("absent.example", 1, 100, &[1; 4]);
    m.record(1, &wire("example"), 6, 1, 100, &soa(30));
    assert_eq!(
        decode_dns_answer(
            &m.bytes,
            0x1234,
            &domain("absent.example"),
            DnsRecordType::A
        ),
        Err(DnsError::InvalidHeader)
    );
    m.bytes[3] = 0x80;
    assert!(
        answer(&m, "absent.example", DnsRecordType::A)
            .negative()
            .is_none()
    );
}
#[test]
fn zero_ttl_alias_still_caches_terminal_denial_and_total_capacity_remains_bounded() {
    let mut m = Message::new("alias.test", 1);
    m.bytes[3] = 0x83;
    m.answer("alias.test", 5, 0, &wire("absent.example"));
    m.record(1, &wire("example"), 6, 1, 100, &soa(30));
    let a = answer(&m, "alias.test", DnsRecordType::A);
    let mut c = DnsCache::new(2);
    c.insert_records(&a, 0).unwrap();
    assert!(
        c.lookup_records(&domain("alias.test"), DnsRecordType::A, 0)
            .is_none()
    );
    assert!(
        c.lookup_records(&domain("absent.example"), DnsRecordType::Aaaa, 0)
            .is_some()
    );
    let mut c = DnsCache::new(0);
    assert_eq!(c.insert_records(&a, 0), Err(DnsError::CacheCapacity));
    let mut c = DnsCache::new(2);
    for i in 0..3 {
        let name = format!("h{i}.example");
        let m = response(&name, DnsRecordType::A, 3, "example", 100, 30);
        c.insert_records(&answer(&m, &name, DnsRecordType::A), 0)
            .unwrap();
    }
    assert_eq!(c.len(), 2);
    assert!(
        c.lookup_records(&domain("h0.example"), DnsRecordType::A, 0)
            .is_none()
    );
    c.clear();
    assert!(c.is_empty());
}

#[test]
fn extended_errors_and_malformed_opt_cannot_be_treated_as_no_data() {
    for (upper, low) in [(1u32, 0u16), (1, 3), (255, 3)] {
        let mut m = response("absent.example", DnsRecordType::A, low, "example", 90, 30);
        m.record(2, &[0], 41, 1232, upper << 24, &[]);
        assert_eq!(
            decode_dns_answer(
                &m.bytes,
                0x1234,
                &domain("absent.example"),
                DnsRecordType::A
            ),
            Err(DnsError::UnsupportedExtendedResponseCode(
                ((upper as u16) << 4) | low
            ))
        );
    }
    for (section, owner, data) in [
        (1, vec![0], vec![]),
        (2, wire("example"), vec![]),
        (2, vec![0], vec![0, 1, 0, 3, 1, 2]),
        (2, vec![0], vec![1]),
    ] {
        let mut m = response("absent.example", DnsRecordType::A, 0, "example", 90, 30);
        m.record(section, &owner, 41, 1232, 0, &data);
        assert!(
            decode_dns_answer(
                &m.bytes,
                0x1234,
                &domain("absent.example"),
                DnsRecordType::A
            )
            .is_err()
        );
    }
    let mut m = response("absent.example", DnsRecordType::A, 0, "example", 90, 30);
    m.record(2, &[0], 41, 1232, 0, &[0, 255, 0, 1, 7]);
    assert_eq!(
        answer(&m, "absent.example", DnsRecordType::A).ttl_seconds(),
        30
    );
    m.record(2, &[0], 41, 1232, 0, &[]);
    assert_eq!(
        m.decode("absent.example", DnsRecordType::A),
        Err(DnsError::InvalidHeader)
    );
}
