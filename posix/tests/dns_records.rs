//! Wire fixtures exercise the production decoder/cache; no DNS server or VM.
extern crate alloc;
#[path = "../../../user/crates/network-stack/src/dns.rs"]
#[allow(dead_code)]
mod production;
use production::*;

fn wire(text: &str) -> Vec<u8> {
    if text == "." {
        return vec![0];
    }
    let mut result = Vec::new();
    for label in text.split('.') {
        result.push(label.len() as u8);
        result.extend_from_slice(label.as_bytes());
    }
    result.push(0);
    result
}

fn domain(text: &str) -> DnsRecordName {
    DnsRecordName::from_wire(&wire(text)).unwrap()
}

struct Message {
    bytes: Vec<u8>,
}
impl Message {
    fn new(name: &str, kind: u16) -> Self {
        let mut bytes = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0];
        bytes.extend(wire(name));
        bytes.extend(kind.to_be_bytes());
        bytes.extend([0, 1]);
        Self { bytes }
    }
    fn record(
        &mut self,
        section: usize,
        owner: &[u8],
        kind: u16,
        class: u16,
        ttl: u32,
        data: &[u8],
    ) -> usize {
        let field = 6 + section * 2;
        let count = u16::from_be_bytes(self.bytes[field..field + 2].try_into().unwrap()) + 1;
        self.bytes[field..field + 2].copy_from_slice(&count.to_be_bytes());
        self.bytes.extend_from_slice(owner);
        self.bytes.extend(kind.to_be_bytes());
        self.bytes.extend(class.to_be_bytes());
        self.bytes.extend(ttl.to_be_bytes());
        self.bytes.extend((data.len() as u16).to_be_bytes());
        let start = self.bytes.len();
        self.bytes.extend_from_slice(data);
        start
    }
    fn answer(&mut self, owner: &str, kind: u16, ttl: u32, data: &[u8]) -> usize {
        self.record(0, &wire(owner), kind, 1, ttl, data)
    }
    fn decode(&self, name: &str, kind: DnsRecordType) -> Result<DnsRecordSet, DnsError> {
        decode_dns_records(&self.bytes, 0x1234, &domain(name), kind)
    }
}

#[test]
fn query_types_and_absolute_names_use_the_exact_dns_wire_format() {
    for (kind, number) in [
        (DnsRecordType::A, 1),
        (DnsRecordType::Aaaa, 28),
        (DnsRecordType::Ptr, 12),
    ] {
        let mut output = [0xee; 300];
        let name = DnsName::parse("Example.COM.").unwrap();
        let n = encode_dns_record_query(0x1234, &DnsRecordName::from(&name), kind, &mut output)
            .unwrap();
        let mut expected =
            b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00".to_vec();
        expected.extend((number as u16).to_be_bytes());
        expected.extend([0, 1]);
        assert_eq!(&output[..n], expected);
        assert!(output[n..].iter().all(|byte| *byte == 0xee));
        for size in 0..n {
            assert_eq!(
                encode_dns_record_query(1, &domain("example.com"), kind, &mut output[..size]),
                Err(DnsError::BufferTooSmall)
            );
        }
    }
    assert_eq!(DnsName::parse("a.."), Err(DnsError::EmptyLabel));
    assert_eq!(DnsName::parse("."), Err(DnsError::EmptyName));
}

#[test]
fn binary_dns_labels_and_root_do_not_inherit_hostname_restrictions() {
    let binary = b"\x04A.\x00\xff\x04_SVC\0";
    let name = DnsRecordName::from_wire(binary).unwrap();
    assert_eq!(name.wire(), b"\x04a.\x00\xff\x04_svc\0");
    assert_eq!(name.hostname(), Err(DnsError::InvalidCharacter));
    assert_eq!(domain(".").wire(), [0]);
    assert_eq!(domain(".").hostname(), Err(DnsError::EmptyName));
    let mut m = Message::new("example.com", 1);
    m.answer("example.com", 1, 60, &[192, 0, 2, 1]);
    m.record(2, binary, 16, 1, 60, &[1, 0xff]);
    m.record(2, &[0], 41, 1232, 0, &[]); // An EDNS OPT owner is the root.
    assert_eq!(
        m.decode("example.com", DnsRecordType::A).unwrap().values(),
        [DnsRecordValue::Ipv4([192, 0, 2, 1])]
    );
}

#[test]
fn dns_name_wire_limits_and_label_boundaries_are_checked() {
    let text = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    let name = domain(&text);
    assert_eq!(name.wire().len(), 255);
    assert_eq!(name.hostname().unwrap().as_str(), text);
    assert_eq!(
        DnsRecordName::from_wire(&wire(&(text + "x"))),
        Err(DnsError::NameTooLong)
    );
    assert_eq!(DnsRecordName::from_wire(&[]), Err(DnsError::Truncated));
    assert_eq!(
        DnsRecordName::from_wire(&[0, 0]),
        Err(DnsError::InvalidHeader)
    );
    assert_eq!(
        DnsRecordName::from_wire(&[64, 0]),
        Err(DnsError::LabelTooLong)
    );
    assert_eq!(
        DnsRecordName::from_wire(&[2, b'a', 0]),
        Err(DnsError::Truncated)
    );
    assert_eq!(
        domain("_svc.example").hostname(),
        Err(DnsError::InvalidCharacter)
    );
}

#[test]
fn all_addresses_are_retained_deduplicated_and_expire_as_one_rrset() {
    for (kind, number, first, second, values) in [
        (
            DnsRecordType::A,
            1,
            vec![192, 0, 2, 1],
            vec![192, 0, 2, 2],
            vec![
                DnsRecordValue::Ipv4([192, 0, 2, 1]),
                DnsRecordValue::Ipv4([192, 0, 2, 2]),
            ],
        ),
        (
            DnsRecordType::Aaaa,
            28,
            vec![1; 16],
            vec![2; 16],
            vec![DnsRecordValue::Ipv6([1; 16]), DnsRecordValue::Ipv6([2; 16])],
        ),
    ] {
        let mut m = Message::new("example.com", number);
        m.answer("EXAMPLE.COM", number, 300, &first);
        m.answer("example.com", number, 90, &second);
        m.answer("example.com", number, 30, &first);
        let records = m.decode("example.com", kind).unwrap();
        assert_eq!(records.values(), values);
        assert_eq!(records.ttl_seconds(), 30);
        let mut cache = DnsCache::new(8);
        cache.insert_records(&records, 17).unwrap();
        let cached = cache
            .lookup_records(&domain("EXAMPLE.COM"), kind, 1017)
            .unwrap();
        assert_eq!(cached.values(), values);
        assert_eq!(cached.ttl_seconds(), 29);
        assert!(
            cache
                .lookup_records(&domain("example.com"), kind, 30016)
                .is_some()
        );
        assert!(
            cache
                .lookup_records(&domain("example.com"), kind, 30017)
                .is_none()
        );
    }
}

#[test]
fn reordered_cname_chains_keep_all_terminal_addresses_and_shortest_ttl() {
    for order in [[0, 1, 2, 3], [3, 1, 0, 2], [2, 3, 1, 0]] {
        let mut m = Message::new("alias.test", 1);
        for index in order {
            match index {
                0 => {
                    m.answer("alias.test", 5, 40, &wire("middle.test"));
                }
                1 => {
                    m.answer("middle.test", 5, 20, &wire("host.test"));
                }
                2 => {
                    m.answer("host.test", 1, 300, &[192, 0, 2, 1]);
                }
                _ => {
                    m.answer("host.test", 1, 50, &[192, 0, 2, 2]);
                }
            }
        }
        let records = m.decode("alias.test", DnsRecordType::A).unwrap();
        assert_eq!(records.question(), &domain("alias.test"));
        assert_eq!(records.canonical_name(), &domain("host.test"));
        assert_eq!(records.values().len(), 2);
        assert!(
            records
                .values()
                .contains(&DnsRecordValue::Ipv4([192, 0, 2, 1]))
        );
        assert!(
            records
                .values()
                .contains(&DnsRecordValue::Ipv4([192, 0, 2, 2]))
        );
        assert_eq!(records.ttl_seconds(), 20);
        let answer =
            decode_dns_response(&m.bytes, 0x1234, &DnsName::parse("alias.test").unwrap()).unwrap();
        assert_eq!(answer.ttl_seconds, 20);
    }
}

#[test]
fn cname_targets_may_use_compression_inside_the_declared_rdata() {
    let mut m = Message::new("alias.example", 1);
    let cname = m.record(0, &[0xc0, 0x0c], 5, 1, 20, b"\x04host\xc0\x12");
    m.record(
        0,
        &[0xc0 | ((cname >> 8) as u8), cname as u8],
        1,
        1,
        60,
        &[192, 0, 2, 1],
    );
    let records = m.decode("alias.example", DnsRecordType::A).unwrap();
    assert_eq!(records.canonical_name(), &domain("host.example"));
    assert_eq!(records.values(), [DnsRecordValue::Ipv4([192, 0, 2, 1])]);
    assert_eq!(records.ttl_seconds(), 20);
}

#[test]
fn valid_deep_compression_and_expanded_name_limits_are_distinct() {
    let mut m = Message::new("example.com", 1);
    let mut previous = 12;
    for byte in 0..130 {
        let owner = m.bytes.len();
        m.record(
            0,
            &[0xc0 | ((previous >> 8) as u8), previous as u8],
            1,
            1,
            60,
            &[192, 0, 2, byte],
        );
        previous = owner;
    }
    assert_eq!(
        m.decode("example.com", DnsRecordType::A)
            .unwrap()
            .values()
            .len(),
        130
    );
    let text = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    let mut m = Message::new(&text, 1);
    m.record(0, &[1, b'x', 0xc0, 12], 1, 1, 60, &[192, 0, 2, 1]);
    assert_eq!(
        m.decode(&text, DnsRecordType::A),
        Err(DnsError::NameTooLong)
    );
}

#[test]
fn cname_cycles_conflicts_and_data_coexistence_are_rejected() {
    for target in ["a.test", "b.test"] {
        let mut m = Message::new("a.test", 1);
        m.answer("a.test", 5, 10, &wire(target));
        if target != "a.test" {
            m.answer("b.test", 5, 10, &wire("a.test"));
        }
        assert_eq!(
            m.decode("a.test", DnsRecordType::A),
            Err(DnsError::AliasLoop)
        );
    }
    let mut m = Message::new("a.test", 1);
    m.answer("a.test", 5, 60, &wire("b.test"));
    m.answer("a.test", 5, 20, &wire("c.test"));
    assert_eq!(
        m.decode("a.test", DnsRecordType::A),
        Err(DnsError::ConflictingAlias)
    );
    for kind in [1, 28, 2, 12, 16] {
        let mut m = Message::new("a.test", 1);
        m.answer("a.test", 5, 60, &wire("b.test"));
        let data = match kind {
            1 => vec![1; 4],
            28 => vec![1; 16],
            12 => wire("c.test"),
            _ => vec![0],
        };
        m.answer("a.test", kind, 60, &data);
        assert_eq!(
            m.decode("a.test", DnsRecordType::A),
            Err(DnsError::ConflictingAlias)
        );
    }
}

#[test]
fn duplicate_aliases_and_dnssec_companions_preserve_the_lower_ttl() {
    let mut m = Message::new("a.test", 28);
    m.answer("a.test", 5, 90, &wire("b.test"));
    m.answer("A.TEST", 5, 10, &wire("B.TEST"));
    m.answer("a.test", 46, 1, &[0]); // RRSIG: opaque, never claimed validated.
    m.answer("b.test", 28, 120, &[7; 16]);
    let records = m.decode("a.test", DnsRecordType::Aaaa).unwrap();
    assert_eq!(records.values(), [DnsRecordValue::Ipv6([7; 16])]);
    assert_eq!(records.ttl_seconds(), 10);
}

#[test]
fn alias_depth_is_bounded_without_accepting_a_prefix_as_success() {
    for depth in [DNS_MAX_ALIAS_DEPTH, DNS_MAX_ALIAS_DEPTH + 1] {
        let mut m = Message::new("a0.test", 1);
        for index in 0..depth {
            m.answer(
                &format!("a{index}.test"),
                5,
                10,
                &wire(&format!("a{}.test", index + 1)),
            );
        }
        m.answer(&format!("a{depth}.test"), 1, 10, &[192, 0, 2, 1]);
        let result = m.decode("a0.test", DnsRecordType::A);
        if depth == DNS_MAX_ALIAS_DEPTH {
            assert_eq!(result.unwrap().values().len(), 1);
        } else {
            assert_eq!(result, Err(DnsError::AliasDepth));
        }
    }
}

#[test]
fn additional_authority_wrong_owner_class_and_type_cannot_poison_answers() {
    let mut m = Message::new("example.com", 1);
    m.answer("foreign.test", 1, 10, &[1; 4]);
    m.record(0, &wire("example.com"), 1, 3, 10, &[2; 4]);
    m.answer("example.com", 28, 10, &[3; 16]);
    m.record(1, &wire("example.com"), 1, 1, 10, &[4; 4]);
    m.record(2, &wire("example.com"), 1, 1, 10, &[5; 4]);
    let records = m.decode("example.com", DnsRecordType::A).unwrap();
    assert!(records.values().is_empty());
    let mut cache = DnsCache::new(8);
    cache.insert_records(&records, 0).unwrap();
    assert!(cache.is_empty());
}

#[test]
fn cname_only_and_nodata_are_not_fabricated_answers_or_negative_cache_entries() {
    for alias in [false, true] {
        let mut m = Message::new("a.test", 1);
        if alias {
            m.answer("a.test", 5, 15, &wire("b.test"));
        }
        let records = m.decode("a.test", DnsRecordType::A).unwrap();
        assert!(records.values().is_empty());
        assert_eq!(
            records.canonical_name(),
            &domain(if alias { "b.test" } else { "a.test" })
        );
        let mut cache = DnsCache::new(0);
        cache.insert_records(&records, 0).unwrap();
        assert!(cache.is_empty());
    }
}

#[test]
fn reverse_names_and_ptr_rrsets_cover_ipv4_ipv6_and_binary_targets() {
    assert_eq!(
        DnsRecordName::reverse_ipv4([192, 0, 2, 255]),
        domain("255.2.0.192.in-addr.arpa")
    );
    let address = [
        0x43, 0x21, 0, 0, 0, 1, 0, 2, 0, 3, 0, 4, 0x05, 0x67, 0x89, 0xab,
    ];
    assert_eq!(
        DnsRecordName::reverse_ipv6(address),
        domain("b.a.9.8.7.6.5.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.0.0.0.0.1.2.3.4.ip6.arpa")
    );
    for name in ["1.2.0.192.in-addr.arpa", "b.a.ip6.arpa"] {
        let mut m = Message::new(name, 12);
        m.answer(name, 12, 120, &wire("first.test"));
        m.answer(name, 12, 60, &wire("second.test"));
        m.answer(name, 12, 30, b"\x03a\x00\xff\0");
        let records = m.decode(name, DnsRecordType::Ptr).unwrap();
        assert_eq!(
            records.values(),
            [
                DnsRecordValue::Name(domain("first.test")),
                DnsRecordValue::Name(domain("second.test")),
                DnsRecordValue::Name(DnsRecordName::from_wire(b"\x03a\x00\xff\0").unwrap())
            ]
        );
        assert_eq!(records.ttl_seconds(), 30);
    }
}

#[test]
fn large_stream_messages_retain_every_member_instead_of_the_udp_prefix() {
    let mut m = Message::new("example.com", 28);
    for byte in 0..128 {
        m.record(0, &[0xc0, 0x0c], 28, 1, 60, &[byte; 16]);
    }
    assert!(m.bytes.len() > DNS_MAX_MESSAGE_LEN);
    assert_eq!(
        m.decode("example.com", DnsRecordType::Aaaa)
            .unwrap()
            .values()
            .len(),
        128
    );
    assert_eq!(
        decode_dns_response(&m.bytes, 0x1234, &DnsName::parse("example.com").unwrap()),
        Err(DnsError::MessageTooLarge)
    );
    assert_eq!(
        decode_dns_records(&vec![0; 65536], 0, &domain("example.com"), DnsRecordType::A),
        Err(DnsError::MessageTooLarge)
    );
}

#[test]
fn tc_is_a_distinct_retry_and_never_allows_partial_rrset_caching() {
    let mut m = Message::new("example.com", 1);
    m.answer("example.com", 1, 60, &[192, 0, 2, 1]);
    m.bytes[2] |= 2;
    m.bytes[6..8].copy_from_slice(&2u16.to_be_bytes());
    m.bytes.extend([0xc0]); // Partial last RR is normal with TC.
    assert_eq!(
        m.decode("example.com", DnsRecordType::A),
        Err(DnsError::TruncatedResponse)
    );
    assert_eq!(
        m.decode("foreign.test", DnsRecordType::A),
        Err(DnsError::QuestionMismatch)
    );
    assert_eq!(
        decode_dns_records(&m.bytes, 7, &domain("example.com"), DnsRecordType::A),
        Err(DnsError::TransactionMismatch)
    );
}

#[test]
fn every_prefix_and_malformed_record_length_is_rejected() {
    let mut m = Message::new("example.com", 1);
    m.answer("example.com", 5, 10, &wire("host.test"));
    m.answer("host.test", 1, 10, &[192, 0, 2, 1]);
    for length in 0..m.bytes.len() {
        assert!(
            decode_dns_records(
                &m.bytes[..length],
                0x1234,
                &domain("example.com"),
                DnsRecordType::A
            )
            .is_err(),
            "prefix {length}"
        );
    }
    for (kind, length) in [(1, 3), (1, 5), (28, 15), (28, 17)] {
        let mut bad = Message::new("example.com", 1);
        bad.answer("example.com", kind, 10, &vec![0; length]);
        assert_eq!(
            bad.decode("example.com", DnsRecordType::A),
            Err(DnsError::InvalidRecordLength)
        );
    }
    for bytes in [vec![], vec![0xc0], vec![0xc0, 0x0c, 0], vec![3, b'a', b'b']] {
        let mut bad = Message::new("example.com", 1);
        bad.answer("example.com", 5, 10, &bytes);
        assert!(bad.decode("example.com", DnsRecordType::A).is_err());
    }
}

#[test]
fn bad_trailing_records_cannot_be_hidden_after_a_valid_answer() {
    for section in 0..3 {
        let mut m = Message::new("example.com", 1);
        m.answer("example.com", 1, 10, &[192, 0, 2, 1]);
        m.record(section, &wire("foreign.test"), 28, 1, 10, &[1; 15]);
        assert_eq!(
            m.decode("example.com", DnsRecordType::A),
            Err(DnsError::InvalidRecordLength)
        );
    }
    let mut m = Message::new("example.com", 1);
    m.answer("example.com", 1, 10, &[192, 0, 2, 1]);
    m.bytes.push(0);
    assert_eq!(
        m.decode("example.com", DnsRecordType::A),
        Err(DnsError::InvalidHeader)
    );
}

#[test]
fn forward_header_out_of_range_and_cyclic_pointers_are_rejected() {
    let mut m = Message::new("example.com", 1);
    let data = m.record(0, &[0xc0, 0x0c], 5, 1, 10, &[0xc0, 0x0c]);
    for (target, error) in [
        (0, DnsError::InvalidPointer),
        (65535, DnsError::PointerOutOfBounds),
        (data, DnsError::PointerLoop),
        (data + 1, DnsError::InvalidPointer),
    ] {
        m.bytes[data..data + 2].copy_from_slice(&[0xc0 | ((target >> 8) as u8), target as u8]);
        assert_eq!(m.decode("example.com", DnsRecordType::A), Err(error));
    }
    m.bytes[data..data + 2].copy_from_slice(&[0xc0, 0x0c]);
    // A backwards pointer into a label prefix that leads to itself is a loop.
    let name = m.bytes.len();
    m.record(
        0,
        &[1, b'x', 0xc0 | ((name >> 8) as u8), name as u8],
        1,
        1,
        10,
        &[1; 4],
    );
    assert_eq!(
        m.decode("example.com", DnsRecordType::A),
        Err(DnsError::PointerLoop)
    );
}

#[test]
fn reserved_header_bits_and_mismatched_question_type_class_are_rejected() {
    let m = Message::new("example.com", 1);
    for (offset, mask) in [(2, 0x80), (2, 0x08), (3, 0x40)] {
        let mut bad = m.bytes.clone();
        bad[offset] ^= mask;
        assert_eq!(
            decode_dns_records(&bad, 0x1234, &domain("example.com"), DnsRecordType::A),
            Err(DnsError::InvalidHeader)
        );
    }
    assert_eq!(
        m.decode("example.com", DnsRecordType::Aaaa),
        Err(DnsError::QuestionMismatch)
    );
    let mut bad = m.bytes.clone();
    *bad.last_mut().unwrap() = 3;
    assert_eq!(
        decode_dns_records(&bad, 0x1234, &domain("example.com"), DnsRecordType::A),
        Err(DnsError::QuestionMismatch)
    );
    for ad_cd in [0x10, 0x20, 0x30] {
        let mut good = m.bytes.clone();
        good[3] |= ad_cd;
        assert!(
            decode_dns_records(&good, 0x1234, &domain("example.com"), DnsRecordType::A).is_ok()
        );
    }
}

#[test]
fn cache_keys_include_record_type_and_replacement_never_merges_old_members() {
    let mut cache = DnsCache::new(3);
    let mut a = Message::new("example.com", 1);
    a.answer("example.com", 1, 60, &[1; 4]);
    a.answer("example.com", 1, 60, &[2; 4]);
    let mut aaaa = Message::new("example.com", 28);
    aaaa.answer("example.com", 28, 90, &[3; 16]);
    cache
        .insert_records(&a.decode("example.com", DnsRecordType::A).unwrap(), 0)
        .unwrap();
    cache
        .insert_records(&aaaa.decode("example.com", DnsRecordType::Aaaa).unwrap(), 0)
        .unwrap();
    let mut replacement = Message::new("example.com", 1);
    replacement.answer("example.com", 1, 10, &[4; 4]);
    cache
        .insert_records(
            &replacement.decode("example.com", DnsRecordType::A).unwrap(),
            1000,
        )
        .unwrap();
    assert_eq!(cache.len(), 2);
    assert_eq!(
        cache
            .lookup_records(&domain("example.com"), DnsRecordType::A, 1000)
            .unwrap()
            .values(),
        [DnsRecordValue::Ipv4([4; 4])]
    );
    assert_eq!(
        cache
            .lookup_records(&domain("example.com"), DnsRecordType::Aaaa, 11000)
            .unwrap()
            .values(),
        [DnsRecordValue::Ipv6([3; 16])]
    );
    assert!(
        cache
            .lookup_records(&domain("example.com"), DnsRecordType::A, 11000)
            .is_none()
    );
}

#[test]
fn zero_high_bit_and_alias_ttls_invalidate_only_the_matching_positive_entry() {
    for ttl in [0, 0x8000_0000, u32::MAX] {
        let mut cache = DnsCache::new(3);
        let name = DnsName::parse("alias.test").unwrap();
        cache.insert(&name, [1; 4], 100, 0).unwrap();
        let mut m = Message::new("alias.test", 1);
        m.answer("alias.test", 5, ttl, &wire("host.test"));
        m.answer("host.test", 1, 120, &[2; 4]);
        let records = m.decode("alias.test", DnsRecordType::A).unwrap();
        assert_eq!(records.values(), [DnsRecordValue::Ipv4([2; 4])]);
        assert_eq!(records.ttl_seconds(), 0);
        cache.insert_records(&records, 1).unwrap();
        assert!(cache.is_empty());
    }
    let mut m = Message::new("example.com", 1);
    m.answer("example.com", 1, 0x8000_0000, &[1; 4]);
    let records = m.decode("example.com", DnsRecordType::A).unwrap();
    assert_eq!(records.ttl_seconds(), 0);
}

#[test]
fn positive_cache_capacity_expiration_and_clock_overflow_are_bounded() {
    let name = DnsName::parse("example.com").unwrap();
    assert_eq!(
        DnsCache::new(0).insert(&name, [1; 4], 1, 0),
        Err(DnsError::CacheCapacity)
    );
    let mut cache = DnsCache::new(1);
    cache.insert(&name, [1; 4], 1, u64::MAX).unwrap();
    assert!(cache.is_empty());
    cache.insert(&name, [1; 4], 1, u64::MAX - 100).unwrap();
    assert_eq!(cache.lookup(&name, u64::MAX - 1), Some([1; 4]));
    assert_eq!(cache.lookup(&name, u64::MAX), None);
    cache.insert(&name, [1; 4], 1, 0).unwrap();
    let other = DnsName::parse("other.test").unwrap();
    cache.insert(&other, [2; 4], 10, 1000).unwrap();
    assert_eq!(cache.len(), 1);
    assert_eq!(cache.lookup(&name, 1000), None);
}

#[test]
fn deterministic_mutations_never_escape_name_type_or_message_bounds() {
    let mut m = Message::new("example.com", 28);
    m.answer("example.com", 5, 60, &wire("host.test"));
    m.answer("host.test", 28, 30, &[1; 16]);
    for position in 0..m.bytes.len() {
        for bit in 0..8 {
            let mut bytes = m.bytes.clone();
            bytes[position] ^= 1 << bit;
            if let Ok(records) =
                decode_dns_records(&bytes, 0x1234, &domain("example.com"), DnsRecordType::Aaaa)
            {
                assert_eq!(records.question(), &domain("example.com"));
                assert_eq!(records.record_type(), DnsRecordType::Aaaa);
                assert!(records.canonical_name().wire().len() <= 255);
                assert!(
                    records
                        .values()
                        .iter()
                        .all(|v| matches!(v, DnsRecordValue::Ipv6(_)))
                );
            }
        }
    }
}
