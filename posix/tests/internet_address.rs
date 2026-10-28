//! Production no_std conversions against the host C library's independent
//! implementation, including malformed syntax and fixed-buffer boundaries.
use mochios_posix_client::internet::{self as inet, Address};
use std::{
    ffi::{CString, c_char, c_int, c_void},
    net::{Ipv4Addr, Ipv6Addr},
};
unsafe extern "C" {
    fn inet_pton(family: c_int, source: *const c_char, destination: *mut c_void) -> c_int;
    fn inet_ntop(
        family: c_int,
        source: *const c_void,
        destination: *mut c_char,
        capacity: u32,
    ) -> *const c_char;
}
fn reference_parse(family: i32, text: &str) -> Option<Vec<u8>> {
    let text = CString::new(text).unwrap();
    let mut bytes = [0xa5; 16];
    let n = inet::address_length(family).unwrap();
    let result = unsafe { inet_pton(family, text.as_ptr(), bytes.as_mut_ptr().cast()) };
    assert!(matches!(result, 0 | 1));
    (result == 1).then(|| bytes[..n].to_vec())
}
fn reference_format(family: i32, bytes: &[u8]) -> String {
    let mut text = [0u8; 46];
    let pointer = unsafe { inet_ntop(family, bytes.as_ptr().cast(), text.as_mut_ptr().cast(), 46) };
    assert_eq!(pointer, text.as_ptr().cast());
    let n = text.iter().position(|b| *b == 0).unwrap();
    String::from_utf8(text[..n].into()).unwrap()
}
fn compare(family: i32, text: &str) {
    let expected = reference_parse(family, text);
    let got = Address::parse(family, text.as_bytes()).unwrap();
    assert_eq!(
        got.as_ref().map(|a| a.octets().to_vec()),
        expected,
        "{text}"
    );
    if let Some(address) = got {
        let mut buffer = [0xa5; 46];
        let n = address.format(&mut buffer).unwrap();
        assert_eq!(
            &buffer[..n],
            reference_format(family, address.octets()).as_bytes(),
            "{text}"
        );
        assert_eq!(buffer[n], 0xa5);
        assert_eq!(Address::parse(family, &buffer[..n]), Ok(Some(address)));
    }
}
#[test]
fn ipv4_syntax_is_strict_decimal_and_matches_the_c_library() {
    for text in [
        "0.0.0.0",
        "127.0.0.1",
        "192.0.2.1",
        "255.255.255.255",
        "1.2.3.4",
        "",
        "127.1",
        "1",
        "0xffffffff",
        "0x7f.0.0.1",
        "01.2.3.4",
        "1.2.3.04",
        "1.2.3.256",
        "1.2.3.-1",
        "1.2.3.+1",
        "1.2.3.4.5",
        "1.2.3.",
        "1.2.3.4 ",
        " 1.2.3.4",
        "1.2.3.4/32",
        "1.2.3.4%1",
        "１.2.3.4",
    ] {
        compare(inet::AF_INET, text);
    }
}
#[test]
fn ipv6_compression_mapped_addresses_and_bad_forms_match_the_c_library() {
    for text in [
        "::",
        "::1",
        "::2",
        "::ffff",
        "::0.1.0.0",
        "::192.0.2.1",
        "::FFFF:192.0.2.1",
        "::ffff:0.0.0.0",
        "1:0:0:2:0:0:3:4",
        "2001:DB8::1234",
        "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255",
        "1:2:3:4:5::192.0.2.1",
        "",
        ":",
        ":::1",
        "1::2::3",
        "1:2:3:4:5:6:7",
        "1:2:3:4:5:6:7:8:9",
        "1:2:3:4:5:6:7:10000",
        "1:2:3:4:5:6:7:gggg",
        "2001:db8::1%2",
        "fe80::1%eth0",
        "2001:db8::1/64",
        " ::1",
        "::1 ",
        "192.0.2.1",
        "::ffff:192.000.2.1",
        "1:2:3:4:5:192.0.2.1",
    ] {
        compare(inet::AF_INET6, text);
    }
}
#[test]
fn all_zero_run_lengths_and_thousands_of_addresses_have_interoperable_presentation() {
    for run in 0..=8 {
        for start in 0..=8 - run {
            let mut segments = [1, 2, 3, 4, 5, 6, 7, 8];
            segments[start..start + run].fill(0);
            let address = Ipv6Addr::from(segments);
            compare(inet::AF_INET6, &address.to_string());
        }
    }
    let mut random = 0x12345678u32;
    for _ in 0..2048 {
        let mut bytes = [0; 16];
        for part in bytes.chunks_mut(4) {
            random = random.wrapping_mul(1664525).wrapping_add(1013904223);
            part.copy_from_slice(&random.to_be_bytes());
        }
        compare(inet::AF_INET6, &Ipv6Addr::from(bytes).to_string());
        let ipv4: [u8; 4] = bytes[..4].try_into().unwrap();
        compare(inet::AF_INET, &Ipv4Addr::from(ipv4).to_string());
    }
}
#[test]
fn family_lengths_binary_inputs_and_capacity_failures_are_explicit_and_bounded() {
    for family in [-1, 0, 1, 3, 255, i32::MAX] {
        assert_eq!(inet::address_length(family), Err(-97));
        assert_eq!(Address::parse(family, b"::1"), Err(-97));
        assert_eq!(Address::from_octets(family, &[0; 16]), Err(-97));
    }
    assert_eq!(Address::from_octets(2, &[0; 16]), Err(-22));
    assert_eq!(Address::from_octets(10, &[0; 4]), Err(-22));
    for text in [b"127.0.0.1\0".as_slice(), b"\xff\xff", b"::1\0extra"] {
        assert_eq!(Address::parse(2, text), Ok(None));
        assert_eq!(Address::parse(10, text), Ok(None));
    }
    let address = Address::V6([0xff; 16]);
    let expected = reference_format(10, address.octets());
    for size in 0..expected.len() {
        let mut bytes = [0xa5; 46];
        assert_eq!(address.format(&mut bytes[..size]), Err(-28));
        assert!(bytes[size..].iter().all(|b| *b == 0xa5));
    }
    let mut bytes = [0; 46];
    assert_eq!(
        address.format(&mut bytes[..expected.len()]),
        Ok(expected.len())
    );
}
