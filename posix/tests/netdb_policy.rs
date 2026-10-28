use mochios_posix_client::{
    internet::{AF_INET, AF_INET6, Address},
    netdb::{self as n, *},
};
use std::collections::BTreeMap;

struct Fixture {
    calls: Vec<String>,
    config: Configuration,
    hosts: BTreeMap<i32, Result<Vec<ScopedAddress>, Error>>,
    canonical: Vec<u8>,
    reverse: Option<(Vec<u8>, bool)>,
    reverse_error: Option<Error>,
    after_host: Option<Error>,
}
impl Default for Fixture {
    fn default() -> Self {
        Self {
            calls: Vec::new(),
            config: Configuration {
                ipv4: true,
                ipv6: true,
            },
            hosts: BTreeMap::new(),
            canonical: b"canonical.example".to_vec(),
            reverse: None,
            reverse_error: None,
            after_host: None,
        }
    }
}
impl Backend for Fixture {
    fn configuration(&mut self) -> Result<Configuration, Error> {
        self.calls.push("config".into());
        Ok(self.config)
    }
    fn scope(&mut self, name: &[u8]) -> Result<Option<u32>, Error> {
        self.calls
            .push(format!("scope:{}", String::from_utf8_lossy(name)));
        Ok((name == b"eth0").then_some(7))
    }
    fn host(
        &mut self,
        name: &[u8],
        family: i32,
        emit: &mut dyn FnMut(Host<'_>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.calls
            .push(format!("host:{family}:{}", String::from_utf8_lossy(name)));
        for address in self
            .hosts
            .get(&family)
            .cloned()
            .unwrap_or(Err(Error::NoName))?
        {
            emit(Host {
                address,
                canonical: Some(&self.canonical),
            })?;
        }
        self.after_host.map_or(Ok(()), Err)
    }
    fn service(&mut self, name: &[u8], transport: Transport) -> Result<Option<u16>, Error> {
        self.calls.push(format!(
            "service:{transport:?}:{}",
            String::from_utf8_lossy(name)
        ));
        Ok(match (name, transport) {
            (b"http", Transport::Tcp) => Some(80),
            (b"domain", _) => Some(53),
            _ => None,
        })
    }
    fn reverse(
        &mut self,
        address: ScopedAddress,
        out: &mut [u8],
    ) -> Result<Option<Reverse>, Error> {
        self.calls.push(format!("reverse:{address:?}"));
        if let Some(error) = self.reverse_error {
            return Err(error);
        }
        let Some((name, local)) = &self.reverse else {
            return Ok(None);
        };
        let target = out.get_mut(..name.len()).ok_or(Error::Overflow)?;
        target.copy_from_slice(name);
        Ok(Some(Reverse {
            length: name.len(),
            local: *local,
        }))
    }
    fn service_name(
        &mut self,
        port: u16,
        transport: Transport,
        out: &mut [u8],
    ) -> Result<Option<usize>, Error> {
        self.calls
            .push(format!("service_name:{port}:{transport:?}"));
        let name: &[u8] = match (port, transport) {
            (80, Transport::Tcp) => b"http",
            (53, _) => b"domain",
            (512, Transport::Tcp) => b"exec",
            (512, Transport::Udp) => b"biff",
            _ => return Ok(None),
        };
        out.get_mut(..name.len())
            .ok_or(Error::Overflow)?
            .copy_from_slice(name);
        Ok(Some(name.len()))
    }
}
#[derive(Debug, PartialEq, Eq)]
struct Owned {
    address: ScopedAddress,
    port: u16,
    transport: Transport,
    canonical: Option<Vec<u8>>,
}
fn resolve(
    f: &mut Fixture,
    node: Option<&[u8]>,
    service: Option<&[u8]>,
    hints: Hints,
) -> Result<Vec<Owned>, Error> {
    let mut out = Vec::new();
    let count = n::getaddrinfo(f, node, service, hints, &mut |e| {
        out.push(Owned {
            address: e.address,
            port: e.port,
            transport: e.transport,
            canonical: e.canonical.map(Vec::from),
        });
        Ok(())
    })?;
    assert_eq!(count, out.len());
    assert!(count > 0);
    Ok(out)
}
fn v4() -> ScopedAddress {
    Address::V4([192, 0, 2, 1]).into()
}
fn v6() -> ScopedAddress {
    let mut a = [0; 16];
    a[..4].copy_from_slice(&[0x20, 1, 0xd, 0xb8]);
    a[15] = 1;
    Address::V6(a).into()
}
#[test]
fn numeric_hosts_ports_transport_inference_and_canonical_require_no_backend() {
    for (node, address) in [
        (b"192.0.2.1".as_slice(), v4()),
        (b"2001:db8::1".as_slice(), v6()),
    ] {
        for (kind, protocol, nout) in [
            (0, 0, 2),
            (1, 0, 1),
            (0, 6, 1),
            (2, 0, 1),
            (0, 17, 1),
            (1, 6, 1),
            (2, 17, 1),
        ] {
            let mut f = Fixture::default();
            let out = resolve(
                &mut f,
                Some(node),
                Some(b"65535"),
                Hints {
                    flags: AI_NUMERICHOST | AI_NUMERICSERV | AI_CANONNAME,
                    socktype: kind,
                    protocol,
                    ..Hints::default()
                },
            )
            .unwrap();
            assert_eq!(out.len(), nout);
            assert_eq!(out[0].canonical.as_deref(), Some(node));
            assert!(out[1..].iter().all(|e| e.canonical.is_none()));
            assert!(out.iter().all(|e| e.address == address && e.port == 65535));
            assert!(f.calls.is_empty(), "{:?}", f.calls);
        }
    }
}
#[test]
fn null_node_loopback_wildcard_and_zero_ports_obey_family_and_passive() {
    for flags in [0, AI_PASSIVE, AI_PASSIVE | AI_CANONNAME] {
        for family in [AF_UNSPEC, AF_INET, AF_INET6] {
            let mut f = Fixture::default();
            let out = resolve(
                &mut f,
                None,
                Some(b"0"),
                Hints {
                    flags,
                    family,
                    socktype: 1,
                    ..Hints::default()
                },
            )
            .unwrap();
            assert_eq!(out.len(), if family == AF_UNSPEC { 2 } else { 1 });
            for item in out {
                assert!(item.canonical.is_none());
                assert_eq!(item.port, 0);
                match item.address.address {
                    Address::V4(ip) => assert_eq!(
                        ip,
                        if flags & AI_PASSIVE != 0 {
                            [0; 4]
                        } else {
                            [127, 0, 0, 1]
                        }
                    ),
                    Address::V6(ip) => {
                        assert_eq!(ip[..15], [0; 15]);
                        assert_eq!(ip[15], u8::from(flags & AI_PASSIVE == 0));
                    }
                }
            }
            assert!(f.calls.is_empty());
        }
    }
    assert_eq!(
        resolve(&mut Fixture::default(), None, None, Hints::default()),
        Err(Error::NoName)
    );
}
#[test]
fn invalid_hints_empty_inputs_ports_and_numeric_flags_fail_before_host_lookup() {
    for (h, error) in [
        (
            Hints {
                flags: 1 << 30,
                ..Hints::default()
            },
            Error::BadFlags,
        ),
        (
            Hints {
                family: 1,
                ..Hints::default()
            },
            Error::Family,
        ),
        (
            Hints {
                socktype: 5,
                ..Hints::default()
            },
            Error::SockType,
        ),
        (
            Hints {
                socktype: 1,
                protocol: 17,
                ..Hints::default()
            },
            Error::Service,
        ),
        (
            Hints {
                protocol: 255,
                ..Hints::default()
            },
            Error::Service,
        ),
    ] {
        let mut f = Fixture::default();
        assert_eq!(resolve(&mut f, Some(b"name"), Some(b"80"), h), Err(error));
        assert!(f.calls.is_empty());
    }
    for service in [b"65536".as_slice(), b"999999999999999999999", b"", b"80\0"] {
        let mut f = Fixture::default();
        assert_eq!(
            resolve(&mut f, Some(b"name"), Some(service), Hints::default()),
            Err(Error::Service)
        );
        assert!(f.calls.is_empty());
    }
    let mut f = Fixture::default();
    assert_eq!(
        resolve(
            &mut f,
            Some(b"name"),
            Some(b"http"),
            Hints {
                flags: AI_NUMERICSERV,
                ..Hints::default()
            }
        ),
        Err(Error::NoName)
    );
    assert!(f.calls.is_empty());
    assert_eq!(
        resolve(
            &mut f,
            Some(b"name"),
            Some(b"80"),
            Hints {
                flags: AI_NUMERICHOST,
                ..Hints::default()
            }
        ),
        Err(Error::NoName)
    );
    assert!(f.calls.is_empty());
    for name in [b"".as_slice(), b"foo\0bar"] {
        assert_eq!(
            resolve(&mut f, Some(name), None, Hints::default()),
            Err(Error::NoName)
        );
    }
}
#[test]
fn all_dns_records_are_emitted_without_a_fixed_first_address_limit() {
    let mut f = Fixture::default();
    let addresses = (0..3000u32)
        .map(|n| Address::V4(n.to_be_bytes()).into())
        .collect::<Vec<_>>();
    f.hosts.insert(AF_INET, Ok(addresses.clone()));
    f.hosts.insert(AF_INET6, Ok(vec![v6()]));
    let out = resolve(
        &mut f,
        Some(b"alias.example"),
        Some(b"domain"),
        Hints {
            flags: AI_CANONNAME,
            ..Hints::default()
        },
    )
    .unwrap();
    assert_eq!(out.len(), 6002);
    assert_eq!(
        out[0].canonical.as_deref(),
        Some(b"canonical.example".as_slice())
    );
    assert!(out[1..].iter().all(|e| e.canonical.is_none()));
    assert_eq!(out[0].address, v6());
    for (i, a) in addresses.iter().enumerate() {
        assert_eq!(out[2 + i * 2].address, *a);
        assert_eq!(out[3 + i * 2].address, *a);
    }
}
#[test]
fn service_names_alias_protocol_constraints_and_missing_service_are_distinct() {
    let mut f = Fixture::default();
    let out = resolve(&mut f, Some(b"192.0.2.1"), Some(b"http"), Hints::default()).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].transport, Transport::Tcp);
    assert_eq!(out[0].port, 80);
    assert_eq!(
        resolve(
            &mut f,
            Some(b"192.0.2.1"),
            Some(b"http"),
            Hints {
                socktype: 2,
                ..Hints::default()
            }
        ),
        Err(Error::Service)
    );
    let out = resolve(&mut f, Some(b"192.0.2.1"), None, Hints::default()).unwrap();
    assert_eq!(out.len(), 2);
    assert!(out.iter().all(|e| e.port == 0));
}
#[test]
fn mapped_fallback_all_and_unspecified_flags_have_separate_semantics() {
    for (have6, all, expected) in [
        (false, false, 1),
        (true, false, 1),
        (false, true, 1),
        (true, true, 2),
    ] {
        let mut f = Fixture::default();
        f.hosts.insert(AF_INET, Ok(vec![v4()]));
        if have6 {
            f.hosts.insert(AF_INET6, Ok(vec![v6()]));
        }
        let out = resolve(
            &mut f,
            Some(b"name"),
            Some(b"80"),
            Hints {
                family: AF_INET6,
                flags: AI_V4MAPPED | if all { AI_ALL } else { 0 },
                socktype: 1,
                ..Hints::default()
            },
        )
        .unwrap();
        assert_eq!(out.len(), expected);
        if !have6 || all {
            let Address::V6(a) = out.last().unwrap().address.address else {
                panic!()
            };
            assert_eq!(a[10..12], [255; 2]);
            assert_eq!(a[12..], [192, 0, 2, 1]);
        }
        assert_eq!(
            f.calls.iter().any(|c| c.starts_with("host:2:")),
            !have6 || all
        );
    }
    let mut f = Fixture::default();
    f.hosts.insert(AF_INET, Ok(vec![v4()]));
    let out = resolve(
        &mut f,
        Some(b"name"),
        None,
        Hints {
            flags: AI_V4MAPPED | AI_ALL,
            ..Hints::default()
        },
    )
    .unwrap();
    assert!(matches!(out[0].address.address, Address::V4(_)));
    assert_eq!(
        resolve(
            &mut f,
            Some(b"192.0.2.1"),
            None,
            Hints {
                family: AF_INET6,
                ..Hints::default()
            }
        ),
        Err(Error::NoName)
    );
}
#[test]
fn address_configuration_uses_supplied_families_and_never_guesses_from_loopback() {
    for config in [
        Configuration {
            ipv4: false,
            ipv6: false,
        },
        Configuration {
            ipv4: true,
            ipv6: false,
        },
        Configuration {
            ipv4: false,
            ipv6: true,
        },
    ] {
        let mut f = Fixture {
            config,
            ..Fixture::default()
        };
        f.hosts.insert(AF_INET, Ok(vec![v4()]));
        f.hosts.insert(AF_INET6, Ok(vec![v6()]));
        let out = resolve(
            &mut f,
            Some(b"name"),
            Some(b"80"),
            Hints {
                flags: AI_ADDRCONFIG,
                socktype: 1,
                ..Hints::default()
            },
        );
        if !config.ipv4 && !config.ipv6 {
            assert_eq!(out, Err(Error::NoName));
        } else {
            let out = out.unwrap();
            assert_eq!(out.len(), 1);
            assert_eq!(out[0].address, if config.ipv4 { v4() } else { v6() });
        }
        assert_eq!(
            f.calls.iter().any(|c| c.starts_with("host:2:")),
            config.ipv4
        );
        assert_eq!(
            f.calls.iter().any(|c| c.starts_with("host:10:")),
            config.ipv6
        );
    }
}
#[test]
fn family_failures_aggregate_but_sink_failures_and_authority_errors_are_not_hidden() {
    let mut f = Fixture::default();
    f.hosts.insert(AF_INET6, Err(Error::Again));
    f.hosts.insert(AF_INET, Err(Error::Fail));
    assert_eq!(
        resolve(&mut f, Some(b"name"), None, Hints::default()),
        Err(Error::Again)
    );
    f.hosts.insert(AF_INET, Ok(vec![v4()]));
    assert_eq!(
        resolve(&mut f, Some(b"name"), None, Hints::default())
            .unwrap()
            .len(),
        2
    );
    f.hosts.insert(AF_INET6, Err(Error::System(-13)));
    assert_eq!(
        resolve(&mut f, Some(b"name"), None, Hints::default()),
        Err(Error::System(-13))
    );
    f.hosts.insert(AF_INET6, Ok(vec![v6()]));
    let mut calls = 0;
    assert_eq!(
        n::getaddrinfo(&mut f, Some(b"name"), None, Hints::default(), &mut |_| {
            calls += 1;
            Err(Error::Memory)
        }),
        Err(Error::Memory)
    );
    assert_eq!(calls, 1);
    f.hosts.insert(AF_INET6, Ok(vec![v4()]));
    assert_eq!(
        resolve(&mut f, Some(b"name"), None, Hints::default()),
        Err(Error::Fail)
    );
    f.hosts.insert(AF_INET6, Ok(vec![v6()]));
    f.canonical = b"bad\0name".to_vec();
    assert_eq!(
        resolve(
            &mut f,
            Some(b"name"),
            None,
            Hints {
                flags: AI_CANONNAME,
                ..Hints::default()
            }
        ),
        Err(Error::Fail)
    );
}
#[test]
fn scope_literals_accept_numeric_or_resolved_interfaces_without_dns() {
    let mut f = Fixture::default();
    for (node, scope) in [
        (b"fe80::1%7".as_slice(), 7),
        (b"fe80::1%eth0", 7),
        (b"fe80::1%0", 0),
        (b"fe80::1%4294967295", u32::MAX),
    ] {
        let out = resolve(
            &mut f,
            Some(node),
            Some(b"0"),
            Hints {
                flags: AI_NUMERICHOST,
                socktype: 1,
                ..Hints::default()
            },
        )
        .unwrap();
        assert_eq!(out[0].address.scope, scope);
    }
    assert_eq!(f.calls, vec!["scope:eth0"]);
    for bad in [
        b"fe80::1%".as_slice(),
        b"fe80::1%missing",
        b"fe80::1%4294967296",
        b"fe80::1%7%8",
        b"127.0.0.1%7",
        b"invalid::address",
    ] {
        assert_eq!(
            resolve(&mut f, Some(bad), None, Hints::default()),
            Err(Error::NoName)
        );
    }
    assert!(!f.calls.iter().any(|c| c.starts_with("host:")));
}
#[test]
fn reverse_numeric_omission_overflow_and_port_protocol_are_independent() {
    let mut f = Fixture::default();
    let mut host = [0; NI_MAXHOST];
    let mut service = [0; NI_MAXSERV];
    n::getnameinfo(
        &mut f,
        v4(),
        512,
        NI_NUMERICHOST | NI_NUMERICSERV,
        Some(&mut host),
        Some(&mut service),
    )
    .unwrap();
    assert_eq!(&host[..10], b"192.0.2.1\0");
    assert_eq!(&service[..4], b"512\0");
    assert!(f.calls.is_empty());
    for (flags, want) in [(0, b"exec\0".as_slice()), (NI_DGRAM, b"biff\0".as_slice())] {
        n::getnameinfo(&mut f, v4(), 512, flags, None, Some(&mut service)).unwrap();
        assert_eq!(&service[..want.len()], want);
    }
    assert!(!f.calls.iter().any(|c| c.starts_with("reverse:")));
    assert_eq!(
        n::getnameinfo(&mut f, v4(), 80, 0, None, None),
        Err(Error::NoName)
    );
    assert_eq!(
        n::getnameinfo(&mut f, v4(), 80, 1 << 20, Some(&mut host), None),
        Err(Error::BadFlags)
    );
    for capacity in 0..10 {
        let mut out = [0xa5; 16];
        assert_eq!(
            n::getnameinfo(
                &mut f,
                v4(),
                0,
                NI_NUMERICHOST,
                Some(&mut out[..capacity]),
                None
            ),
            Err(Error::Overflow)
        );
        assert!(out[capacity..].iter().all(|b| *b == 0xa5));
    }
}
#[test]
fn reverse_required_names_local_nofqdn_mapping_and_errors_do_not_fake_results() {
    let mut f = Fixture::default();
    let mut out = [0; NI_MAXHOST];
    f.reverse_error = Some(Error::NoName);
    n::getnameinfo(&mut f, v4(), 0, 0, Some(&mut out), None).unwrap();
    assert_eq!(&out[..10], b"192.0.2.1\0");
    f.reverse_error = None;
    assert_eq!(
        n::getnameinfo(&mut f, v4(), 0, NI_NAMEREQD, Some(&mut out), None),
        Err(Error::NoName)
    );
    n::getnameinfo(&mut f, v4(), 0, 0, Some(&mut out), None).unwrap();
    assert_eq!(&out[..10], b"192.0.2.1\0");
    for local in [false, true] {
        f.reverse = Some((b"host.example".to_vec(), local));
        n::getnameinfo(&mut f, v4(), 0, NI_NOFQDN, Some(&mut out), None).unwrap();
        let expected = if local {
            b"host\0".as_slice()
        } else {
            b"host.example\0".as_slice()
        };
        assert_eq!(&out[..expected.len()], expected);
    }
    f.reverse_error = Some(Error::Again);
    assert_eq!(
        n::getnameinfo(&mut f, v4(), 0, 0, Some(&mut out), None),
        Err(Error::Again)
    );
    f.reverse_error = None;
    f.calls.clear();
    let mut mapped = [0; 16];
    mapped[10..12].fill(255);
    mapped[12..].copy_from_slice(&[192, 0, 2, 1]);
    n::getnameinfo(
        &mut f,
        Address::V6(mapped).into(),
        0,
        0,
        Some(&mut out),
        None,
    )
    .unwrap();
    assert_eq!(f.calls[0], format!("reverse:{:?}", v4()));
}

#[test]
fn legacy_numeric_forms_match_host_getaddrinfo_without_changing_inet_pton() {
    for input in [
        "127.1",
        "127.0.1",
        "0177.0.0.1",
        "0x7f000001",
        "0xffffffff",
        "4294967295",
        "192.0.2.1",
        "1.2.65535",
        "1.16777215",
        "256.1",
        "1.2.65536",
        "4294967296",
        "0x",
        "09.1",
        "1..2",
        " 127.1",
        "+127.1",
    ] {
        let node = std::ffi::CString::new(input).unwrap();
        let hints = libc::addrinfo {
            ai_flags: libc::AI_NUMERICHOST | libc::AI_NUMERICSERV,
            ai_family: libc::AF_INET,
            ai_socktype: libc::SOCK_STREAM,
            ai_protocol: 0,
            ai_addrlen: 0,
            ai_addr: std::ptr::null_mut(),
            ai_canonname: std::ptr::null_mut(),
            ai_next: std::ptr::null_mut(),
        };
        let mut result = std::ptr::null_mut();
        let status =
            unsafe { libc::getaddrinfo(node.as_ptr(), c"80".as_ptr(), &hints, &mut result) };
        let got = n::ipv4_number(input.as_bytes());
        if status == 0 {
            let address = unsafe { &*((*result).ai_addr.cast::<libc::sockaddr_in>()) };
            assert_eq!(got, Some(address.sin_addr.s_addr.to_ne_bytes()), "{input}");
            unsafe { libc::freeaddrinfo(result) };
        } else {
            assert_eq!(got, None, "{input}: {status}");
        }
    }
}

#[test]
fn a_failed_family_cannot_commit_a_partial_prefix_even_if_addresses_were_emitted() {
    for error in [
        Error::NoName,
        Error::Again,
        Error::Fail,
        Error::Memory,
        Error::System(-5),
    ] {
        let mut f = Fixture {
            after_host: Some(error),
            ..Fixture::default()
        };
        f.hosts.insert(AF_INET6, Ok(vec![v6()]));
        assert_eq!(
            resolve(&mut f, Some(b"name"), None, Hints::default()),
            Err(error)
        );
        assert_eq!(f.calls.len(), 1);
    }
}

#[test]
fn numeric_forward_and_reverse_results_match_independent_host_libc() {
    for node in [
        None,
        Some("192.0.2.1"),
        Some("2001:db8::1"),
        Some("::ffff:192.0.2.1"),
    ] {
        for family in [AF_UNSPEC, AF_INET, AF_INET6] {
            for kind in [1, 2] {
                for flags in [
                    AI_NUMERICHOST | AI_NUMERICSERV,
                    AI_NUMERICHOST | AI_NUMERICSERV | AI_PASSIVE,
                    AI_NUMERICHOST | AI_NUMERICSERV | AI_V4MAPPED,
                ] {
                    let node_c = node.map(|s| std::ffi::CString::new(s).unwrap());
                    let h = libc::addrinfo {
                        ai_flags: flags,
                        ai_family: family,
                        ai_socktype: kind,
                        ai_protocol: 0,
                        ai_addrlen: 0,
                        ai_addr: std::ptr::null_mut(),
                        ai_canonname: std::ptr::null_mut(),
                        ai_next: std::ptr::null_mut(),
                    };
                    let mut head = std::ptr::null_mut();
                    let code = unsafe {
                        libc::getaddrinfo(
                            node_c.as_ref().map_or(std::ptr::null(), |n| n.as_ptr()),
                            c"32100".as_ptr(),
                            &h,
                            &mut head,
                        )
                    };
                    let mut f = Fixture::default();
                    let ours = resolve(
                        &mut f,
                        node.map(str::as_bytes),
                        Some(b"32100"),
                        Hints {
                            family,
                            socktype: kind,
                            flags,
                            ..Hints::default()
                        },
                    );
                    if code != 0 {
                        assert_eq!(
                            ours.map(|_| ()),
                            Err(Error::NoName),
                            "{node:?}/{family}/{flags}: {code}"
                        );
                        continue;
                    }
                    let mut expected = Vec::new();
                    let mut cursor = head;
                    while !cursor.is_null() {
                        let entry = unsafe { &*cursor };
                        let mut host = [0i8; 1025];
                        let mut port = [0i8; 32];
                        assert_eq!(
                            unsafe {
                                libc::getnameinfo(
                                    entry.ai_addr,
                                    entry.ai_addrlen,
                                    host.as_mut_ptr(),
                                    1025,
                                    port.as_mut_ptr(),
                                    32,
                                    libc::NI_NUMERICHOST | libc::NI_NUMERICSERV,
                                )
                            },
                            0
                        );
                        assert_eq!(
                            unsafe { std::ffi::CStr::from_ptr(port.as_ptr()) }.to_bytes(),
                            b"32100"
                        );
                        expected.push((
                            entry.ai_family,
                            unsafe { std::ffi::CStr::from_ptr(host.as_ptr()) }
                                .to_bytes()
                                .to_vec(),
                            entry.ai_socktype,
                            entry.ai_protocol,
                        ));
                        cursor = entry.ai_next;
                    }
                    unsafe { libc::freeaddrinfo(head) };
                    let mut actual = ours
                        .unwrap()
                        .into_iter()
                        .map(|e| {
                            let mut out = [0; 1025];
                            let length = e.address.format(&mut out).unwrap();
                            (
                                e.address.family(),
                                out[..length].to_vec(),
                                e.transport.socktype(),
                                e.transport.protocol(),
                            )
                        })
                        .collect::<Vec<_>>();
                    expected.sort();
                    actual.sort();
                    assert_eq!(actual, expected, "{node:?}/{family}/{flags}");
                    assert!(f.calls.is_empty());
                }
            }
        }
    }
}
