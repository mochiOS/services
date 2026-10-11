use mochios_posix_client::{configuration::local_limit, io_vector, thread};

#[test]
fn configuration_matches_the_limits_enforced_by_the_runtime() {
    for (selector, limit) in [
        (38, thread::MAX_THREAD_KEYS),
        (40, thread::MAX_THREADS),
        (53, thread::DESTRUCTOR_ITERATIONS),
        (66, io_vector::IOV_MAX),
    ] {
        assert_eq!(local_limit(selector), Some(limit));
        assert!(limit > 0);
    }
}

#[test]
fn local_queries_do_not_invent_values_for_other_configuration() {
    for selector in [-1, 4, 9, 10, 11, 12, 42, i32::MAX] {
        assert_eq!(local_limit(selector), None);
    }
}

#[test]
fn selectors_match_the_sdk_headers() {
    let header = include_str!("../../../libraries/newlib/newlib/libc/include/sys/unistd.h");
    for (name, selector) in [
        ("_SC_THREAD_KEYS_MAX", 38),
        ("_SC_THREAD_THREADS_MAX", 40),
        ("_SC_THREAD_DESTRUCTOR_ITERATIONS", 53),
        ("_SC_IOV_MAX", 66),
    ] {
        assert!(header.lines().any(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            fields == ["#define", name, &selector.to_string()]
        }));
    }
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    assert!(runtime.contains("configuration::local_limit(name)"));
    assert!(runtime.contains("for _ in 0..mochios_posix_client::thread::DESTRUCTOR_ITERATIONS"));
}
