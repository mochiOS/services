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

#[test]
fn unavailable_io_options_are_known_answers_not_size_limits() {
    use mochios_posix_client::configuration::{file_option, system_option};
    for selector in [21, 28, 32] {
        assert_eq!(system_option(selector), Some(-1));
    }
    for selector in [9, 10, 11] {
        assert_eq!(file_option(selector), Some(-1));
    }
    for selector in [-1, 0, 12, i32::MAX] {
        assert_eq!(file_option(selector), None);
    }
    for selector in [-1, 9, 10, 22, 27, 33, i32::MAX] {
        assert_eq!(system_option(selector), None);
    }
    let header = include_str!("../../../libraries/newlib/newlib/libc/include/sys/unistd.h");
    for (name, selector) in [
        ("_SC_ASYNCHRONOUS_IO", 21),
        ("_SC_PRIORITIZED_IO", 28),
        ("_SC_SYNCHRONIZED_IO", 32),
        ("_PC_ASYNC_IO", 9),
        ("_PC_PRIO_IO", 10),
        ("_PC_SYNC_IO", 11),
    ] {
        assert!(
            header
                .lines()
                .any(|line| line.split_whitespace().collect::<Vec<_>>()
                    == ["#define", name, &selector.to_string()])
        );
    }
}
