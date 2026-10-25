#![allow(dead_code)]
use core::ffi::{c_char, c_int};
use mochios_posix_protocol as posix_protocol;
use std::cell::Cell;
#[path = "../../../user/crates/newlib-runtime/src/auxiliary.rs"]
mod implementation;
#[path = "../../../user/crates/newlib-runtime/src/user_copy.rs"]
mod user_copy;
#[path = "support/user_copy_native.rs"]
mod user_copy_native;
use user_copy_native::{syscall, syscall_errno};
const EFAULT: c_int = 14;
const EIO: c_int = 5;
const ENOENT: c_int = 2;
const ENAMETOOLONG: c_int = 91;
const PAGE_SIZE: usize = 4096;
thread_local! { static ERRNO: Cell<i32> = const { Cell::new(0) }; }
fn set_errno(value: i32) {
    ERRNO.set(value);
}
fn vector(table: &[[usize; 2]]) -> implementation::Vector {
    implementation::Vector {
        base: table.as_ptr() as usize,
        count: table.len(),
    }
}

#[test]
fn lookup_preserves_zero_values_and_obeys_the_original_extent_and_terminator() {
    let table = [[6, 4096], [7, 0], [31, 0x1234], [0, 0], [55, 99]];
    let view = vector(&table);
    assert_eq!(view.lookup(6), Ok(4096));
    assert_eq!(view.lookup(7), Ok(0));
    assert_eq!(view.lookup(31), Ok(0x1234));
    assert_eq!(view.lookup(0), Err(ENOENT));
    assert_eq!(view.lookup(55), Err(ENOENT));
    let bounded = implementation::Vector { count: 2, ..view };
    assert_eq!(bounded.lookup(31), Err(ENOENT));
}

#[test]
fn identity_replaces_placeholders_in_the_actual_vector_without_touching_image_metadata() {
    let mut table = [
        [11, 0],
        [12, 0],
        [13, 0],
        [14, 0],
        [23, 0],
        [31, 0x1234],
        [0, 0],
    ];
    vector(&table)
        .install_identity(implementation::Identity {
            real_uid: 501,
            effective_uid: 502,
            real_gid: 20,
            effective_gid: 21,
        })
        .unwrap();
    assert_eq!(
        table,
        [
            [11, 501],
            [12, 502],
            [13, 20],
            [14, 21],
            [23, 1],
            [31, 0x1234],
            [0, 0]
        ]
    );
    vector(&table)
        .install_identity(implementation::Identity {
            real_uid: 501,
            effective_uid: 501,
            real_gid: 20,
            effective_gid: 20,
        })
        .unwrap();
    assert_eq!(table[4], [23, 0]);
    table[0][1] = 503;
    assert_eq!(vector(&table).lookup(11), Ok(503));
}

#[test]
fn faultable_words_and_overflow_fail_without_forming_application_references() {
    assert_eq!(
        implementation::Vector { base: 1, count: 1 }.lookup(6),
        Err(EFAULT)
    );
    user_copy_native::CALLS.with_borrow_mut(Vec::clear);
    for view in [
        implementation::Vector {
            base: usize::MAX - 3,
            count: 1,
        },
        implementation::Vector {
            base: 8,
            count: usize::MAX,
        },
    ] {
        assert_eq!(view.lookup(6), Err(EFAULT));
    }
    user_copy_native::CALLS.with_borrow(|calls| assert!(calls.is_empty()));
    let table = [[6, 4096], [7, 0]];
    let view = vector(&table);
    user_copy_native::DENIED.set(Some(view.base + 16..view.base + 32));
    assert_eq!(view.lookup(6), Ok(4096));
    assert_eq!(view.lookup(7), Err(EFAULT));
    user_copy_native::DENIED.set(None);
}

#[test]
fn exported_getter_distinguishes_a_zero_value_from_missing_or_faulted_metadata() {
    let mut table: [[usize; 2]; 4] = [[6, 4096], [7, 0], [31, 0x1234], [0, 0]];
    implementation::initialize(table.as_ptr() as usize, table.len());
    assert_eq!(implementation::getauxval(6), 4096);
    ERRNO.set(123);
    assert_eq!(implementation::getauxval(7), 0);
    assert_eq!(ERRNO.get(), 123);
    assert_eq!(implementation::getauxval(999), 0);
    assert_eq!(ERRNO.get(), ENOENT);
    // Removing the terminator cannot expand the private startup bound.
    table[3] = [99, 17];
    std::hint::black_box(&table);
    assert_eq!(implementation::getauxval(99), 17);
    implementation::initialize(1, 1);
    assert_eq!(implementation::getauxval(6), 0);
    assert_eq!(ERRNO.get(), EFAULT);
    implementation::initialize(0, 0);
}
