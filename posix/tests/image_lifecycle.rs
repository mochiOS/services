//! Exercise the runtime's real callback runners, including reverse teardown.
use std::cell::RefCell;
type InitFn = unsafe extern "C" fn();
#[path = "../../../user/crates/newlib-runtime/src/image_lifecycle.rs"]
mod implementation;

thread_local! { static EVENTS: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) }; }
extern "C" fn first() {
    EVENTS.with_borrow_mut(|events| events.push(1));
}
extern "C" fn second() {
    EVENTS.with_borrow_mut(|events| events.push(2));
}
extern "C" fn third() {
    EVENTS.with_borrow_mut(|events| events.push(3));
}

#[test]
fn initialization_is_forward_and_finalization_undoes_it_in_reverse() {
    let array: [InitFn; 3] = [first, second, third];
    EVENTS.with_borrow_mut(Vec::clear);
    // SAFETY: these bounds describe a live array of callable functions.
    unsafe {
        implementation::initialize(array.as_ptr(), array.as_ptr().add(array.len()));
        implementation::finalize(array.as_ptr(), array.as_ptr().add(array.len()));
    }
    EVENTS.with_borrow(|events| assert_eq!(*events, [1, 2, 3, 3, 2, 1]));
}

#[test]
fn empty_and_single_entry_ranges_do_not_read_outside_the_array() {
    EVENTS.with_borrow_mut(Vec::clear);
    for array in [&[][..], &[second as InitFn][..]] {
        // SAFETY: both bounds come from the same live array, including empty.
        unsafe {
            implementation::initialize(array.as_ptr(), array.as_ptr().add(array.len()));
            implementation::finalize(array.as_ptr(), array.as_ptr().add(array.len()));
        }
    }
    EVENTS.with_borrow(|events| assert_eq!(*events, [2, 2]));
}
