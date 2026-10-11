#[path = "../../../user/crates/newlib-runtime/src/groups.rs"]
mod groups;

#[test]
fn groups_use_newlib_array_stride_and_preserve_adjacent_memory() {
    let mut output = [777; 4];
    groups::store(&[10, 20], &mut output[..2]).unwrap();
    assert_eq!(output, [10, 20, 777, 777]);
    let mut wire = [0; 4];
    groups::widen(&output[..2], &mut wire);
    assert_eq!(wire, [10, 20, 0, 0]);
    assert_eq!(core::mem::size_of::<groups::Gid>(), 2);
}

#[test]
fn overflow_and_short_arrays_never_partially_write() {
    let mut output = [777; 2];
    assert_eq!(groups::store(&[10, 65536], &mut output), Err(()));
    assert_eq!(output, [777; 2]);
    assert_eq!(groups::store(&[10, 20, 30], &mut output), Err(()));
    assert_eq!(output, [777; 2]);
    groups::store(&[0, 65535], &mut output).unwrap();
    assert_eq!(output, [0, 65535]);
    groups::store(&[], &mut []).unwrap();
}

#[test]
fn public_runtime_group_arrays_match_newlib_headers() {
    let header = include_str!("../../../libraries/newlib/newlib/libc/include/sys/_types.h");
    assert!(header.contains("typedef unsigned short __gid_t;"));
    let runtime = include_str!("../../../user/crates/newlib-runtime/src/lib.rs");
    assert!(runtime.contains("grouplist: *mut groups::Gid"));
    assert!(runtime.contains("grouplist: *const groups::Gid"));
    assert!(
        runtime.contains("groups::store(&groups[..count], destination).map_err(|_| EOVERFLOW)?")
    );
}
