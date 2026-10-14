extern crate alloc;

#[path = "../../../core/src/util/object_snapshot.rs"]
mod snapshot;

#[test]
fn snapshot_is_exact_bounded_and_owned_without_a_seekable_file() {
    let mut source = b"image".to_vec();
    let bytes = snapshot::read(5, 5, |output| {
        output.copy_from_slice(&source);
        Ok(output.len())
    })
    .unwrap();
    source.fill(0);
    assert_eq!(bytes, b"image");
    assert_eq!(
        snapshot::read(0, 5, |output| {
            assert!(output.is_empty());
            Ok(0)
        }),
        Ok(vec![])
    );
}

#[test]
fn extent_errors_and_short_reads_never_produce_an_executable_snapshot() {
    assert_eq!(
        snapshot::read(6, 5, |_| panic!("oversized read")),
        Err(mnu_abi::EFBIG)
    );
    assert_eq!(
        snapshot::read(u64::MAX, 5, |_| panic!("oversized read")),
        Err(mnu_abi::EFBIG)
    );
    for count in [0, 4, 6] {
        assert_eq!(snapshot::read(5, 5, |_| Ok(count)), Err(mnu_abi::EIO));
    }
    assert_eq!(
        snapshot::read(5, 5, |_| Err(mnu_abi::EACCES)),
        Err(mnu_abi::EACCES)
    );
}
