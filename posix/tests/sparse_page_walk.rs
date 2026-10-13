#[path = "../../../core/src/mem/sparse_page_walk.rs"]
mod sparse_page_walk;
use sparse_page_walk::{next, Entry, Error};
use std::collections::BTreeMap;

#[test]
fn missing_subtrees_are_skipped_across_all_levels() {
    let address = (3 << 39) | (7 << 30) | (11 << 21) | (19 << 12);
    let entries = BTreeMap::from([
        ((4096, 3, 4), Entry::Branch(8192)),
        ((8192, 7, 3), Entry::Branch(12288)),
        ((12288, 11, 2), Entry::Branch(16384)),
        ((16384, 19, 1), Entry::Leaf),
    ]);
    let queries = std::cell::Cell::new(0);
    let mut inspect = |table, index, level| -> Result<Entry, ()> {
        queries.set(queries.get() + 1);
        Ok(entries
            .get(&(table, index, level))
            .copied()
            .unwrap_or(Entry::Absent))
    };
    assert_eq!(next(4096, 0, 1 << 47, &mut inspect), Ok(Some(address)));
    assert!(
        queries.get() < 150,
        "work must not scale with virtual page count"
    );
    assert_eq!(
        next(4096, address, address + 4096, &mut inspect),
        Ok(Some(address))
    );
    assert_eq!(next(4096, address + 4096, 4 << 39, &mut inspect), Ok(None));
}

#[test]
fn invalid_inputs_and_unsupported_leaf_levels_are_rejected() {
    for (root, start, end) in [
        (0, 0, 4096),
        (1, 0, 4096),
        (4096, 1, 4096),
        (4096, 0, 4097),
        (4096, 8192, 4096),
        (4096, 0, (1 << 47) + 4096),
    ] {
        assert_eq!(
            next(root, start, end, |_, _, _| -> Result<Entry, ()> {
                panic!("invalid input must not inspect a table")
            }),
            Err(Error::InvalidRange)
        );
    }
    assert_eq!(
        next(4096, 0, 4096, |_, _, _| Ok::<_, ()>(Entry::Leaf)),
        Err(Error::InvalidTree)
    );
    assert_eq!(
        next(4096, 0, 4096, |_, _, _| Ok::<_, ()>(Entry::Branch(0))),
        Err(Error::InvalidTree)
    );
    assert_eq!(
        next(4096, 0, 4096, |_, _, _| Err::<Entry, _>(7)),
        Err(Error::Backend(7))
    );
    assert_eq!(
        next(4096, 0, 0, |_, _, _| -> Result<Entry, ()> { panic!() }),
        Ok(None)
    );
}
