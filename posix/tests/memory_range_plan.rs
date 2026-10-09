extern crate alloc;

#[path = "../../../core/src/mem/range_plan.rs"]
mod range_plan;

#[test]
fn adjacent_regions_are_clipped_and_keep_backing_offsets() {
    let regions = [(0x1000, 0x3000, 8192), (0x3000, 0x5000, 65536)];
    let plan = range_plan::collect(0x2000, 0x2000, |cursor| {
        regions
            .iter()
            .find(|(start, end, _)| cursor >= *start && cursor < *end)
            .map(|(start, end, offset)| (*end, Some(offset + cursor - start)))
    });
    assert_eq!(plan, Some(vec![(12288, 4096), (65536, 4096)]));
}

#[test]
fn no_work_regions_still_validate_coverage() {
    let plan = range_plan::collect(4096, 12288, |cursor| match cursor {
        4096 => Some((8192, None)),
        8192 => Some((12288, Some(7))),
        12288 => Some((16384, None)),
        _ => None,
    });
    assert_eq!(plan, Some(vec![(7, 4096)]));
    assert_eq!(
        range_plan::collect::<u64>(4096, 4096, |_| Some((8192, None))),
        Some(vec![])
    );
}

#[test]
fn holes_overflow_and_nonadvancing_regions_fail_before_io() {
    assert_eq!(
        range_plan::collect(4096, 8192, |cursor| {
            (cursor == 4096).then_some((8192, Some(7)))
        }),
        None
    );
    assert_eq!(
        range_plan::collect::<u64>(u64::MAX - 1, 4096, |_| panic!("overflow lookup")),
        None
    );
    assert_eq!(
        range_plan::collect(4096, 4096, |_| Some((4096, Some(7)))),
        None
    );
    assert_eq!(
        range_plan::collect(4096, 4096, |_| Some((0, Some(7)))),
        None
    );
}

#[test]
fn plan_owns_backing_references_after_mapping_is_removed() {
    use std::sync::Arc;
    let object = Arc::new(42);
    let plan = range_plan::collect(4096, 4096, |_| Some((8192, Some(object.clone())))).unwrap();
    drop(object);
    assert_eq!(*plan[0].0, 42);
}
