#[allow(dead_code)]
#[path = "../../compositor/src/protocol.rs"]
mod protocol;
#[allow(dead_code)]
mod state {
    pub const MAX_DIMENSION: u32 = 16_384;
    pub const MAX_SHARED_PIXELS: usize = 262_144 * 4096 / 4;
}
#[allow(dead_code)]
#[path = "../../compositor/src/geometry.rs"]
mod geometry;

#[test]
fn native_geometry_limits_are_distinct_from_userspace_posix_range_policy() {
    use mochi_user_syscall::{NativeError, SysError};
    let limit = NativeError::LimitExceeded.into_raw();
    for rect in [
        geometry::Rect {
            x: i32::MAX,
            y: 0,
            width: u32::MAX,
            height: 1,
        },
        geometry::Rect {
            x: 0,
            y: i32::MAX,
            width: 1,
            height: u32::MAX,
        },
        geometry::Rect {
            x: 3,
            y: 0,
            width: 2,
            height: 1,
        },
    ] {
        let status = geometry::validate_damage_rect(rect, 4, 4).err().unwrap();
        assert_eq!(status, protocol::errno_status(limit));
        assert_eq!(
            SysError::from_raw(-i64::from(status)).native_error(),
            Some(NativeError::LimitExceeded)
        );
    }
    for rect in [
        geometry::Rect::default(),
        geometry::Rect {
            x: -1,
            y: 0,
            width: 1,
            height: 1,
        },
    ] {
        assert_eq!(geometry::validate_damage_rect(rect, 4, 4).err(), Some(22));
    }
    assert!(geometry::validate_damage_rect(geometry::Rect::full(4, 4), 4, 4).is_ok());
    assert_eq!(mochios_posix_protocol::STATUS_ERANGE, -34);
    assert_eq!(mochios_posix_client::newlib_errno::from_status(-34), 34);
    assert_eq!(
        mochios_posix_client::newlib_errno::from_status(limit as i64),
        139
    );
    for source in [
        include_str!("../../signature/src/main.rs"),
        include_str!("../../signature/src/posix_io.rs"),
        include_str!("../../package/src/main.rs"),
        include_str!("../../workspace/src/main.rs"),
        include_str!("../../user/src/main.rs"),
    ] {
        assert!(!source.contains("syscall::ERANGE"));
        assert!(source.contains("STATUS_ERANGE"));
    }
}
