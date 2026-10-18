#[allow(dead_code)]
#[path = "../../display/src/present.rs"]
mod present;
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn damage_coordinate_overflow_is_native_and_invalid_geometry_stays_invalid() {
    use mochi_user_syscall::NativeError;
    let geometry = present::DisplayGeometry {
        width: 4,
        height: 3,
        stride: 4,
        format: present::PIXEL_FORMAT_XRGB8888,
    };
    for damage in [
        present::DamageRect {
            x: u32::MAX,
            y: 0,
            width: 2,
            height: 1,
        },
        present::DamageRect {
            x: 0,
            y: u32::MAX,
            width: 1,
            height: 2,
        },
    ] {
        let raw = damage.validate(geometry).unwrap_err();
        assert_eq!(NativeError::from_raw(raw), Some(NativeError::LimitExceeded));
        assert_ne!(raw as i64, -34);
    }
    let invalid = present::DisplayGeometry {
        stride: 3,
        ..geometry
    };
    assert_eq!(invalid.byte_len(), Err(mochi_user_syscall::EINVAL));
    assert_eq!(
        present::DamageRect::full(geometry).validate(geometry),
        Ok(())
    );
}

#[test]
fn real_framebuffer_and_cursor_bounds_fail_before_copy_or_allocation() {
    let mut program = probe::program();
    probe::constants(
        &mut program,
        include_str!("../../display/src/present.rs"),
        &["SIZE_LIMIT", "BYTES_PER_PIXEL"],
    );
    program.push_str(
        r#"
mod present {pub const MAX_DIMENSION:u32=4096;}
mod platform {pub mod memory {
    pub struct FramebufferInfo {pub stride:u32,pub height:u32,pub size:u64}
}}
"#,
    );
    let framebuffer = include_str!("../../display/src/framebuffer_backend.rs");
    program.push_str(&framebuffer[framebuffer.find("fn visible_height(").unwrap()..]);
    program.push_str(probe::between(
        include_str!("../../display/src/virtio_gpu_backend/dma.rs"),
        "fn cursor_bgra(",
        "#[cfg(test)]",
    ));
    program.push_str(
        r#"
mod backing {
use super::*;
struct Region(Vec<u8>);
impl Region {
    fn len(&self)->usize{self.0.len()}
    fn bytes(&self)->&[u8]{&self.0}
    fn bytes_mut(&mut self)->&mut[u8]{&mut self.0}
    fn sync_for_cpu(&self)->Result<(),()>{Ok(())}
}
struct BackingStore {length:usize,regions:Vec<Region>}
impl BackingStore {
"#,
    );
    let dma = include_str!("../../display/src/virtio_gpu_backend/dma.rs");
    program.push_str(probe::between(
        dma,
        "    pub(super) fn write_all(",
        "    pub(super) fn copy_rect(",
    ));
    program.push_str(probe::between(
        dma,
        "    pub(super) fn write_at(",
        "fn cursor_bgra(",
    ));
    // The latter source span already contains the impl's closing brace.
    program.push_str(
        r#"
pub fn check(){
    let limit=NativeError::LimitExceeded.into_raw();
    let mut store=BackingStore{length:8,regions:vec![Region(vec![0;4]),Region(vec![0;4])]};
    assert_eq!(store.write_all(&[1,2,3,4,5,6,7,8]),Ok(()));
    assert_eq!(store.write_all(&[9;9]),Err(limit));
    assert_eq!(store.write_at(usize::MAX,&[9]),Err(limit));
    assert_eq!(store.write_at(7,&[9,9]),Err(limit));
    assert_eq!(store.regions[0].0,[1,2,3,4]);
    assert_eq!(store.regions[1].0,[5,6,7,8]);
    assert_eq!(store.write_at(3,&[9,10,11]),Ok(()));
    assert_eq!(store.regions[0].0,[1,2,3,9]);
    assert_eq!(store.regions[1].0,[10,11,7,8]);
    assert_eq!(store.read_u32_at(0),Ok(u32::from_le_bytes([1,2,3,9])));
    assert_eq!(store.read_u32_at(7),Err(limit));
    assert_eq!(store.read_u32_at(usize::MAX),Err(limit));
}
}
"#,
    );
    program.push_str(probe::between(
        include_str!("../../display/src/protocol.rs"),
        "pub(crate) fn errno_status(",
        "#[cfg(test)]",
    ));
    program.push_str(r#"
fn main(){
    backing::check();
    use platform::memory::FramebufferInfo as Info;
    let limit=NativeError::LimitExceeded.into_raw();
    assert_eq!(visible_height(&Info{stride:4,height:3,size:48}),Ok(3));
    for info in [Info{stride:0,height:3,size:48},Info{stride:4,height:0,size:48},
        Info{stride:4,height:3,size:47},Info{stride:4,height:4097,size:u64::MAX}] {
        assert_eq!(visible_height(&info),Err(limit));
    }
    assert_eq!(page_align_up(1),Ok(4096));
    assert_eq!(page_align_up(u64::MAX-4095),Ok(u64::MAX-4095));
    for value in [u64::MAX-4094,u64::MAX] {assert_eq!(page_align_up(value),Err(limit));}
    assert_eq!(cursor_bgra(u32::MAX,u32::MAX,u32::MAX,&[]),Err(limit));
    assert_eq!(cursor_bgra(1,1,u32::MAX,&[10,20,30,40]),Err(limit));
    assert_eq!(cursor_bgra(1,1,2,&[10,20,30,40]).unwrap(),
        [30,20,10,40,0,0,0,0,0,0,0,0,0,0,0,0]);
    let status=errno_status(limit);
    assert_eq!(SysError::from_raw(-i64::from(status)).native_error(),Some(NativeError::LimitExceeded));
}
"#);
    probe::run(&program);
}
