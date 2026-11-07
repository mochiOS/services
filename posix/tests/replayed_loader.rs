//! Execute the shared recording/replay backend, including adversarial transcripts.
use mochios_posix_client::{
    ObjectHandleAttachment,
    image_preparation::{
        Backend, Environment, Preparation, Source,
        replay::{Recording, Replay, original},
    },
    newlib_errno::*,
};
use std::{cell::RefCell, collections::BTreeMap};
thread_local! {static IMAGES:RefCell<(u32,BTreeMap<u32,Vec<u8>>)>=RefCell::new((1,BTreeMap::new()));}
struct Memory;
fn image(bytes: &[u8]) -> u32 {
    IMAGES.with_borrow_mut(|s| {
        let id = s.0;
        s.0 += 1;
        s.1.insert(id, bytes.to_vec());
        id
    })
}
fn elf() -> Vec<u8> {
    let mut b = vec![0; 512];
    b[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    b[16..18].copy_from_slice(&3u16.to_le_bytes());
    b[18..20].copy_from_slice(&62u16.to_le_bytes());
    b[20..24].copy_from_slice(&1u32.to_le_bytes());
    for (at, n) in [(24, 256u64), (32, 64)] {
        b[at..at + 8].copy_from_slice(&n.to_le_bytes());
    }
    for (at, n) in [(52, 64u16), (54, 56), (56, 1)] {
        b[at..at + 2].copy_from_slice(&n.to_le_bytes());
    }
    b[64..68].copy_from_slice(&1u32.to_le_bytes());
    b[68..72].copy_from_slice(&5u32.to_le_bytes());
    for (at, n) in [(96, 512u64), (104, 4096), (112, 4096)] {
        b[at..at + 8].copy_from_slice(&n.to_le_bytes());
    }
    b[256] = 0xc3;
    b
}
unsafe impl Backend for Memory {
    fn critical<T>(f: impl FnOnce() -> T) -> T {
        f()
    }
    fn allocate(n: usize) -> *mut u8 {
        unsafe {
            let p = std::alloc::alloc(std::alloc::Layout::from_size_align(n + 16, 16).unwrap());
            if p.is_null() {
                return p;
            }
            p.cast::<usize>().write(n);
            p.add(16)
        }
    }
    unsafe fn deallocate(p: *mut u8) {
        if !p.is_null() {
            unsafe {
                let base = p.sub(16);
                let n = base.cast::<usize>().read();
                std::alloc::dealloc(
                    base,
                    std::alloc::Layout::from_size_align(n + 16, 16).unwrap(),
                )
            }
        }
    }
    fn close(h: u32) {
        IMAGES.with_borrow_mut(|s| {
            assert!(s.1.remove(&h).is_some());
        });
    }
    fn read_at(&self, h: u32, b: &mut [u8], at: usize) -> Result<usize, i32> {
        IMAGES.with_borrow(|s| {
            let data = s.1.get(&h).ok_or(EIO)?;
            let at = at.min(data.len());
            let n = b.len().min(data.len() - at);
            b[..n].copy_from_slice(&data[at..at + n]);
            Ok(n)
        })
    }
    fn open_library(&self, _: &[u8]) -> Result<ObjectHandleAttachment<u32>, i32> {
        Err(ENOENT)
    }
    fn validate_library(&self, _: ObjectHandleAttachment<u32>) -> Result<(), i32> {
        Ok(())
    }
    fn validate_captured(&self, s: Source<'_>, b: &[u8]) -> Result<(), i32> {
        if matches!(s, Source::Root) && b == elf()
            || matches!(
                s,
                Source::Dependency {
                    path: b"/approved/lib.so",
                    ..
                }
            ) && b == b"library"
        {
            Ok(())
        } else {
            Err(EACCES)
        }
    }
    fn entropy(&self, b: &mut [u8]) -> Result<(), i32> {
        b.fill(9);
        Ok(())
    }
    fn create_image(&self, n: usize) -> Result<u32, i32> {
        Ok(image(&vec![0; n]))
    }
    fn write_at(&self, h: u32, b: &[u8], at: usize) -> Result<usize, i32> {
        IMAGES.with_borrow_mut(|s| {
            let data = s.1.get_mut(&h).ok_or(EIO)?;
            let n = b.len().min(31);
            let out = data.get_mut(at..at + n).ok_or(EIO)?;
            out.copy_from_slice(&b[..n]);
            Ok(n)
        })
    }
    fn readonly_image(&self, h: u32) -> Result<u32, i32> {
        let b = IMAGES.with_borrow(|s| s.1[&h].clone());
        Ok(image(&b))
    }
}
#[test]
fn replay_reconstructs_the_exact_common_loader_output_and_reclaims_handles() {
    let root = image(&elf());
    let recorded = Recording::new(Memory, Environment::default()).unwrap();
    let mut first = Preparation::default();
    let prepared = first
        .prepare(&recorded, root, Environment::default(), Default::default())
        .unwrap();
    let expected = prepared.bytes.to_vec();
    let record = recorded.with_bytes(|b| b.to_vec());
    let replay = Replay::new(&Memory, &record).unwrap();
    let mut second = Preparation::default();
    let result = second
        .prepare(&replay, root, replay.environment(), Default::default())
        .unwrap();
    replay.finish().unwrap();
    assert_eq!(result.bytes, expected);
    drop(first);
    drop(second);
    Memory::close(root);
    IMAGES.with_borrow(|s| assert!(s.1.is_empty()));
}
#[test]
fn root_library_paths_entropy_order_and_trailing_operations_are_not_trusted() {
    let rec = Recording::new(
        Memory,
        Environment {
            library_path: Some(b"/approved"),
            ..Default::default()
        },
    )
    .unwrap();
    rec.validate_captured(Source::Root, &elf()).unwrap();
    let mut random = [0; 8];
    rec.entropy(&mut random).unwrap();
    let dep = Source::Dependency {
        needed: b"lib.so",
        path: b"/approved/lib.so",
    };
    rec.validate_captured(dep, b"library").unwrap();
    let bytes = rec.with_bytes(|b| b.to_vec());
    for n in [0, 7, 19, bytes.len() - 1] {
        assert!(Replay::new(&Memory, &bytes[..n]).is_err());
    }
    let r = Replay::new(&Memory, &bytes).unwrap();
    assert!(r.finish().is_err());
    assert!(r.entropy(&mut random).is_err());
    r.validate_captured(Source::Root, r.root()).unwrap();
    r.entropy(&mut random).unwrap();
    assert_eq!(r.open_library(b"/unapproved/lib.so"), Err(ENOENT));
    let file = r.open_library(b"/approved/lib.so").unwrap();
    r.validate_library(file).unwrap();
    r.validate_captured(dep, b"library").unwrap();
    r.finish().unwrap();
    Memory::close(file.handle);
    let mut tampered = bytes.clone();
    let original_offset = original(&bytes).unwrap().as_ptr() as usize - bytes.as_ptr() as usize;
    tampered[original_offset + 256] ^= 1;
    let r = Replay::new(&Memory, &tampered).unwrap();
    assert_eq!(r.validate_captured(Source::Root, r.root()), Err(EACCES));
    let last = bytes.len() - 1;
    let mut bad = bytes.clone();
    bad[last] ^= 1;
    let r = Replay::new(&Memory, &bad).unwrap();
    r.validate_captured(Source::Root, r.root()).unwrap();
    r.entropy(&mut random).unwrap();
    assert_eq!(r.validate_captured(dep, b"librarx"), Err(EACCES));
}

#[test]
fn transcript_environment_and_event_budgets_fail_closed() {
    for value in [b"bad\0value".as_slice(), &vec![b'x'; 65537]] {
        assert!(matches!(
            Recording::new(
                Memory,
                Environment {
                    library_path: Some(value),
                    ..Default::default()
                }
            ),
            Err(E2BIG)
        ));
    }
    let recording = Recording::new(Memory, Environment::default()).unwrap();
    recording.validate_captured(Source::Root, &elf()).unwrap();
    let mut random = [0; 8];
    for _ in 1..8200 {
        recording.entropy(&mut random).unwrap();
    }
    assert_eq!(recording.entropy(&mut random), Err(EFBIG));
    let mut bytes = recording.with_bytes(|b| b.to_vec());
    assert!(Replay::new(&Memory, &bytes).is_ok());
    let last = bytes[bytes.len() - 24..].to_vec();
    bytes.extend_from_slice(&last);
    assert!(Replay::new(&Memory, &bytes).is_err());
    let mut duplicate_root = Recording::new(Memory, Environment::default())
        .unwrap()
        .with_bytes(|b| b.to_vec());
    let root = Recording::new(Memory, Environment::default()).unwrap();
    root.validate_captured(Source::Root, &elf()).unwrap();
    let events = root.with_bytes(|b| b[20..].to_vec());
    duplicate_root.extend_from_slice(&events);
    duplicate_root.extend_from_slice(&events);
    assert!(Replay::new(&Memory, &duplicate_root).is_err());
}
