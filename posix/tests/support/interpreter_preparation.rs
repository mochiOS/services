use super::*;
use mochios_posix_client::image_preparation::{Backend, Environment, Preparation};
#[path = "interpreter_fixture.rs"]
pub(super) mod fixture;

#[test]
fn captures_exact_interpreter_without_search_or_parent_relocation() {
    let root = fixture::image(true, true, false);
    let loader = fixture::image(false, false, true);
    reset(0);
    STATE.with_borrow_mut(|s| {
        s.bytes = root.clone();
        s.libraries = vec![(fixture::PATH.to_vec(), loader)];
    });
    let mut owner = Preparation::<exec_image::Runtime>::default();
    let result = owner
        .prepare(
            &exec_image::Runtime,
            19,
            Environment {
                library_path: Some(b"/untrusted"),
                preload: Some(b"bad.so"),
                audit: Some(b"audit.so"),
            },
            Default::default(),
        )
        .unwrap();
    let executable = result.executable.unwrap();
    assert_eq!(executable.load_bias, 0);
    assert_eq!(executable.entry, 0x401100);
    assert_ne!(executable.interpreter_base, 0);
    assert!(result.lifecycle.is_empty() && result.tls.is_empty() && result.indirect.is_empty());
    assert_eq!(result.image, 29);
    assert_eq!(
        u64::from_le_bytes(result.bytes[24..32].try_into().unwrap()),
        executable.interpreter_base + 0x1100
    );
    drop(owner);
    STATE.with_borrow(|s| {
        assert_eq!(s.library_paths, [fixture::PATH]);
        assert!(!s.closed.contains(&19));
        for h in [200, 28, 29] {
            assert_eq!(s.closed.iter().filter(|&&x| x == h).count(), 1);
        }
    });
}

#[test]
fn interpreter_failures_propagate_without_creating_or_leaking_output() {
    for (failure, error) in [
        (20, EACCES),
        (21, EACCES),
        (22, EIO),
        (23, ENOEXEC),
        (24, EIO),
        (25, EIO),
        (26, ENOENT),
        (27, ENOTDIR),
    ] {
        reset(failure);
        STATE.with_borrow_mut(|s| {
            s.bytes = fixture::image(true, false, true);
            s.libraries = vec![(fixture::PATH.to_vec(), fixture::image(false, false, true))];
        });
        let mut owner = Preparation::<exec_image::Runtime>::default();
        let result = owner.prepare(
            &exec_image::Runtime,
            19,
            Environment::default(),
            Default::default(),
        );
        assert!(matches!(result,Err(e) if e==error), "failure {failure}");
        drop(owner);
        STATE.with_borrow(|s| {
            assert_eq!(s.images_created, 0);
            assert!(!s.closed.contains(&19));
            assert_eq!(
                s.closed.iter().filter(|&&h| h == 200).count(),
                usize::from(failure != 20)
            );
        });
    }
    for missing in [false, true] {
        reset(0);
        STATE.with_borrow_mut(|s| {
            s.bytes = fixture::image(true, false, true);
            if !missing {
                s.libraries = vec![(fixture::PATH.to_vec(), vec![0; 64])];
            }
        });
        let mut owner = Preparation::<exec_image::Runtime>::default();
        let result = owner.prepare(
            &exec_image::Runtime,
            19,
            Environment::default(),
            Default::default(),
        );
        assert!(matches!(result,Err(e) if e==if missing {ENOENT}else{ENOEXEC}));
        drop(owner);
        STATE.with_borrow(|s| assert_eq!(s.images_created, 0));
    }
}
