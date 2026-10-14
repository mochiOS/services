#[path = "../../../core/src/syscall/exec/launch.rs"]
mod actual;

#[test]
fn launch_kind_is_explicit_and_preserves_the_native_startup_image() {
    use actual::ImageLaunch;
    use mnu_abi::process_image;
    let mut bytes = [0; process_image::HEADER_LEN + 16];
    let length = process_image::encode(0, &[0; 16], &[], &mut bytes).unwrap();
    let startup = process_image::decode(&bytes[..length]).unwrap();
    let created = ImageLaunch::Created(startup);
    assert!(!created.is_bootstrap());
    assert_eq!(created.startup(), Some(startup));
    assert!(ImageLaunch::Bootstrap.is_bootstrap());
    assert_eq!(ImageLaunch::Bootstrap.startup(), None);
}

#[test]
fn runtime_creation_cannot_select_bootstrap_by_label_identity_or_privilege() {
    let source = include_str!("../../../core/src/syscall/exec.rs");
    let bootstrap = source
        .split("pub(crate) fn launch_bootstrap_image(")
        .nth(1)
        .unwrap()
        .split("\n}\n")
        .next()
        .unwrap();
    let created = source
        .split("pub fn process_create_syscall(")
        .nth(1)
        .unwrap()
        .split("\n}\n")
        .next()
        .unwrap();
    assert!(bootstrap.contains("ImageLaunch::Bootstrap"));
    assert!(created.contains("ImageLaunch::Created(startup)"));
    let loader = source
        .split("fn exec_with_data(")
        .nth(1)
        .unwrap()
        .split("\nfn replace_current_process_image(")
        .next()
        .unwrap();
    assert!(loader.contains("let is_boot_init = launch.is_bootstrap();"));
    for policy in [
        "init_launch",
        "boot_init.exec_path",
        "boot_init.process_name",
        "launched_tid",
    ] {
        assert!(
            !loader.contains(policy),
            "name/thread-based bootstrap policy returned: {policy}"
        );
    }
    assert!(loader.contains("if let Some(handle) = created_handle.0.take() {\n            handle\n        } else {\n            pid.as_u64()"));
}
