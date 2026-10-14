extern crate alloc;

#[path = "../../core/src/bootstrap_plan.rs"]
mod plan;

use mnu_abi::exec::*;
use mnu_abi::process_create::{self, InitialState};

fn identity() -> Vec<String> {
    vec![
        format!("{APPLICATION_PACKAGE_ID_PREFIX}org.mochios.logger"),
        format!("{APPLICATION_DEVELOPER_ID_PREFIX}org.mochios.system"),
        format!("{APPLICATION_SUBJECT_KEY_ID_PREFIX}{}", "0".repeat(64)),
        format!("{APPLICATION_PROVENANCE_PREFIX}built-in"),
    ]
}

#[test]
fn verified_identity_and_exact_image_digest_are_separate_from_runtime_arguments() {
    let path = "/system/services/logger.service";
    let prepared = plan::prepare(path, &identity(), &["123".into()], b"abc", [7; 16]).unwrap();
    let fields: Vec<_> = prepared
        .authorization
        .split(|byte| *byte == 0)
        .filter(|field| !field.is_empty())
        .map(|field| std::str::from_utf8(field).unwrap())
        .collect();
    assert_eq!(fields.len(), 7);
    assert!(fields.contains(&format!("{EXECUTABLE_DIGEST_PREFIX}ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad").as_str()));
    assert!(fields.contains(
        &format!("{EXEC_AUTHORIZATION_KIND_PREFIX}{EXEC_AUTHORIZATION_KIND_SPAWN}").as_str()
    ));
    assert!(fields.contains(&format!("{EXEC_AUTHORIZATION_CLASS_PREFIX}privileged").as_str()));
    assert_eq!(prepared.authorization.len(), 1024);
    let decoded = process_create::decode(&prepared.creation).unwrap();
    assert_eq!(decoded.identity, path);
    assert_eq!(decoded.label, "logger.service");
    let InitialState::Image(image) = decoded.startup else {
        panic!("ELF startup expected")
    };
    assert!(image.stack().windows(4).any(|window| window == b"123\0"));
    assert!(
        !image
            .stack()
            .windows(APPLICATION_PACKAGE_ID_PREFIX.len())
            .any(|window| window == APPLICATION_PACKAGE_ID_PREFIX.as_bytes())
    );
    let changed = plan::prepare(path, &identity(), &["123".into()], b"abcd", [7; 16]).unwrap();
    assert_ne!(prepared.authorization, changed.authorization);
}

#[test]
fn inherited_handles_use_explicit_attenuated_grants_and_long_arguments_are_not_truncated() {
    let inherited = format!(
        "{INHERITED_HANDLE_PREFIX}77:42:{}",
        mnu_abi::HANDLE_RIGHT_SEND
    );
    let argument = "a".repeat(1500);
    let prepared = plan::prepare(
        "/system/services/capability.service",
        &identity(),
        &[inherited, argument.clone()],
        b"image",
        [0; 16],
    )
    .unwrap();
    let request = process_create::decode(&prepared.creation).unwrap();
    let grants: Vec<_> = request.handles().collect();
    assert_eq!(grants.len(), 1);
    assert_eq!(
        (grants[0].key, grants[0].source, grants[0].rights),
        (77, 42, mnu_abi::HANDLE_RIGHT_SEND)
    );
    let InitialState::Image(image) = request.startup else {
        panic!()
    };
    assert!(
        image
            .stack()
            .windows(argument.len())
            .any(|window| window == argument.as_bytes())
    );
    assert!(plan::prepare("/x", &identity(), &["b".repeat(100_000)], b"image", [0; 16]).is_err());
}

#[test]
fn malformed_or_oversized_identity_never_produces_an_authorization_plan() {
    let mut entries = identity();
    entries.swap(0, 1);
    assert!(matches!(
        plan::prepare("/x", &entries, &[], b"image", [0; 16]),
        Err(plan::Error::Identity)
    ));
    let mut entries = identity();
    entries[0].push('\0');
    assert!(matches!(
        plan::prepare("/x", &entries, &[], b"image", [0; 16]),
        Err(plan::Error::Identity)
    ));
    let mut entries = identity();
    entries.pop();
    assert!(plan::prepare("/x", &entries, &[], b"image", [0; 16]).is_err());
    let mut entries = identity();
    entries[0].push_str(&"x".repeat(1024));
    assert!(matches!(
        plan::prepare("/x", &entries, &[], b"image", [0; 16]),
        Err(plan::Error::TooLarge)
    ));
}

#[test]
fn core_startup_has_no_legacy_pathname_creation_or_silent_argument_truncation() {
    let core = include_str!("../../core/src/main.rs");
    let native = include_str!("../../core/src/native_bootstrap.rs");
    assert!(!core.contains("spawn_manifest("));
    assert!(!core.contains("fn encode_spawn_args("));
    assert!(native.contains("create_stopped(image.handle(), &plan.creation)"));
    assert!(native.contains("authorize_exec_for_requester("));
    assert!(native.contains("process_creation::create_with_rollback("));
}
