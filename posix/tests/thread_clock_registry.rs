use mochios_posix_client::thread_clock::{Error, Registry, Target, FIRST_ID};
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

fn target(thread: u32, native_thread: u64) -> Target {
    Target {
        thread,
        native_thread,
    }
}

#[test]
fn clock_ids_are_stable_per_lifetime_and_never_retarget_reused_slots() {
    let mut registry = Registry::<2>::new();
    assert_eq!(
        registry.get_or_insert(target(0, 1)),
        Err(Error::InvalidTarget)
    );
    assert_eq!(
        registry.get_or_insert(target(64, 0)),
        Err(Error::InvalidTarget)
    );
    let a = registry.get_or_insert(target(64, 100)).unwrap();
    assert_eq!(a, FIRST_ID);
    assert_eq!(registry.get_or_insert(target(64, 100)), Ok(a));
    let b = registry.get_or_insert(target(65, u64::MAX)).unwrap();
    assert_eq!(registry.get_or_insert(target(66, 300)), Err(Error::Full));
    registry.retire_native(100);
    let c = registry.get_or_insert(target(128, 101)).unwrap();
    assert!(c > b);
    assert_eq!(registry.resolve(a), None);
    assert_eq!(registry.resolve(b), Some(target(65, u64::MAX)));
    registry.retain(|record| record.native_thread != 101);
    let d = registry.get_or_insert(target(128, 102)).unwrap();
    assert!(d > c);
    assert_eq!(registry.resolve(c), None);
    for invalid in [0, 1, 2, 3, 4, 17, FIRST_ID - 1] {
        assert_eq!(registry.resolve(invalid), None);
    }
}

#[test]
fn fork_invalidates_copied_ids_without_reusing_them_or_changing_parent_records() {
    let mut parent = Registry::<2>::new();
    let old = parent.get_or_insert(target(64, 100)).unwrap();
    let mut child = parent.clone();
    child.clear_for_fork();
    assert_eq!(child.resolve(old), None);
    let new = child.get_or_insert(target(64, 200)).unwrap();
    assert!(new > old);
    assert_eq!(parent.resolve(old), Some(target(64, 100)));
    for _ in 0..1000 {
        child.retire_native(200);
        let next = child.get_or_insert(target(64, 200)).unwrap();
        assert!(next > new);
        assert_eq!(child.resolve(new), None);
    }
}

#[test]
fn actual_full_width_clock_nonce_exhaustion_never_wraps_into_builtin_clocks() {
    let mut program = String::from("#![allow(dead_code)]\nmod thread {\n");
    program.push_str(include_str!(
        "../../../user/crates/posix-client/src/thread.rs"
    ));
    program.push_str("}\nmod clock {\n");
    program.push_str(include_str!(
        "../../../user/crates/posix-client/src/thread_clock.rs"
    ));
    program.push_str(r#"
pub fn run(){
 let mut registry=Registry::<1>::new();registry.last=u64::MAX-1;
 assert_eq!(registry.get_or_insert(Target{thread:64,native_thread:100}),Ok(u64::MAX));
 registry.clear_for_fork();assert_eq!(registry.get_or_insert(Target{thread:64,native_thread:200}),Err(Error::Exhausted));
 assert_eq!(registry.last,u64::MAX);assert_eq!(registry.resolve(0),None);
}
}
fn main(){clock::run()}
"#);
    probe::run(&program);
}
