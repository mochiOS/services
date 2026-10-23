#[allow(dead_code)]
#[path = "../../../user/crates/newlib-runtime/src/thread_lookup.rs"]
mod implementation;

use implementation::TokenCache;

#[test]
fn cache_preserves_token_generation_and_never_reuses_another_revision() {
    let cache = TokenCache::new();
    assert_eq!(cache.get(0x1000, 1), None);
    cache.insert(0x1000, 1, 64);
    assert_eq!(cache.get(0x1000, 1), Some(64));
    assert_eq!(cache.get(0x1000, 2), None);
    // A reused slot must retain the complete generation-bearing token.
    cache.insert(0x1000, 2, 128);
    assert_eq!(cache.get(0x1000, 2), Some(128));
    assert_eq!(cache.get(0x1000, 1), None);
    assert_eq!(cache.get(0x1000, 0), None);
    cache.insert(0x1000, u32::MAX, 64);
    assert_eq!(cache.get(0x1000, u32::MAX), None);
}

#[test]
fn colliding_writers_never_mix_revision_with_another_tokens_generation() {
    let cache = std::sync::Arc::new(TokenCache::new());
    let workers: Vec<_> = (1..=4u32)
        .map(|revision| {
            let cache = cache.clone();
            std::thread::spawn(move || {
                for _ in 0..10000 {
                    let token = revision * 64;
                    cache.insert(0x1000, revision, token);
                    if let Some(observed) = cache.get(0x1000, revision) {
                        assert_eq!(observed, token);
                    }
                }
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
}

#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn lifecycle_revision_saturates_and_permanently_disables_the_cache() {
    let source = include_str!("../../../user/crates/posix-client/src/thread_lifecycle.rs");
    // Place the real implementation in a fixture with access to its private
    // revision, so exhaustion can be checked without billions of mutations.
    let source = source
        .lines()
        .filter(|line| !line.starts_with("//!"))
        .collect::<Vec<_>>()
        .join("\n");
    probe::run(&format!(
        r#"
{source}
fn main() {{
    let gate=Gate::new();
    gate.revision.store(u32::MAX-1,Ordering::SeqCst);
    assert_eq!(gate.stable_revision(),Some(u32::MAX-1));
    drop(gate.try_enter().unwrap());
    assert_eq!(gate.stable_revision(),None);
    drop(gate.try_freeze().unwrap());
    drop(gate.try_enter().unwrap());
    assert_eq!(gate.revision.load(Ordering::SeqCst),u32::MAX);
    assert_eq!(gate.stable_revision(),None);
}}
"#
    ));
}
