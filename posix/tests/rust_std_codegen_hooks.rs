#[test]
fn fork_core_has_the_non_unwinding_null_reference_hook_required_by_the_pinned_compiler() {
    // Source contract only. The real verification is a mochiOS-target check
    // with build-std=std,panic_abort; host std cannot prove native codegen.
    let source = include_str!("../../../libraries/rust/library/core/src/panicking.rs");
    let hook = source
        .split("#[lang = \"panic_null_reference_constructed\"]")
        .nth(1)
        .expect("pinned compiler's CheckNull pass needs this lang item")
        .split("#[lang = \"panic_invalid_enum_construction\"]")
        .next()
        .unwrap();
    assert!(hook.contains("#[rustc_nounwind]"));
    assert!(hook.contains("fn panic_null_reference_constructed() -> !"));
    assert!(hook.contains("super::intrinsics::abort()"));
    assert!(hook.contains("panic_nounwind_fmt("));
    assert!(hook.contains("null reference produced"));
    // Keep the fork's own compiler aware of the library hook too, rather
    // than only making build-std work with the external pinned compiler.
    let lang_items = include_str!("../../../libraries/rust/compiler/rustc_hir/src/lang_items.rs");
    assert!(lang_items.contains(
        "PanicNullReferenceConstructed, sym::panic_null_reference_constructed, panic_null_reference_constructed, Target::Fn, GenericRequirement::None;"
    ));
    let symbols = include_str!("../../../libraries/rust/compiler/rustc_span/src/symbol.rs");
    assert!(symbols.contains("        panic_null_reference_constructed,"));
}
