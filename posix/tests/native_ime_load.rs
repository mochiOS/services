//! Compare std I/O and the production IME engine under the same native runtime.
#[cfg(target_os = "mochios")]
#[allow(dead_code)]
#[path = "native_rust_dictionary_read.rs"]
mod dictionary_io;

#[cfg(target_os = "mochios")]
fn main() {
    dictionary_io::run().expect("dictionary I/O failed before parser initialization");
    eprintln!("native-ime-load: opening production engine");
    let start = std::time::Instant::now();
    let engine = mochios_ime_engine::Engine::open(input::ime::DICTIONARY_PATH)
        .expect("production dictionary could not be initialized");
    eprintln!(
        "native-ime-load: loaded elapsed_ms={}",
        start.elapsed().as_millis()
    );
    let candidates = engine.candidates("こんにちは", 5);
    assert!(!candidates.is_empty());
    eprintln!("native-ime-load: PASS candidate={}", candidates[0].text);
}

#[cfg(not(target_os = "mochios"))]
fn main() {
    eprintln!("native-ime-load: SKIP (requires mochiOS)");
}
