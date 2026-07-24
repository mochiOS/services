const LIB_SOURCE: &str = include_str!("../src/lib.rs");
const CONTROL_WORKER_SOURCE: &str = include_str!("../src/control_worker.rs");
const DISCOVERY_SOURCE: &str = include_str!("../src/discovery.rs");

fn main() {
    assert!(LIB_SOURCE.contains("None => parser.finish()"));
    assert!(LIB_SOURCE.contains("Ok(config) => control_worker::run(config)"));
    assert!(LIB_SOURCE.contains("Err(error) =>"));
    assert!(LIB_SOURCE.contains("control_worker::idle()"));
    assert!(!LIB_SOURCE.contains("discovery::run"));

    assert_eq!(CONTROL_WORKER_SOURCE.matches("discovery::run").count(), 1);
    assert!(!DISCOVERY_SOURCE.contains("input.service"));
    assert!(!DISCOVERY_SOURCE.contains("display.driver"));
    assert!(!DISCOVERY_SOURCE.contains("compositor.service"));
    assert!(!DISCOVERY_SOURCE.contains("tty.service"));
}
