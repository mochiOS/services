#[cfg(mochios_presentation_probe_307)]
#[path = "../../posix/tests/native_presentation_ui_307.rs"]
mod presentation_probe;

fn main() -> Result<(), viewkit::ViewKitError> {
    let _ = mochi_user_platform::logger::init_from_env();
    #[cfg(mochios_presentation_probe_307)]
    if std::env::args().any(|argument| argument == "--presentation-probe-server") {
        return presentation_probe::run();
    }
    report_missing_capability("account.authenticate");
    report_missing_capability("account.other.modify");
    report_missing_capability("account.other.read");
    report_missing_capability("fs.write.all");
    report_missing_capability("ipc.server");
    report_missing_capability("settings.write");
    report_missing_capability("window.secure-overlay");
    secure_ui::run()
}

fn report_missing_capability(capability: &str) {
    let bytes = capability.as_bytes();
    if !matches!(
        mochi_user_platform::capability::query(bytes.as_ptr() as u64, bytes.len() as u64),
        Ok(1)
    ) {
        mochi_user_platform::logln!("secure-ui.service: missing runtime capability {capability}");
    }
}
