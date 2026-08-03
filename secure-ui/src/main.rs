fn main() -> Result<(), viewkit::ViewKitError> {
    report_missing_capability("account.authenticate");
    report_missing_capability("account.other.modify");
    report_missing_capability("account.other.read");
    report_missing_capability("fs.write.all");
    report_missing_capability("ipc.server");
    report_missing_capability("window.secure-overlay");
    secure_ui::run()
}

fn report_missing_capability(capability: &str) {
    let bytes = capability.as_bytes();
    if !matches!(
        mochi_user_platform::capability::query(bytes.as_ptr() as u64, bytes.len() as u64),
        Ok(1)
    ) {
        eprintln!("secure-ui.service: missing runtime capability {capability}");
    }
}
