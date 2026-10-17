//! Explicitly enabled boot debugging, never a normal-build log disclosure.
//! The receiver calls this only after control messages, attachments, and UTF-8
//! have been validated. Diagnostic output must not recurse through the logger.

pub(super) fn mirror_boot_line(line: &[u8]) {
    #[cfg(feature = "early-serial-diagnostics")]
    {
        let _ = mochi_user_platform::io::stderr(line);
    }
    #[cfg(not(feature = "early-serial-diagnostics"))]
    let _ = line;
}
