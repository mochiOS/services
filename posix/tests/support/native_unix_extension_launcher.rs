//! Opt-in integration fixture. Use the ordinary measured application launch
//! and POSIX child registration; never synthesize grants or a session identity
//! from a kernel PID. The C launcher execs the probe through the native loader.
use super::*;

/// Run the opt-in fixture with normal manifest authorization and wait ownership.
pub(crate) fn run(logger: u64, endpoint: platform::handle::Handle) -> ! {
    let mut arguments = alloc::vec![alloc::format!("{logger}")];
    append_posix_handle(&mut arguments, Some(endpoint));
    let spec = ServiceSpec {
        path: "/system/applications/PortSmoke.app/entry.elf",
        manifest_path: "/system/packages/port-smoke/manifest.toml",
        execution_class: platform::service::ExecutionClass::Unprivileged,
        security_identity: true,
    };
    let process = match spawn_native(spec, "Unix API validation", &arguments, endpoint) {
        Ok(process) => process,
        Err(error) => {
            let _ = platform::logger::write_status_fmt(format_args!(
                "unix-validation launcher failed status={}\n", error.raw()
            ));
            platform::process::exit(1)
        }
    };
    let _ = platform::logger::write_status_fmt(format_args!(
        "unix-validation launcher started pid={}\n", process.process_id()
    ));
    let mut reported_error = false;
    loop {
        match platform::process::handle_status(process.termination_attachment().handle) {
            Ok(status) if status.state == mnu_abi::PROCESS_STATE_EXITED => {
                let _ = platform::logger::write_status_fmt(format_args!(
                    "unix-validation launcher exited status={}\n", status.exit_code
                ));
                drop(process);
                platform::process::exit(status.exit_code)
            }
            Err(error) if !reported_error => {
                let _ = platform::logger::write_status_fmt(format_args!(
                    "unix-validation retaining launcher after status error={}\n", error.raw()
                ));
                reported_error = true;
            }
            _ => {}
        }
        let _ = platform::thread::sleep_milliseconds(2);
    }
}
