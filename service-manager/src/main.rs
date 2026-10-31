#[cfg(not(any(mochios_inet_socket_probe_213, mochios_input_authority_probe_302,mochios_consent_input_probe_306,mochios_presentation_probe_307)))]
fn main() {
    service_manager::run()
}
#[cfg(any(mochios_inet_socket_probe_213, mochios_input_authority_probe_302,mochios_consent_input_probe_306,mochios_presentation_probe_307))]
include!("../../posix/tests/support/inet_manager_entry.inc");
