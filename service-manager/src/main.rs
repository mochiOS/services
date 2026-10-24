#[cfg(not(mochios_inet_socket_probe_213))]
fn main() {
    service_manager::run()
}
#[cfg(mochios_inet_socket_probe_213)]
include!("../../posix/tests/support/inet_manager_entry.inc");
