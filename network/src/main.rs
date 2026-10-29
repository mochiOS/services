extern crate alloc;

mod datagram;
mod datagram_authority;
mod driver;
mod http;
mod reply;
mod resolver;
mod resolver_rpc;
mod resolver_provider;
mod resolver_backend;
mod interfaces;
mod service;
mod stack;
mod stream;
mod stream_provider;
mod status;
mod tls;
#[cfg(mochios_dns_replies_probe_280)]
#[path = "../../posix/tests/native_dns_replies.rs"]
mod native_dns_replies;

getrandom::register_custom_getrandom!(mochios_tls_client::platform_getrandom);

fn main() {
    let _ = mochi_user_platform::logger::init_from_env();
    #[cfg(mochios_dns_replies_probe_280)]
    native_dns_replies::run();
    #[cfg(not(mochios_dns_replies_probe_280))]
    service::run()
}
