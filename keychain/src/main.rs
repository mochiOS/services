fn main() {
    #[cfg(target_os = "linux")]
    let result = keychain_service::host::run();
    #[cfg(target_os = "mochios")]
    let result = keychain_service::native::run();
    #[cfg(not(any(target_os = "linux", target_os = "mochios")))]
    let result: Result<(), mochios_keychain_protocol::Error> =
        Err(mochios_keychain_protocol::Error::Unavailable);
    if let Err(error) = result {
        eprintln!("keychain.service: {error}");
        std::process::exit(1);
    }
}
