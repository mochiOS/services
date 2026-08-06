#[cfg(target_os = "mochios")]
fn main() {
    mboot_agent::runtime::run()
}

#[cfg(not(target_os = "mochios"))]
fn main() {}
