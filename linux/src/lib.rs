mod codec;
#[cfg(target_os = "mochios")]
mod compositor;
#[cfg(target_os = "mochios")]
mod host;
mod input;
#[cfg(target_os = "mochios")]
mod portal;
#[cfg(target_os = "mochios")]
mod runtime;

#[cfg(target_os = "mochios")]
pub fn run() -> ! {
    let _ = mochi_user_platform::logger::init_from_env();
    runtime::run()
}

#[cfg(not(target_os = "mochios"))]
pub fn run() -> ! {
    panic!("linux.service can only run on mochiOS")
}
