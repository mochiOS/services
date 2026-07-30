extern crate alloc;

mod backend;
mod framebuffer_backend;
mod present;
mod protocol;
mod service;
mod virtio_gpu_backend;

fn main() {
    let _ = mochi_user_platform::logger::init_from_env();
    service::run()
}
