extern crate alloc;

mod backend;
mod framebuffer_backend;
mod present;
mod protocol;
mod service;
mod shared_buffer;
mod virtio_gpu_backend;

use mochi_user_platform as platform;

fn main() {
    let _ = mochi_user_platform::logger::init_from_env();
    service::run()
}
