extern crate alloc;

mod backdrop;
mod client;
mod context_menu;
mod cursor;
mod decoration;
mod display;
mod fps_overlay;
mod frame_buffer;
mod geometry;
mod gpu_compositor;
mod input;
mod protocol;
mod received_buffer;
mod renderer;
mod server;
mod startup;
mod state;
mod surface;
mod window;

use mochi_user_platform as platform;

fn main() {
    let _ = platform::logger::init_from_env();
    server::run()
}
