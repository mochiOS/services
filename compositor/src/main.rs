extern crate alloc;

mod client;
mod context_menu;
mod cursor;
mod decoration;
mod display;
mod geometry;
mod gpu_compositor;
mod input;
mod protocol;
mod renderer;
mod server;
mod state;
mod surface;
mod window;

use mochi_user_platform as platform;

fn main() {
    let _ = platform::logger::init_from_env();
    server::run()
}
