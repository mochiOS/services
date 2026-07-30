extern crate alloc;

mod client;
mod cursor;
mod decoration;
mod display;
mod geometry;
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
