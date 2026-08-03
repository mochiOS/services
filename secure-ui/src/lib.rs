mod authentication;
mod clock;
mod login;
mod setup;
mod wallpaper;

pub fn run() -> Result<(), viewkit::ViewKitError> {
    viewkit::run::<login::LoginApp>()
}
