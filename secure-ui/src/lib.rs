mod authentication;
mod clock;
mod login;
mod network_prompt;
mod permission_server;
mod portal_prompt;
mod setup;
mod wallpaper;

pub fn run() -> Result<(), viewkit::ViewKitError> {
    if permission_server::requested() {
        return permission_server::run();
    }
    if let Some(application) = network_prompt::from_arguments() {
        return network_prompt::run(application);
    }
    if let Some(prompt) = portal_prompt::PromptConfiguration::from_arguments() {
        return portal_prompt::run(prompt);
    }
    viewkit::run::<login::LoginApp>()
}
