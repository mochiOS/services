mod authentication;
mod clock;
mod login;
mod network_prompt;
mod portal_prompt;
mod setup;
mod wallpaper;

pub fn run() -> Result<(), viewkit::ViewKitError> {
    if let Some(application) = network_prompt::from_arguments() {
        return network_prompt::run(application);
    }
    if let Some(prompt) = portal_prompt::PromptConfiguration::from_arguments() {
        return portal_prompt::run(prompt);
    }
    viewkit::run::<login::LoginApp>()
}
