mod authentication;
mod clock;
mod login;
mod portal_prompt;
mod setup;
mod wallpaper;

pub fn run() -> Result<(), viewkit::ViewKitError> {
    if let Some(prompt) = portal_prompt::PromptConfiguration::from_arguments() {
        return portal_prompt::run(prompt);
    }
    viewkit::run::<login::LoginApp>()
}
