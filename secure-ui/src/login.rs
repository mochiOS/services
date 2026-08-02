use std::cell::Cell;
use std::rc::Rc;

use viewkit::prelude::*;

use crate::authentication::{self, AuthenticationError};
use crate::clock::LoginClock;
use crate::wallpaper::Wallpaper;

const FORM_WIDTH: f32 = 320.0;

pub(crate) struct LoginApp {
    username: TextFieldInteractionState,
    password: TextFieldInteractionState,
    status: State<String>,
    next_request_id: Rc<Cell<u64>>,
    wallpaper: Wallpaper,
}

impl App for LoginApp {
    type Body = Box<dyn View + 'static>;

    fn new() -> Self {
        let username = TextFieldInteractionState::new();
        username.set_focused(true);
        Self {
            username,
            password: TextFieldInteractionState::new(),
            status: State::new(String::new()),
            next_request_id: Rc::new(Cell::new(1)),
            wallpaper: Wallpaper::load_default(),
        }
    }

    fn window(&self) -> WindowOptions {
        WindowOptions::new("Secure UI")
            .resizable(false)
            .secure_overlay(true)
    }

    fn body(&self, _context: &ViewContext) -> Self::Body {
        let username_focus = self.username.clone();
        let password_focus = self.password.clone();
        let submit_username = move || {
            username_focus.set_focused(false);
            password_focus.set_focused(true);
        };
        let password_submit = submit_callback(
            self.username.clone(),
            self.password.clone(),
            self.status.clone(),
            Rc::clone(&self.next_request_id),
        );
        let status = self.status.get();

        let form = VStack::new()
            .alignment(StackAlignment::Center)
            .gap(StackGap::Small)
            .child(
                Text::new("Sign in")
                    .font_size(24.0)
                    .line_height(32.0)
                    .weight(600)
                    .alignment(TextAlignment::Center)
                    .color(Color::WHITE)
                    .frame(FORM_WIDTH, 36.0),
            )
            .child(
                TextField::with_interaction(self.username.clone())
                    .placeholder("User name")
                    .size(TextFieldSize::Large)
                    .on_submit(submit_username)
                    .frame(FORM_WIDTH, 44.0),
            )
            .child(
                TextField::with_interaction(self.password.clone())
                    .placeholder("Password")
                    .size(TextFieldSize::Large)
                    .secure(true)
                    .on_submit(password_submit)
                    .frame(FORM_WIDTH, 44.0),
            )
            .child(
                Button::new("Log In")
                    .color(ButtonColor::Accent)
                    .on_click(submit_callback(
                        self.username.clone(),
                        self.password.clone(),
                        self.status.clone(),
                        Rc::clone(&self.next_request_id),
                    ))
                    .frame(FORM_WIDTH, 42.0),
            )
            .child(
                Text::new(status)
                    .font_size(13.0)
                    .line_height(20.0)
                    .weight(500)
                    .alignment(TextAlignment::Center)
                    .color(Color::WHITE)
                    .frame(FORM_WIDTH, 24.0),
            );

        let clock = Padding::only(42.0, 28.0, 54.0, 28.0).content(
            VStack::new()
                .alignment(StackAlignment::Center)
                .gap(StackGap::None)
                .child(LoginClock.frame(520.0, 118.0))
                .child(Spacer::new()),
        );
        let centered_form = Padding::symmetric(28.0, 54.0).content(
            VStack::new()
                .alignment(StackAlignment::Center)
                .gap(StackGap::None)
                .child(Spacer::new())
                .child(form)
                .child(Spacer::new()),
        );

        Box::new(
            ZStack::new()
                .alignment(ZStackAlignment::Center)
                .child(self.wallpaper.clone())
                .child(clock)
                .child(centered_form),
        )
    }
}

fn submit_callback(
    username: TextFieldInteractionState,
    password: TextFieldInteractionState,
    status: State<String>,
    next_request_id: Rc<Cell<u64>>,
) -> impl FnMut() {
    move || {
        let name = username.value();
        let mut secret = password.value();
        if name.is_empty() || secret.is_empty() {
            status.set("Enter your user name and password.".to_owned());
            clear_string(&mut secret);
            password.clear();
            return;
        }
        status.set("Signing in...".to_owned());
        let request_id = next_request_id.get();
        next_request_id.set(request_id.wrapping_add(1).max(1));
        let result = authentication::authenticate(request_id, &name, secret.as_bytes());
        clear_string(&mut secret);
        password.clear();
        match result {
            Ok(user) => status.set(format!("Signed in as {}", user.name)),
            Err(AuthenticationError::InvalidCredentials) => {
                status.set("The user name or password is incorrect.".to_owned())
            }
            Err(AuthenticationError::ServiceUnavailable) => {
                status.set("Account service is unavailable.".to_owned())
            }
            Err(AuthenticationError::Protocol) => {
                status.set("Authentication could not be completed.".to_owned())
            }
        }
    }
}

fn clear_string(value: &mut String) {
    if value.is_empty() {
        return;
    }
    value.replace_range(.., &"\0".repeat(value.len()));
    value.clear();
}
