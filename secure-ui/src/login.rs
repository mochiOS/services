use std::cell::Cell;
use std::rc::Rc;

use viewkit::prelude::*;

use crate::authentication::{self, AuthenticationError};
use crate::clock::LoginClock;
use crate::wallpaper::Wallpaper;

const FORM_WIDTH: f32 = 320.0;

pub(crate) struct LoginApp {
    users: Vec<authentication::LoginUser>,
    selected_username: State<String>,
    password: TextFieldInteractionState,
    status: State<String>,
    next_request_id: Rc<Cell<u64>>,
    login_target: Option<mochi_user_platform::service_ready::Target>,
    wallpaper: Wallpaper,
}

impl App for LoginApp {
    type Body = Box<dyn View + 'static>;

    fn new() -> Self {
        let (users, initial_status) = match authentication::list_users(1) {
            Ok(users) => (users, String::new()),
            Err(AuthenticationError::ServiceUnavailable) => {
                (Vec::new(), "Account service is unavailable.".to_owned())
            }
            Err(AuthenticationError::InvalidCredentials | AuthenticationError::Protocol) => {
                (Vec::new(), "The user list could not be loaded.".to_owned())
            }
        };
        let selected_username = users
            .first()
            .map(|user| user.name.clone())
            .unwrap_or_default();
        let password = TextFieldInteractionState::new();
        password.set_focused(!selected_username.is_empty());
        Self {
            users,
            selected_username: State::new(selected_username),
            password,
            status: State::new(initial_status),
            next_request_id: Rc::new(Cell::new(2)),
            login_target: mochi_user_platform::service_ready::take_bootstrap_target(),
            wallpaper: Wallpaper::load_default(),
        }
    }

    fn window(&self) -> WindowOptions {
        WindowOptions::new("Secure UI")
            .resizable(false)
            .secure_overlay(true)
    }

    fn body(&self, _context: &ViewContext) -> Self::Body {
        let password_submit = submit_callback(
            self.selected_username.clone(),
            self.password.clone(),
            self.status.clone(),
            Rc::clone(&self.next_request_id),
            self.login_target,
        );
        let status = self.status.get();
        let selected_username = self.selected_username.get();
        let user_rows = self.users.iter().map(|user| {
            let name = user.name.clone();
            let selected = name == selected_username;
            let selection = self.selected_username.clone();
            let password = self.password.clone();
            let status = self.status.clone();
            Button::new(user.display_name.clone())
                .style(user_button_style(selected))
                .on_click(move || {
                    selection.set(name.clone());
                    password.clear();
                    password.set_focused(true);
                    status.set(String::new());
                })
                .frame(FORM_WIDTH, 44.0)
        });
        let user_list_height = (self.users.len().clamp(1, 3) as f32) * 50.0;
        let user_content_height = (self.users.len().max(1) as f32) * 50.0;
        let user_list: StackChild = if self.users.is_empty() {
            Text::new("No users are available.")
                .font_size(14.0)
                .alignment(TextAlignment::Center)
                .color(Color::WHITE)
                .frame(FORM_WIDTH, 44.0)
        } else {
            Scroll::vertical(
                VStack::new()
                    .alignment(StackAlignment::Center)
                    .gap(StackGap::Small)
                    .children(user_rows)
                    .height(user_content_height),
            )
            .scrollbar(ScrollBarVisibility::Automatic)
            .frame(FORM_WIDTH, user_list_height)
        };

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
            .child(user_list)
            .child(
                HStack::new()
                    .alignment(StackAlignment::Center)
                    .gap(StackGap::Small)
                    .child(
                        TextField::with_interaction(self.password.clone())
                            .placeholder("Password")
                            .size(TextFieldSize::Large)
                            .secure(true)
                            .on_submit(password_submit)
                            .frame(FORM_WIDTH - 52.0, 44.0),
                    )
                    .child(
                        Button::new("")
                            .content(
                                Icon::new(IconName::ChevronRight)
                                    .size(20.0)
                                    .color(Color::WHITE),
                            )
                            .style(ButtonStyle::Custom {
                                background: Color::TRANSPARENT,
                                hovered_background: Color::TRANSPARENT,
                                border: Color::TRANSPARENT,
                                hovered_border: Color::TRANSPARENT,
                                foreground: Color::WHITE,
                            })
                            .enabled(!selected_username.is_empty())
                            .on_click(submit_callback(
                                self.selected_username.clone(),
                                self.password.clone(),
                                self.status.clone(),
                                Rc::clone(&self.next_request_id),
                                self.login_target,
                            ))
                            .frame(44.0, 44.0),
                    )
                    .frame(FORM_WIDTH, 44.0),
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
    selected_username: State<String>,
    password: TextFieldInteractionState,
    status: State<String>,
    next_request_id: Rc<Cell<u64>>,
    login_target: Option<mochi_user_platform::service_ready::Target>,
) -> impl FnMut() {
    move || {
        let name = selected_username.get();
        let mut secret = password.value();
        if name.is_empty() || secret.is_empty() {
            status.set("Select a user and enter the password.".to_owned());
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
            Ok(user) => {
                let Some(target) = login_target else {
                    status.set("Login completion channel is unavailable.".to_owned());
                    return;
                };
                match mochi_user_platform::service_ready::notify(target, 0) {
                    Ok(_) => mochi_user_platform::process::exit(0),
                    Err(_) => status.set(format!("Could not start the session for {}.", user.name)),
                }
            }
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

fn user_button_style(selected: bool) -> ButtonStyle {
    if selected {
        ButtonStyle::Custom {
            background: Color::rgba(255, 255, 255, 224),
            hovered_background: Color::WHITE,
            border: Color::WHITE,
            hovered_border: Color::WHITE,
            foreground: Color::from_rgb_hex(0x202124),
        }
    } else {
        ButtonStyle::Custom {
            background: Color::rgba(20, 24, 30, 112),
            hovered_background: Color::rgba(20, 24, 30, 160),
            border: Color::rgba(255, 255, 255, 96),
            hovered_border: Color::rgba(255, 255, 255, 160),
            foreground: Color::WHITE,
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
