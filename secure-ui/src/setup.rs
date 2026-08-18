use std::cell::Cell;
use std::fs;
use std::io;
use std::os::unix::fs::{PermissionsExt, chown};
use std::path::Path;
use std::rc::Rc;

use mochi_user_platform::mboot_wifi::{self as wifi, WifiNetwork, WifiStatus};
use mochios_user_database::{FIRST_REGULAR_UID, UserRecord};
use mochios_user_protocol::{AddUser, MAX_MESSAGE_LEN, RemoveUser, SetPassword, Status};
use viewkit::prelude::*;

use crate::authentication::{self, AuthenticationError};

const CONTENT_WIDTH: f32 = 420.0;
const QR_IMAGE_SIZE: f32 = 152.0;
const PRIVACY_QR_PATH: &str = "/system/resources/startup/qr-privacy.png";
const TERMS_QR_PATH: &str = "/system/resources/startup/qr-terms.png";
const HOME_DIRECTORIES: [&str; 6] = [
    "Desktop",
    "Documents",
    "Downloads",
    "Movies",
    "Music",
    "Pictures",
];

pub(crate) struct AccountSetup {
    page: State<usize>,
    full_name: TextFieldInteractionState,
    account_name: TextFieldInteractionState,
    password: TextFieldInteractionState,
    password_confirmation: TextFieldInteractionState,
    wifi_password: TextFieldInteractionState,
    wifi_status: State<WifiStatus>,
    wifi_networks: State<Vec<WifiNetwork>>,
    wifi_selected: State<usize>,
    network_message: State<String>,
    status: State<String>,
    created_display_name: State<String>,
    created_identity: State<Option<mochi_user_platform::service_ready::SessionIdentity>>,
    privacy_qr: Option<ImageData>,
    terms_qr: Option<ImageData>,
}

impl AccountSetup {
    pub(crate) fn new() -> Self {
        Self {
            page: State::new(0),
            full_name: TextFieldInteractionState::new(),
            account_name: TextFieldInteractionState::new(),
            password: TextFieldInteractionState::new(),
            password_confirmation: TextFieldInteractionState::new(),
            wifi_password: TextFieldInteractionState::new(),
            wifi_status: State::new(wifi::status().unwrap_or_default()),
            wifi_networks: State::new(Vec::new()),
            wifi_selected: State::new(0),
            network_message: State::new(String::new()),
            status: State::new(String::new()),
            created_display_name: State::new(String::new()),
            created_identity: State::new(None),
            privacy_qr: ImageData::from_path(PRIVACY_QR_PATH).ok(),
            terms_qr: ImageData::from_path(TERMS_QR_PATH).ok(),
        }
    }

    pub(crate) fn body(
        &self,
        next_request_id: Rc<Cell<u64>>,
        login_target: Option<mochi_user_platform::service_ready::Target>,
    ) -> Box<dyn View + 'static> {
        match self.page.get() {
            0 => self.welcome_page(),
            1 => self.terms_page(),
            2 => self.network_page(),
            3 => self.account_page(next_request_id),
            _ => self.completed_page(login_target),
        }
    }

    fn page_header(title: &'static str, subtitle: &'static str) -> impl View + 'static {
        VStack::new()
            .alignment(StackAlignment::Center)
            .gap(StackGap::ExtraSmall)
            .child(
                Text::new(title)
                    .font_size(28.0)
                    .line_height(36.0)
                    .weight(700)
                    .alignment(TextAlignment::Center)
                    .color(Color::WHITE),
            )
            .child(
                Text::new(subtitle)
                    .font_size(13.0)
                    .line_height(20.0)
                    .alignment(TextAlignment::Center)
                    .color(Color::rgba(255, 255, 255, 216)),
            )
    }

    fn progress(&self) -> StackChild {
        let page = self.page.get();
        HStack::new()
            .alignment(StackAlignment::Center)
            .distribution(StackDistribution::Center)
            .gap(StackGap::Small)
            .child(progress_dot(page == 0))
            .child(progress_dot(page == 1))
            .child(progress_dot(page == 2))
            .child(progress_dot(page == 3))
            .child(progress_dot(page >= 4))
            .frame(CONTENT_WIDTH, 12.0)
    }

    fn welcome_page(&self) -> Box<dyn View + 'static> {
        let page = self.page.clone();
        Box::new(
            VStack::new()
                .alignment(StackAlignment::Center)
                .gap(StackGap::Large)
                .child(Self::page_header(
                    "Welcome to mochiOS",
                    "Let's prepare this device for you",
                ))
                .child(
                    Text::new("Let’s get your device ready!")
                        .font_size(12.0)
                        .line_height(19.0)
                        .alignment(TextAlignment::Center)
                        .color(Color::rgba(255, 255, 255, 216))
                        .frame(CONTENT_WIDTH, 48.0),
                )
                .child(
                    Button::new("Start Setup")
                        .style(ButtonStyle::Accent)
                        .on_click(move || page.set(1))
                        .frame(CONTENT_WIDTH, 44.0),
                )
                .child(self.progress()),
        )
    }

    fn terms_page(&self) -> Box<dyn View + 'static> {
        let page = self.page.clone();
        let wifi_status = self.wifi_status.clone();
        let wifi_networks = self.wifi_networks.clone();
        let network_message = self.network_message.clone();
        Box::new(
            VStack::new()
                .alignment(StackAlignment::Center)
                .gap(StackGap::Medium)
                .child(Self::page_header(
                    "Terms and Privacy",
                    "Review both documents before continuing",
                ))
                .child(
                    HStack::new()
                        .alignment(StackAlignment::Center)
                        .gap(StackGap::Medium)
                        .child(qr_card(
                            self.terms_qr.clone(),
                            "Terms of Use",
                            "policy.mochios.org/terms/",
                        ))
                        .child(qr_card(
                            self.privacy_qr.clone(),
                            "Privacy Policy",
                            "policy.mochios.org/privacy/",
                        )),
                )
                .child(
                    Text::new(
                        "Selecting Agree confirms that you have reviewed and accepted both documents.",
                    )
                    .font_size(11.0)
                    .line_height(18.0)
                    .alignment(TextAlignment::Center)
                    .color(Color::rgba(255, 255, 255, 216))
                    .frame(500.0, 38.0),
                )
                .child(
                    Button::new("Agree and Continue")
                        .style(ButtonStyle::Accent)
                        .on_click(move || {
                            page.set(2);
                            refresh_wifi(&wifi_status, &wifi_networks, &network_message);
                        })
                        .frame(CONTENT_WIDTH, 44.0),
                )
                .child(self.progress()),
        )
    }

    fn network_page(&self) -> Box<dyn View + 'static> {
        let host = self.wifi_status.get();
        let networks = self.wifi_networks.get();
        let selected_index = self
            .wifi_selected
            .get()
            .min(networks.len().saturating_sub(1));
        let selected_network = networks.get(selected_index).cloned();

        let mut rows = VStack::new()
            .alignment(StackAlignment::Stretch)
            .gap(StackGap::ExtraSmall);
        if networks.is_empty() {
            rows = rows.child(
                Text::new(if host.available {
                    "No Wi-Fi networks found. Select Scan to try again."
                } else {
                    "Wi-Fi is unavailable. You can continue using Ethernet or configure it later."
                })
                .font_size(12.0)
                .line_height(19.0)
                .alignment(TextAlignment::Center)
                .color(Color::rgba(255, 255, 255, 216))
                .frame(CONTENT_WIDTH, 72.0),
            );
        } else {
            for (index, network) in networks.iter().enumerate() {
                let selection = self.wifi_selected.clone();
                let password = self.wifi_password.clone();
                let secured = network.secured;
                rows = rows.child(
                    Button::new(network.ssid.clone())
                        .content(
                            HStack::new()
                                .alignment(StackAlignment::Center)
                                .distribution(StackDistribution::SpaceBetween)
                                .child(
                                    Text::new(network.ssid.clone())
                                        .font_size(13.0)
                                        .line_height(20.0)
                                        .weight(600),
                                )
                                .child(
                                    Text::new(format!(
                                        "{} · {} dBm",
                                        if network.secured { "Secured" } else { "Open" },
                                        network.signal
                                    ))
                                    .font_size(10.0)
                                    .line_height(16.0)
                                    .color(Theme::current().colors.text_secondary),
                                ),
                        )
                        .style(if index == selected_index {
                            ButtonStyle::Standard
                        } else {
                            ButtonStyle::Ghost
                        })
                        .alignment(ZStackAlignment::Leading)
                        .on_click(move || {
                            selection.set(index);
                            password.clear();
                            password.set_focused(secured);
                        })
                        .height(40.0),
                );
            }
        }

        let refresh_host = self.wifi_status.clone();
        let refresh_networks = self.wifi_networks.clone();
        let refresh_message = self.network_message.clone();
        let scan = Button::new("Scan")
            .style(ButtonStyle::Standard)
            .on_click(move || refresh_wifi(&refresh_host, &refresh_networks, &refresh_message))
            .frame(76.0, 36.0);

        let connect_networks = self.wifi_networks.clone();
        let connect_selection = self.wifi_selected.clone();
        let connect_password = self.wifi_password.clone();
        let connect_host = self.wifi_status.clone();
        let connect_message = self.network_message.clone();
        let connect = Button::new("Connect")
            .style(ButtonStyle::Accent)
            .enabled(selected_network.is_some())
            .on_click(move || {
                let networks = connect_networks.get();
                let Some(network) = networks.get(connect_selection.get()) else {
                    connect_message.set("Select a Wi-Fi network.".to_owned());
                    return;
                };
                let mut password = connect_password.value();
                if network.secured && !(8..=63).contains(&password.len()) {
                    connect_message.set("Wi-Fi passwords must be 8 to 63 bytes.".to_owned());
                    clear_string(&mut password);
                    return;
                }
                match wifi::connect(network, &password) {
                    Ok(()) => {
                        connect_password.clear();
                        connect_message.set(format!("Connecting to {}...", network.ssid));
                        if let Ok(status) = wifi::status() {
                            connect_host.set(status);
                        }
                    }
                    Err(error) => connect_message.set(format!("Unable to connect: {error}")),
                }
                clear_string(&mut password);
            })
            .frame(96.0, 36.0);

        let page = self.page.clone();
        let full_name = self.full_name.clone();
        let status_summary = if host.connected {
            format!("Connected to {}", host.ssid)
        } else if host.available {
            "Choose a Wi-Fi network or continue without one.".to_owned()
        } else {
            "No wireless adapter is available. Network setup can be completed later.".to_owned()
        };

        Box::new(
            VStack::new()
                .alignment(StackAlignment::Center)
                .gap(StackGap::Small)
                .child(Self::page_header(
                    "Connect to a Network",
                    "Internet access keeps trust data and system services up to date",
                ))
                .child(
                    Text::new(status_summary)
                        .font_size(11.0)
                        .line_height(18.0)
                        .alignment(TextAlignment::Center)
                        .color(Color::rgba(255, 255, 255, 216))
                        .frame(CONTENT_WIDTH, 24.0),
                )
                .child(
                    Card::new()
                        .content(Scroll::vertical(rows))
                        .frame(CONTENT_WIDTH, 194.0),
                )
                .child(
                    HStack::new()
                        .alignment(StackAlignment::Center)
                        .gap(StackGap::Small)
                        .child(
                            TextField::with_interaction(self.wifi_password.clone())
                                .placeholder(
                                    if selected_network
                                        .as_ref()
                                        .is_some_and(|network| network.secured)
                                    {
                                        "Wi-Fi Password"
                                    } else {
                                        "No password required"
                                    },
                                )
                                .secure(true)
                                .enabled(
                                    selected_network
                                        .as_ref()
                                        .is_some_and(|network| network.secured),
                                )
                                .frame(240.0, 36.0),
                        )
                        .child(scan)
                        .child(connect)
                        .frame(CONTENT_WIDTH, 36.0),
                )
                .child(status_text(self.network_message.get()))
                .child(
                    Button::new(if host.connected {
                        "Continue"
                    } else {
                        "Continue Without Network"
                    })
                    .style(ButtonStyle::Accent)
                    .on_click(move || {
                        page.set(3);
                        full_name.set_focused(true);
                    })
                    .frame(CONTENT_WIDTH, 44.0),
                )
                .child(self.progress()),
        )
    }

    fn account_page(&self, next_request_id: Rc<Cell<u64>>) -> Box<dyn View + 'static> {
        let password_notice = if self.password.value().is_empty() {
            "Warning: a blank password leaves this account unprotected."
        } else {
            ""
        };
        let submit = submit_callback(
            self.full_name.clone(),
            self.account_name.clone(),
            self.password.clone(),
            self.password_confirmation.clone(),
            self.status.clone(),
            self.created_display_name.clone(),
            self.created_identity.clone(),
            self.page.clone(),
            Rc::clone(&next_request_id),
        );
        Box::new(
            VStack::new()
                .alignment(StackAlignment::Center)
                .gap(StackGap::Small)
                .child(Self::page_header(
                    "Create Your Account",
                    "This account is stored locally on this device",
                ))
                .child(setup_field("Full Name", self.full_name.clone(), false))
                .child(setup_field(
                    "Account Name",
                    self.account_name.clone(),
                    false,
                ))
                .child(setup_field("Password", self.password.clone(), true))
                .child(
                    TextField::with_interaction(self.password_confirmation.clone())
                        .placeholder("Verify Password")
                        .size(TextFieldSize::Large)
                        .secure(true)
                        .on_submit(submit_callback(
                            self.full_name.clone(),
                            self.account_name.clone(),
                            self.password.clone(),
                            self.password_confirmation.clone(),
                            self.status.clone(),
                            self.created_display_name.clone(),
                            self.created_identity.clone(),
                            self.page.clone(),
                            next_request_id,
                        ))
                        .frame(CONTENT_WIDTH, 44.0),
                )
                .child(
                    Text::new(password_notice)
                        .font_size(10.0)
                        .line_height(16.0)
                        .alignment(TextAlignment::Center)
                        .color(Color::from_rgb_hex(0xffcf70))
                        .frame(CONTENT_WIDTH, 18.0),
                )
                .child(
                    Button::new("Create Account")
                        .style(ButtonStyle::Accent)
                        .on_click(submit)
                        .frame(CONTENT_WIDTH, 44.0),
                )
                .child(status_text(self.status.get()))
                .child(self.progress()),
        )
    }

    fn completed_page(
        &self,
        login_target: Option<mochi_user_platform::service_ready::Target>,
    ) -> Box<dyn View + 'static> {
        let status = self.status.clone();
        let identity = self.created_identity.get();
        let display_name = self.created_display_name.get();
        let message = if display_name.is_empty() {
            "Your account is ready.".to_owned()
        } else {
            format!("Welcome, {display_name}.")
        };
        Box::new(
            VStack::new()
                .alignment(StackAlignment::Center)
                .gap(StackGap::Large)
                .child(
                    ZStack::new()
                        .alignment(ZStackAlignment::Center)
                        .child(
                            Ellipse::new()
                                .color(EllipseColor::Custom(Color::WHITE))
                                .frame(72.0, 72.0),
                        )
                        .child(
                            Icon::new(IconName::Check)
                                .size(34.0)
                                .color(Color::from_rgb_hex(0x151518)),
                        ),
                )
                .child(Self::page_header(
                    "Setup Complete",
                    "mochiOS is ready to use",
                ))
                .child(
                    Text::new(message)
                        .font_size(13.0)
                        .line_height(20.0)
                        .alignment(TextAlignment::Center)
                        .color(Color::WHITE),
                )
                .child(
                    Button::new("Get Started!")
                        .style(ButtonStyle::Accent)
                        .on_click(move || finish_setup(login_target, identity, &status))
                        .frame(CONTENT_WIDTH, 44.0),
                )
                .child(status_text(self.status.get()))
                .child(self.progress()),
        )
    }
}

fn progress_dot(active: bool) -> StackChild {
    Ellipse::new()
        .color(EllipseColor::Custom(if active {
            Color::WHITE
        } else {
            Color::rgba(255, 255, 255, 96)
        }))
        .frame(
            if active { 9.0 } else { 7.0 },
            if active { 9.0 } else { 7.0 },
        )
}

fn refresh_wifi(
    status: &State<WifiStatus>,
    networks: &State<Vec<WifiNetwork>>,
    message: &State<String>,
) {
    let mut current = match wifi::status() {
        Ok(current) => current,
        Err(error) => {
            networks.set(Vec::new());
            message.set(format!("Wi-Fi setup is unavailable: {error}"));
            return;
        }
    };
    if !current.available {
        status.set(current);
        networks.set(Vec::new());
        message.set("No supported wireless adapter was detected.".to_owned());
        return;
    }
    if !current.enabled {
        if let Err(error) = wifi::set_enabled(true) {
            status.set(current);
            networks.set(Vec::new());
            message.set(format!("Unable to enable Wi-Fi: {error}"));
            return;
        }
        if let Ok(updated) = wifi::status() {
            current = updated;
        }
    }
    status.set(current);
    match wifi::scan() {
        Ok(found) => {
            let count = found.len();
            networks.set(found);
            message.set(if count == 0 {
                "No Wi-Fi networks were found.".to_owned()
            } else {
                format!("Found {count} Wi-Fi networks.")
            });
        }
        Err(error) => {
            networks.set(Vec::new());
            message.set(format!("Unable to scan for Wi-Fi: {error}"));
        }
    }
}

fn qr_card(image: Option<ImageData>, title: &'static str, address: &'static str) -> StackChild {
    let qr = match image {
        Some(image) => Image::new(image)
            .content_mode(ImageContentMode::Fit)
            .frame(QR_IMAGE_SIZE, QR_IMAGE_SIZE),
        None => Text::new("QR code unavailable. please report this issue to the mochiOS team.")
            .font_size(11.0)
            .alignment(TextAlignment::Center)
            .color(Color::from_rgb_hex(0x6e6e73))
            .frame(QR_IMAGE_SIZE, QR_IMAGE_SIZE),
    };
    Card::new()
        .color(RectangleColor::Custom(Color::WHITE))
        .content(
            Padding::all(18.0).content(
                VStack::new()
                    .alignment(StackAlignment::Center)
                    .gap(StackGap::ExtraSmall)
                    .child(qr)
                    .child(
                        Text::new(title)
                            .font_size(14.0)
                            .line_height(20.0)
                            .weight(700)
                            .alignment(TextAlignment::Center)
                            .color(Color::from_rgb_hex(0x151518)),
                    )
                    .child(
                        Text::new(address)
                            .font_size(9.0)
                            .line_height(14.0)
                            .alignment(TextAlignment::Center)
                            .color(Color::from_rgb_hex(0x6e6e73)),
                    ),
            ),
        )
        .frame(216.0, 238.0)
}

fn setup_field(
    placeholder: &'static str,
    interaction: TextFieldInteractionState,
    secure: bool,
) -> StackChild {
    TextField::with_interaction(interaction)
        .placeholder(placeholder)
        .size(TextFieldSize::Large)
        .secure(secure)
        .frame(CONTENT_WIDTH, 44.0)
}

fn status_text(status: String) -> StackChild {
    Text::new(status)
        .font_size(12.0)
        .line_height(18.0)
        .weight(500)
        .alignment(TextAlignment::Center)
        .color(Color::WHITE)
        .frame(CONTENT_WIDTH, 22.0)
}

fn submit_callback(
    full_name: TextFieldInteractionState,
    account_name: TextFieldInteractionState,
    password: TextFieldInteractionState,
    password_confirmation: TextFieldInteractionState,
    status: State<String>,
    created_display_name: State<String>,
    created_identity: State<Option<mochi_user_platform::service_ready::SessionIdentity>>,
    page: State<usize>,
    next_request_id: Rc<Cell<u64>>,
) -> impl FnMut() {
    move || {
        let display_name = full_name.value().trim().to_owned();
        let name = account_name.value().trim().to_owned();
        let mut secret = password.value();
        let mut confirmation = password_confirmation.value();

        let validation = validate_input(&display_name, &name, &secret, &confirmation);
        if let Err(message) = validation {
            status.set(message.to_owned());
            clear_string(&mut secret);
            clear_string(&mut confirmation);
            return;
        }

        status.set("Creating your account...".to_owned());
        let request_id = next_request_id.get();
        next_request_id.set(request_id.wrapping_add(4).max(1));
        let result = create_first_account(request_id, &display_name, &name, secret.as_bytes());
        clear_string(&mut secret);
        clear_string(&mut confirmation);
        password.clear();
        password_confirmation.clear();

        match result {
            Ok(identity) => {
                created_display_name.set(display_name);
                created_identity.set(Some(identity));
                status.set(String::new());
                page.set(4);
            }
            Err(SetupError::InvalidInput) => {
                status.set("Check the account information and try again.".to_owned())
            }
            Err(SetupError::AccountAlreadyExists) => {
                status.set("An account has already been configured.".to_owned())
            }
            Err(SetupError::ServiceUnavailable) => {
                status.set("Account service is unavailable.".to_owned())
            }
            Err(SetupError::Storage) => status.set("The account could not be saved.".to_owned()),
            Err(SetupError::Protocol) => {
                status.set("Account setup could not be completed.".to_owned())
            }
        }
    }
}

fn finish_setup(
    login_target: Option<mochi_user_platform::service_ready::Target>,
    identity: Option<mochi_user_platform::service_ready::SessionIdentity>,
    status: &State<String>,
) {
    let Some(target) = login_target else {
        status.set("The login channel is unavailable.".to_owned());
        return;
    };
    let Some(identity) = identity else {
        status.set("The account identity is unavailable.".to_owned());
        return;
    };
    match mochi_user_platform::service_ready::notify_session(target, 0, identity) {
        Ok(_) => viewkit::request_exit(),
        Err(_) => status.set("The session could not start.".to_owned()),
    }
}

fn validate_input(
    display_name: &str,
    name: &str,
    password: &str,
    confirmation: &str,
) -> Result<(), &'static str> {
    if display_name.is_empty() {
        return Err("Enter your full name.");
    }
    if name.is_empty() {
        return Err("Enter an account name.");
    }
    let mut candidate = UserRecord::regular(name, FIRST_REGULAR_UID, FIRST_REGULAR_UID);
    candidate.display_name = display_name.to_owned();
    if candidate.validate().is_err() {
        return Err(
            "Use lowercase letters, numbers, hyphens, or underscores for the account name.",
        );
    }
    if password.len() > mochios_user_protocol::MAX_PASSWORD_LEN {
        return Err("The password is too long.");
    }
    if password != confirmation {
        return Err("The passwords do not match.");
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SetupError {
    InvalidInput,
    AccountAlreadyExists,
    ServiceUnavailable,
    Storage,
    Protocol,
}

fn create_first_account(
    request_id: u64,
    display_name: &str,
    name: &str,
    password: &[u8],
) -> Result<mochi_user_platform::service_ready::SessionIdentity, SetupError> {
    let database = authentication::load_database(request_id).map_err(map_authentication_error)?;
    if database
        .users()
        .iter()
        .any(|user| user.uid >= FIRST_REGULAR_UID)
    {
        return Err(SetupError::AccountAlreadyExists);
    }
    let uid = database
        .next_regular_uid()
        .map_err(|_| SetupError::InvalidInput)?;
    let mut user = UserRecord::regular(name, uid, uid);
    user.display_name = display_name.to_owned();
    user.validate().map_err(|_| SetupError::InvalidInput)?;
    let encoded = user.encode().map_err(|_| SetupError::InvalidInput)?;

    create_home(&user)?;
    let service = authentication::find_user_service().ok_or(SetupError::ServiceUnavailable)?;
    if let Err(error) = add_user(service, request_id.wrapping_add(1).max(1), &encoded) {
        remove_home(&user);
        return Err(error);
    }
    if let Err(error) = set_password(
        service,
        request_id.wrapping_add(2).max(1),
        &user.name,
        password,
    ) {
        let _ = remove_user(service, request_id.wrapping_add(3).max(1), &user.name);
        remove_home(&user);
        return Err(error);
    }
    Ok(mochi_user_platform::service_ready::SessionIdentity {
        uid: user.uid,
        gid: user.gid,
    })
}

fn add_user(service: u64, request_id: u64, encoded: &[u8]) -> Result<(), SetupError> {
    let request = AddUser {
        request_id,
        encoded_record: encoded,
    };
    mutate(service, request_id, |output| request.encode(output))
}

fn set_password(
    service: u64,
    request_id: u64,
    name: &str,
    password: &[u8],
) -> Result<(), SetupError> {
    let request = SetPassword {
        request_id,
        name,
        password,
    };
    mutate_sensitive(service, request_id, |output| request.encode(output))
}

fn remove_user(service: u64, request_id: u64, name: &str) -> Result<(), SetupError> {
    let request = RemoveUser { request_id, name };
    mutate(service, request_id, |output| request.encode(output))
}

fn mutate(
    service: u64,
    request_id: u64,
    encode: impl FnOnce(&mut [u8]) -> Result<usize, mochios_user_protocol::EncodeError>,
) -> Result<(), SetupError> {
    let mut request = [0u8; MAX_MESSAGE_LEN];
    let request_len = encode(&mut request).map_err(|_| SetupError::InvalidInput)?;
    call_status(service, request_id, &request[..request_len])
}

fn mutate_sensitive(
    service: u64,
    request_id: u64,
    encode: impl FnOnce(&mut [u8]) -> Result<usize, mochios_user_protocol::EncodeError>,
) -> Result<(), SetupError> {
    let mut request = [0u8; MAX_MESSAGE_LEN];
    let request_len = encode(&mut request).map_err(|_| SetupError::InvalidInput)?;
    let result = call_status(service, request_id, &request[..request_len]);
    request[..request_len].fill(0);
    result
}

fn call_status(service: u64, request_id: u64, request: &[u8]) -> Result<(), SetupError> {
    let mut reply = [0u8; mochios_user_protocol::STATUS_LEN];
    let reply_len =
        authentication::call(service, request, &mut reply).map_err(map_authentication_error)?;
    let status = Status::decode(&reply[..reply_len]).map_err(|_| SetupError::Protocol)?;
    if status.request_id != request_id {
        return Err(SetupError::Protocol);
    }
    if status.status == 0 {
        Ok(())
    } else {
        Err(SetupError::Storage)
    }
}

fn create_home(user: &UserRecord) -> Result<(), SetupError> {
    let home = Path::new(&user.home);
    match fs::symlink_metadata(home) {
        Ok(_) => return Err(SetupError::Storage),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err(SetupError::Storage),
    }
    if fs::create_dir_all(home).is_err() {
        return Err(SetupError::Storage);
    }
    for directory in HOME_DIRECTORIES {
        if fs::create_dir(home.join(directory)).is_err() {
            remove_home(user);
            return Err(SetupError::Storage);
        }
    }
    if fs::set_permissions(home, fs::Permissions::from_mode(0o700)).is_err() {
        remove_home(user);
        return Err(SetupError::Storage);
    }
    for directory in HOME_DIRECTORIES {
        if fs::set_permissions(home.join(directory), fs::Permissions::from_mode(0o700)).is_err() {
            remove_home(user);
            return Err(SetupError::Storage);
        }
    }
    if chown(home, Some(user.uid), Some(user.gid)).is_err() {
        remove_home(user);
        return Err(SetupError::Storage);
    }
    for directory in HOME_DIRECTORIES {
        if chown(home.join(directory), Some(user.uid), Some(user.gid)).is_err() {
            remove_home(user);
            return Err(SetupError::Storage);
        }
    }
    Ok(())
}

fn remove_home(user: &UserRecord) {
    let expected = Path::new("/home").join(&user.name);
    if Path::new(&user.home) == expected {
        for directory in HOME_DIRECTORIES.into_iter().rev() {
            let _ = fs::remove_dir(expected.join(directory));
        }
        let _ = fs::remove_dir(expected);
    }
}

fn map_authentication_error(error: AuthenticationError) -> SetupError {
    match error {
        AuthenticationError::ServiceUnavailable => SetupError::ServiceUnavailable,
        AuthenticationError::InvalidCredentials | AuthenticationError::Protocol => {
            SetupError::Protocol
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_first_account_fields() {
        assert_eq!(
            validate_input("Alice", "alice", "password", "password"),
            Ok(())
        );
        assert_eq!(validate_input("Alice", "alice", "", ""), Ok(()));
        assert!(validate_input("Alice", "Alice", "password", "password").is_err());
        assert!(validate_input("Alice", "alice", "password", "different").is_err());
    }
}
