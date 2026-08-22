use mochi_user_platform as platform;

use crate::surface::{Surface, destroy_surface_tree};
use crate::window::Window;

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ClientId(pub(crate) u64);

#[derive(Clone, Copy, Default)]
pub(crate) struct Client {
    pub(crate) live: bool,
    pub(crate) sender: u64,
    pub(crate) id: ClientId,
    pub(crate) decoration_endpoint: u64,
}

pub(crate) fn client_id_for_sender(
    clients: &mut [Client],
    sender: u64,
    next_client_id: &mut u64,
) -> ClientId {
    if let Some(client) = clients
        .iter()
        .find(|client| client.live && client.sender == sender)
    {
        return client.id;
    }
    if let Some(client) = clients.iter_mut().find(|client| !client.live) {
        *next_client_id = next_client_id.wrapping_add(1).max(1);
        let id = ClientId(*next_client_id);
        *client = Client {
            live: true,
            sender,
            id,
            decoration_endpoint: 0,
        };
        return id;
    }
    ClientId(0)
}

pub(crate) fn cleanup_client(
    clients: &mut [Client],
    surfaces: &mut [Surface],
    windows: &mut [Window],
    client: ClientId,
    pointer_focus: &mut Option<usize>,
    keyboard_focus: &mut Option<usize>,
) {
    if client == ClientId(0) {
        return;
    }
    while let Some(index) = surfaces
        .iter()
        .position(|surface| surface.live && surface.owner == client && !surface.is_decoration)
    {
        destroy_surface_tree(surfaces, windows, index, pointer_focus, keyboard_focus);
    }
    while let Some(index) = surfaces
        .iter()
        .position(|surface| surface.live && surface.owner == client && surface.is_decoration)
    {
        destroy_surface_tree(surfaces, windows, index, pointer_focus, keyboard_focus);
    }
    for window in windows
        .iter_mut()
        .filter(|window| window.live && window.decorator == client)
    {
        window.decorator = ClientId(0);
        window.decorator_endpoint = 0;
    }
    if let Some(record) = clients
        .iter_mut()
        .find(|record| record.live && record.id == client)
    {
        *record = Client::default();
    }
}

pub(crate) fn cleanup_dead_clients(
    clients: &mut [Client],
    surfaces: &mut [Surface],
    windows: &mut [Window],
    pointer_focus: &mut Option<usize>,
    keyboard_focus: &mut Option<usize>,
) -> bool {
    let mut changed = false;
    for index in 0..clients.len() {
        let client = clients[index];
        if !client.live {
            continue;
        }
        let has_live_surface = surfaces
            .iter()
            .any(|surface| surface.live && surface.owner == client.id);
        let has_surface_event_endpoint = surfaces.iter().any(|surface| {
            surface.live && surface.owner == client.id && surface.event_endpoint != 0
        });
        let has_live_surface_event_endpoint = surfaces.iter().any(|surface| {
            surface.live
                && surface.owner == client.id
                && surface.event_endpoint != 0
                && platform::ipc::endpoint_alive(surface.event_endpoint)
        });
        let has_live_decoration_endpoint = client.decoration_endpoint != 0
            && platform::ipc::endpoint_alive(client.decoration_endpoint);
        let has_live_window_decorator_endpoint = windows.iter().any(|window| {
            window.live
                && window.decorator == client.id
                && window.decorator_endpoint != 0
                && platform::ipc::endpoint_alive(window.decorator_endpoint)
        });

        let abandoned_surface =
            has_live_surface && has_surface_event_endpoint && !has_live_surface_event_endpoint;
        if abandoned_surface
            || (!has_live_surface
                && !has_live_decoration_endpoint
                && !has_live_window_decorator_endpoint)
        {
            cleanup_client(
                clients,
                surfaces,
                windows,
                client.id,
                pointer_focus,
                keyboard_focus,
            );
            changed = true;
        }
    }
    changed
}
