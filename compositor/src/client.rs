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
