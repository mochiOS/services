//! Service-private factory lifetime, before native Handle admission/publication.
use mochios_posix_protocol as wire;
use posix_service::pty::{EBADF, PtyManager, TerminalSignal};

#[test]
fn factory_opens_distinct_slaves_without_becoming_a_data_endpoint() {
    let mut ptys = PtyManager::new();
    let pair = ptys.open().unwrap();
    let factory = ptys.create_slave_factory(pair.master_object_id).unwrap();
    let first = ptys.open_slave_from_factory(factory).unwrap();
    let second = ptys.open_slave_from_factory(factory).unwrap();
    let ids = [
        pair.master_object_id,
        pair.slave_object_id,
        factory,
        first,
        second,
    ];
    for (index, id) in ids.iter().enumerate() {
        assert!(!ids[..index].contains(id));
    }
    assert_eq!(
        ptys.slave_terminal_id(first),
        ptys.slave_terminal_id(second)
    );
    assert_eq!(
        ptys.signal_object_ids(first).unwrap(),
        vec![ids[0], ids[1], first, second]
    );
    assert_eq!(ptys.read(factory, 1), Err(EBADF));
    assert_eq!(ptys.write(factory, b"x"), Err(EBADF));
    assert_eq!(ptys.attributes(factory), Err(EBADF));
    assert_eq!(ptys.signals(factory), Err(EBADF));
    assert_eq!(ptys.reopen_slave(factory), Err(EBADF));
    assert_eq!(ptys.create_slave_factory(factory), Err(EBADF));
    assert_eq!(ptys.create_slave_factory(first), Err(EBADF));
    assert_eq!(
        ptys.open_slave_from_factory(pair.master_object_id),
        Err(EBADF)
    );
    assert_eq!(ptys.open_slave_from_factory(first), Err(EBADF));
    ptys.release(factory).unwrap();
    assert_eq!(ptys.open_slave_from_factory(factory), Err(EBADF));
    assert!(ptys.attributes(first).is_ok());
    assert_eq!(ptys.take_terminal_signal(), None);
}

#[test]
fn retained_factory_does_not_keep_master_or_slave_open() {
    let mut ptys = PtyManager::new();
    let pair = ptys.open().unwrap();
    let factory = ptys.create_slave_factory(pair.master_object_id).unwrap();
    ptys.release(pair.slave_object_id).unwrap();
    assert_ne!(
        ptys.signals(pair.master_object_id).unwrap() & mnu_abi::HANDLE_SIGNAL_PEER_CLOSED,
        0
    );
    let slave = ptys.open_slave_from_factory(factory).unwrap();
    let terminal_id = ptys.slave_terminal_id(slave).unwrap();
    assert_eq!(
        ptys.signals(pair.master_object_id).unwrap() & mnu_abi::HANDLE_SIGNAL_PEER_CLOSED,
        0
    );
    ptys.release(pair.master_object_id).unwrap();
    assert_eq!(ptys.open_slave_from_factory(factory), Err(EBADF));
    assert_ne!(
        ptys.signals(slave).unwrap() & mnu_abi::HANDLE_SIGNAL_PEER_CLOSED,
        0
    );
    assert_eq!(
        ptys.take_terminal_signal(),
        Some(TerminalSignal {
            terminal_id,
            signal: wire::SIGNAL_HUP
        })
    );
    ptys.release(slave).unwrap();
    // An inert grant can still receive its native final release after all IO
    // objects retire, without resurrecting the terminal or emitting another HUP.
    let other = ptys.open().unwrap();
    assert_eq!(ptys.open_slave_from_factory(factory), Err(EBADF));
    ptys.release(factory).unwrap();
    assert_eq!(ptys.release(factory), Err(EBADF));
    assert!(ptys.attributes(other.slave_object_id).is_ok());
    assert_eq!(ptys.take_terminal_signal(), None);
}

#[test]
fn failed_publication_discards_only_its_own_factories_even_after_all_io_retires() {
    let mut ptys = PtyManager::new();
    let pair = ptys.open().unwrap();
    let factory = ptys.create_slave_factory(pair.master_object_id).unwrap();
    let second_factory = ptys.create_slave_factory(pair.master_object_id).unwrap();
    let other = ptys.open().unwrap();
    let other_factory = ptys.create_slave_factory(other.master_object_id).unwrap();
    ptys.release(pair.master_object_id).unwrap();
    ptys.release(pair.slave_object_id).unwrap();
    ptys.discard(pair);
    assert_eq!(ptys.release(factory), Err(EBADF));
    assert_eq!(ptys.release(second_factory), Err(EBADF));
    assert_eq!(ptys.take_terminal_signal(), None);
    let slave = ptys.open_slave_from_factory(other_factory).unwrap();
    ptys.release(other_factory).unwrap();
    assert_eq!(
        ptys.slave_terminal_id(slave),
        ptys.slave_terminal_id(other.slave_object_id)
    );
}

#[test]
fn provider_final_release_retires_only_the_factory_reference() {
    let mut ptys = PtyManager::new();
    let pair = ptys.open().unwrap();
    let first = ptys.create_slave_factory(pair.master_object_id).unwrap();
    let second = ptys.create_slave_factory(pair.master_object_id).unwrap();
    let mut request = [0; 128];
    let length = mnu_abi::provider::RequestHeader {
        opcode: mnu_abi::provider::OP_RELEASE,
        object_id: first,
        argument: 0,
        basis: 0,
        length: 0,
        data_length: 0,
    }
    .encode(&[], &mut request)
    .unwrap();
    assert_eq!(
        posix_service::pty::handle_provider_request(&mut ptys, &request[..length], &mut [0; 128]),
        None
    );
    assert_eq!(ptys.open_slave_from_factory(first), Err(EBADF));
    assert!(ptys.open_slave_from_factory(second).is_ok());
    assert!(ptys.attributes(pair.master_object_id).is_ok());
    assert_eq!(ptys.take_terminal_signal(), None);
}
