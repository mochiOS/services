use posix_service::fifo::{Access, BUFFER_CAPACITY, Channel, Error, MAX_OPEN_DESCRIPTIONS};

#[test]
fn nonblocking_open_requires_a_reader_only_for_the_writer() {
    let mut channel = Channel::default();
    assert_eq!(channel.open(Access::Write, true), Err(Error::NoReaders));
    let reader = channel.open(Access::Read, true).unwrap();
    assert_eq!(channel.read(reader, &mut [0; 1]), Ok(0));
    let writer = channel.open(Access::Write, true).unwrap();
    assert!(channel.observe(writer).unwrap().open_ready);
    assert_eq!(channel.read(reader, &mut [0; 1]), Err(Error::WouldBlock));
    assert_eq!(channel.observe(reader).unwrap().readers, 1);
    assert_eq!(channel.observe(reader).unwrap().writers, 1);
}

#[test]
fn blocking_open_rendezvous_works_in_both_orders_and_wakes_all_peers() {
    for first in [Access::Read, Access::Write] {
        let opposite = if first == Access::Read {
            Access::Write
        } else {
            Access::Read
        };
        let mut channel = Channel::default();
        let a = channel.open(first, false).unwrap();
        let b = channel.open(first, false).unwrap();
        assert!(!channel.observe(a).unwrap().open_ready);
        assert!(!channel.observe(b).unwrap().open_ready);
        let c = channel.open(opposite, false).unwrap();
        for id in [a, b, c] {
            assert!(channel.observe(id).unwrap().open_ready);
        }
        // A matched open stays completed even when its peer closes before the
        // waiting caller has resumed. It must observe EOF/EPIPE, not wait again.
        channel.close(c).unwrap();
        assert!(channel.observe(a).unwrap().open_ready);
        if first == Access::Read {
            assert_eq!(channel.read(a, &mut [0; 1]), Ok(0));
        } else {
            assert_eq!(channel.write(a, b"x"), Err(Error::NoReaders));
        }
    }
}

#[test]
fn pending_opens_cannot_do_io_and_cancellation_removes_them() {
    let mut channel = Channel::default();
    let pending_reader = channel.open(Access::Read, false).unwrap();
    assert_eq!(
        channel.read(pending_reader, &mut []),
        Err(Error::OpenPending)
    );
    channel.close(pending_reader).unwrap();
    assert_eq!(channel.open(Access::Write, true), Err(Error::NoReaders));
    let pending_writer = channel.open(Access::Write, false).unwrap();
    assert_eq!(channel.write(pending_writer, b"x"), Err(Error::OpenPending));
    channel.close(pending_writer).unwrap();
    let reader = channel.open(Access::Read, true).unwrap();
    assert_eq!(channel.read(reader, &mut [0; 1]), Ok(0));
    assert_eq!(channel.observe(reader).unwrap().writers, 0);
}

#[test]
fn writer_close_drains_data_before_eof_and_a_new_writer_reconnects() {
    let mut channel = Channel::default();
    let reader = channel.open(Access::Read, true).unwrap();
    let writer = channel.open(Access::Write, true).unwrap();
    assert_eq!(channel.write(writer, b"hello"), Ok(5));
    channel.close(writer).unwrap();
    let mut output = [0; 8];
    assert_eq!(channel.read(reader, &mut output), Ok(5));
    assert_eq!(&output[..5], b"hello");
    assert_eq!(channel.read(reader, &mut output), Ok(0));
    let next_writer = channel.open(Access::Write, true).unwrap();
    assert_ne!(next_writer, writer);
    assert_eq!(channel.write(writer, b"stale"), Err(Error::BadDescription));
    assert_eq!(channel.read(reader, &mut output), Err(Error::WouldBlock));
    assert_eq!(channel.write(next_writer, b"next"), Ok(4));
    assert_eq!(channel.read(reader, &mut output), Ok(4));
    assert_eq!(&output[..4], b"next");
}

#[test]
fn losing_readers_breaks_writes_but_another_reader_can_reconnect() {
    let mut channel = Channel::default();
    let reader = channel.open(Access::Read, true).unwrap();
    let writer = channel.open(Access::Write, true).unwrap();
    channel.write(writer, b"queued").unwrap();
    channel.close(reader).unwrap();
    assert_eq!(channel.write(writer, b"lost"), Err(Error::NoReaders));
    let next_reader = channel.open(Access::Read, true).unwrap();
    assert_eq!(channel.write(writer, b"new"), Ok(3));
    let mut output = [0; 9];
    assert_eq!(channel.read(next_reader, &mut output), Ok(9));
    assert_eq!(&output, b"queuednew");
}

#[test]
fn last_close_discards_data_and_does_not_revive_stale_descriptions() {
    let mut channel = Channel::default();
    let reader = channel.open(Access::Read, true).unwrap();
    let writer = channel.open(Access::Write, true).unwrap();
    channel.write(writer, b"discard").unwrap();
    channel.close(reader).unwrap();
    channel.close(writer).unwrap();
    assert_eq!(channel.close(writer), Err(Error::BadDescription));
    let new_reader = channel.open(Access::Read, true).unwrap();
    assert_ne!(reader, new_reader);
    assert_eq!(channel.read(new_reader, &mut [0; 1]), Ok(0));
    assert_eq!(
        channel.read(reader, &mut [0; 1]),
        Err(Error::BadDescription)
    );
}

#[test]
fn small_writes_are_atomic_and_large_writes_make_bounded_progress() {
    let mut channel = Channel::default();
    let reader = channel.open(Access::Read, true).unwrap();
    let writer = channel.open(Access::Write, true).unwrap();
    let atomic = mochios_posix_client::stream::PIPE_BUF;
    assert_eq!(atomic, mochios_posix_protocol::PIPE_BUF);
    let prefix = vec![b'p'; BUFFER_CAPACITY - atomic + 1];
    assert_eq!(channel.write(writer, &prefix), Ok(prefix.len()));
    assert_eq!(
        channel.write(writer, &vec![b'a'; atomic]),
        Err(Error::WouldBlock)
    );
    assert_eq!(
        channel.observe(reader).unwrap().buffered_bytes,
        prefix.len()
    );
    let mut byte = [0];
    assert_eq!(channel.read(reader, &mut byte), Ok(1));
    assert_eq!(channel.write(writer, &vec![b'a'; atomic]), Ok(atomic));
    assert_eq!(channel.write(writer, b"x"), Err(Error::WouldBlock));
    let mut drained = vec![0; BUFFER_CAPACITY];
    assert_eq!(channel.read(reader, &mut drained), Ok(BUFFER_CAPACITY));
    assert!(drained[..prefix.len() - 1].iter().all(|&byte| byte == b'p'));
    assert!(drained[prefix.len() - 1..].iter().all(|&byte| byte == b'a'));
    assert_eq!(
        channel.write(writer, &vec![b'z'; BUFFER_CAPACITY + 1]),
        Ok(BUFFER_CAPACITY)
    );
    assert_eq!(channel.read(reader, &mut drained), Ok(BUFFER_CAPACITY));
    assert!(drained.iter().all(|&byte| byte == b'z'));
}

#[test]
fn wrong_direction_and_stale_operations_leave_data_untouched() {
    let mut channel = Channel::default();
    let reader = channel.open(Access::Read, true).unwrap();
    let writer = channel.open(Access::Write, true).unwrap();
    channel.write(writer, b"keep").unwrap();
    assert_eq!(channel.write(reader, b"bad"), Err(Error::WrongAccess));
    assert_eq!(channel.read(writer, &mut [0; 4]), Err(Error::WrongAccess));
    assert_eq!(channel.write(writer, &[]), Ok(0));
    assert_eq!(channel.read(reader, &mut []), Ok(0));
    let mut output = [0; 4];
    assert_eq!(channel.read(reader, &mut output), Ok(4));
    assert_eq!(&output, b"keep");
}

#[test]
fn admission_limit_does_not_complete_waiters_or_leak_a_peer() {
    let mut channel = Channel::default();
    let mut readers = Vec::new();
    for _ in 0..MAX_OPEN_DESCRIPTIONS {
        readers.push(channel.open(Access::Read, false).unwrap());
    }
    assert_eq!(channel.open(Access::Write, true), Err(Error::ResourceLimit));
    for &reader in &readers {
        assert!(!channel.observe(reader).unwrap().open_ready);
        assert_eq!(channel.observe(reader).unwrap().writers, 0);
    }
    channel.close(readers.pop().unwrap()).unwrap();
    let writer = channel.open(Access::Write, true).unwrap();
    assert!(channel.observe(writer).unwrap().open_ready);
    for reader in readers {
        assert!(channel.observe(reader).unwrap().open_ready);
    }
}

#[test]
fn independent_inode_channels_do_not_share_data_or_open_rendezvous() {
    let mut a = Channel::default();
    let mut b = Channel::default();
    let reader_a = a.open(Access::Read, true).unwrap();
    let reader_b = b.open(Access::Read, true).unwrap();
    let writer_a = a.open(Access::Write, true).unwrap();
    a.write(writer_a, b"a").unwrap();
    assert_eq!(b.read(reader_b, &mut [0; 1]), Ok(0));
    assert_eq!(a.read(reader_a, &mut [0; 1]), Ok(1));
}
