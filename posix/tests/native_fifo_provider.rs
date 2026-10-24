//! Native Provider dispatch, duplicate reference lifetime and shared options.
//! Disk pathname/inode authority is deliberately outside this isolated probe.
#[cfg(not(target_os = "mochios"))]
fn main() {
    eprintln!("fifo-provider: SKIP (requires mochiOS)");
}

#[cfg(target_os = "mochios")]
fn main() {
    use mnu_abi::{SyscallNumber, provider};
    use mochi_user_platform as platform;
    use mochi_user_syscall as syscall;
    use posix_service::{
        fifo::{Access, Channel},
        fifo_provider::{Binding, handle_provider_request, native_signals},
    };
    use std::sync::mpsc;

    let (opened_tx, opened_rx) = mpsc::channel();
    let (released_tx, released_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let endpoint = platform::ipc::create_handle().unwrap();
        let common = mnu_abi::HANDLE_RIGHT_DUPLICATE
            | mnu_abi::HANDLE_RIGHT_TRANSFER
            | mnu_abi::HANDLE_RIGHT_WAIT
            | mnu_abi::HANDLE_RIGHT_CONTROL;
        // Own native references before committing the channel's peer state.
        let reader_handle = platform::handle::create_provider_object(
            endpoint,
            901,
            common | mnu_abi::HANDLE_RIGHT_READ,
        )
        .unwrap();
        let writer_handle = platform::handle::create_provider_object(
            endpoint,
            902,
            common | mnu_abi::HANDLE_RIGHT_WRITE,
        )
        .unwrap();
        let mut channel = Channel::default();
        let reader = channel.open(Access::Read, true).unwrap();
        let writer = channel.open(Access::Write, true).unwrap();
        let reader_binding = Binding::new(901, reader).unwrap();
        let writer_binding = Binding::new(902, writer).unwrap();
        opened_tx.send((reader_handle, writer_handle)).unwrap();
        let mut request = [0; provider::REQUEST_HEADER_LEN + provider::MAX_DATA_LEN];
        let mut response = [0; provider::RESPONSE_HEADER_LEN + provider::MAX_DATA_LEN];
        let mut released = 0;
        while released != 2 {
            let mut objects = platform::ipc::IpcObjectHandles::default();
            let message =
                platform::ipc::wait_object_handles(u64::from(endpoint), &mut request, &mut objects)
                    .unwrap();
            let length = message as u32 as usize;
            assert!(length <= request.len());
            let (header, _) = provider::RequestHeader::decode(&request[..length]).unwrap();
            let binding = match header.object_id {
                901 => reader_binding,
                902 => writer_binding,
                _ => panic!("unknown owner object"),
            };
            let result = handle_provider_request(
                &mut channel,
                binding,
                &request[..length],
                objects.delivery_flags,
                objects.count,
                &mut response,
            )
            .unwrap();
            assert_eq!(objects.count, 0);
            for (id, description) in [(901, reader), (902, writer)] {
                if let Ok(ready) = channel.readiness(description) {
                    let signals = native_signals(ready);
                    let mask = mnu_abi::HANDLE_SIGNAL_READABLE
                        | mnu_abi::HANDLE_SIGNAL_WRITABLE
                        | mnu_abi::HANDLE_SIGNAL_PEER_CLOSED;
                    platform::handle::signal_provider_object(id, signals, mask & !signals).unwrap();
                }
            }
            if let Some(length) = result {
                platform::ipc::reply(message >> 32, &response[..length]).unwrap();
            } else {
                assert_eq!(header.opcode, provider::OP_RELEASE);
                released += 1;
                released_tx.send(header.object_id).unwrap();
            }
        }
        platform::handle::close(endpoint).unwrap();
    });
    let (reader, writer) = opened_rx.recv().unwrap();
    let mut output = [0; 512];
    assert_eq!(
        platform::handle::read(reader, &mut output)
            .unwrap_err()
            .raw(),
        -11
    );
    assert_eq!(platform::handle::write(writer, &[7; 512]).unwrap(), 512);
    assert_eq!(
        platform::handle::read(reader, &mut output[..128]).unwrap(),
        128
    );
    assert_eq!(
        platform::handle::read(reader, &mut output[128..]).unwrap(),
        384
    );
    assert_eq!(output, [7; 512]);
    platform::io::stdout(b"fifo-provider: PASS native Handle read/write and backpressure\n")
        .unwrap();
    let alias = platform::handle::duplicate(
        writer,
        mnu_abi::HANDLE_RIGHT_WRITE
            | mnu_abi::HANDLE_RIGHT_CONTROL
            | mnu_abi::HANDLE_RIGHT_DUPLICATE
            | mnu_abi::HANDLE_RIGHT_TRANSFER,
    )
    .unwrap();
    syscall::call2(
        SyscallNumber::HandleOptionsSet,
        u64::from(writer),
        mnu_abi::HANDLE_OPTION_NONBLOCKING,
    )
    .unwrap();
    assert_eq!(
        syscall::call1(SyscallNumber::HandleOptionsGet, u64::from(alias)).unwrap(),
        mnu_abi::HANDLE_OPTION_NONBLOCKING
    );
    platform::handle::close(writer).unwrap();
    assert_eq!(platform::handle::write(alias, b"alive").unwrap(), 5);
    assert_eq!(platform::handle::read(reader, &mut output).unwrap(), 5);
    assert_eq!(&output[..5], b"alive");
    platform::io::stdout(
        b"fifo-provider: PASS dup shares options and original close preserves writer\n",
    )
    .unwrap();
    assert!(platform::handle::write(reader, b"denied").is_err());
    platform::handle::close(alias).unwrap();
    assert_eq!(released_rx.recv().unwrap(), 902);
    assert_eq!(platform::handle::read(reader, &mut output).unwrap(), 0);
    platform::io::stdout(b"fifo-provider: PASS last writer release produces EOF\n").unwrap();
    platform::handle::close(reader).unwrap();
    assert_eq!(released_rx.recv().unwrap(), 901);
    worker.join().unwrap();
    platform::io::stdout(b"fifo-provider: PASS last reader release and worker cleanup\n").unwrap();
}
