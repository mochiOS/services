#[cfg(not(target_os = "mochios"))]
fn main() {
    eprintln!("queued-client: SKIP (requires mochiOS)");
}

#[cfg(target_os = "mochios")]
fn main() {
    use mochi_user_platform::{handle, ipc, syscall};
    use mochios_posix_client::{
        Client, EndpointTransport, ObjectHandleAttachment as Object, ObjectHandles,
        ObjectTransport, OpenAtBase, StatAtBase, Transport, file_admission::Error,
    };
    use mochios_posix_protocol as wire;
    use std::cell::Cell;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    // Test-only transport injection guarantees a real two-hop Wait reply
    // without relying on scheduling. It adds an unrelated provider ticket;
    // filesystem authorization/resolution must rescope it before storage I/O.
    struct ProbeTransport {
        inner: EndpointTransport,
        provider: u32,
        inject: Cell<bool>,
    }
    impl Drop for ProbeTransport {
        fn drop(&mut self) {
            let _ = handle::close(self.provider);
        }
    }
    impl Transport for &ProbeTransport {
        type Error = syscall::SysError;
        fn call(&self, request: &[u8], response: &mut [u8]) -> Result<usize, Self::Error> {
            self.inner.call(request, response)
        }
    }
    impl ObjectTransport for &ProbeTransport {
        type Handle = u32;
        fn close_received_handle(&self, object: u32) {
            self.inner.close_received_handle(object);
        }
        fn call_with_handles(
            &self,
            request: &[u8],
            response: &mut [u8],
            handles: &mut ObjectHandles<u32>,
        ) -> Result<usize, Self::Error> {
            let (mut header, payload) = wire::decode(request).unwrap();
            if !self.inject.get()
                || header.flags & wire::MUTATION_ADMISSION == 0
                || header.flags & wire::MUTATION_ADMISSION_ATTACHED != 0
            {
                return self.inner.call_with_handles(request, response, handles);
            }
            // Keep the contract that an early error never returns borrows.
            let mut outgoing = core::mem::take(handles);
            let ticket = handle::create_provider_memory_admission(self.provider, 77)?;
            outgoing
                .push(Object {
                    handle: ticket.handle(),
                    rights: mnu_abi::HANDLE_RIGHT_WAIT | mnu_abi::HANDLE_RIGHT_TRANSFER,
                })
                .unwrap();
            header.flags |= wire::MUTATION_ADMISSION_ATTACHED;
            let mut frame = [0; wire::CONTROL_MESSAGE_LEN];
            let length = wire::encode(header, payload, &mut frame).unwrap();
            let result = self
                .inner
                .call_with_handles(&frame[..length], response, &mut outgoing);
            *handles = outgoing;
            result
        }
    }
    fn wait(ticket: &Object<u32>) -> Result<(), syscall::SysError> {
        handle::wait_provider_memory_admission(ticket.handle)
    }

    println!("queued-client: starting real client admission checks");
    let transport = ProbeTransport {
        inner: EndpointTransport::from_launch_context().unwrap(),
        provider: ipc::create_handle().unwrap(),
        inject: Cell::new(true),
    };
    let client = Client::new(&transport);
    client.register_session().unwrap();
    let path = "/tmp/native-queued-client";
    let file = client
        .open_at_with_wait(
            OpenAtBase::ProcessRoot,
            wire::OPEN_READ | wire::OPEN_WRITE | wire::OPEN_CREATE | wire::OPEN_EXCLUSIVE,
            0o600,
            path,
            wait,
        )
        .unwrap();
    let waits = Cell::new(0usize);
    let mut counted_wait = |ticket: &Object<u32>| {
        waits.set(waits.get() + 1);
        wait(ticket)
    };
    client
        .ftruncate_with_wait(file, 8192, &mut counted_wait)
        .unwrap();
    client
        .truncate_at_with_wait(StatAtBase::ProcessRoot, path, 5000, &mut counted_wait)
        .unwrap();
    let other = client
        .open_at_with_wait(
            OpenAtBase::ProcessRoot,
            wire::OPEN_READ | wire::OPEN_WRITE | wire::OPEN_TRUNCATE,
            0,
            path,
            &mut counted_wait,
        )
        .unwrap();
    handle::close(other.handle).unwrap();
    assert_eq!(waits.get(), 3);
    assert!(matches!(
        client.ftruncate_with_wait(file, 8192, |_| Err(4u8)),
        Err(Error::Wait(4))
    ));
    assert_eq!(client.fstat(file).unwrap().size, 0);
    transport.inject.set(false);
    client.ftruncate_with_wait(file, 8192, wait).unwrap();

    // No injected ticket, bounded reader loop, sleeps or throttling here.
    // This is the actual starvation regression with continuous native reads.
    let stopping = Arc::new(AtomicBool::new(false));
    let reads = Arc::new(AtomicUsize::new(0));
    let reader_stop = stopping.clone();
    let reader_reads = reads.clone();
    let reader = std::thread::spawn(move || {
        let mut bytes = [0; 4096];
        while !reader_stop.load(Ordering::Acquire) {
            handle::read_at(file.handle, &mut bytes, 0).unwrap();
            reader_reads.fetch_add(1, Ordering::Release);
        }
    });
    for _ in 0..10000 {
        if reads.load(Ordering::Acquire) != 0 {
            break;
        }
        std::thread::yield_now();
    }
    assert!(reads.load(Ordering::Acquire) != 0);
    let before = waits.get();
    for i in 0..64 {
        client
            .ftruncate_with_wait(
                file,
                if i % 2 == 0 { 5000 } else { 8192 },
                &mut counted_wait,
            )
            .unwrap();
        if i % 8 == 0 {
            let opened = client
                .open_at_with_wait(
                    OpenAtBase::ProcessRoot,
                    wire::OPEN_READ | wire::OPEN_WRITE | wire::OPEN_TRUNCATE,
                    0,
                    path,
                    &mut counted_wait,
                )
                .unwrap();
            handle::close(opened.handle).unwrap();
            client
                .truncate_at_with_wait(StatAtBase::ProcessRoot, path, 8192, &mut counted_wait)
                .unwrap();
        }
    }
    stopping.store(true, Ordering::Release);
    reader.join().unwrap();
    handle::close(file.handle).unwrap();
    client.unlink_at(StatAtBase::ProcessRoot, 0, path).unwrap();
    println!(
        "queued-client: PASS three paths, cancellation and continuous reader ({} reads, {} contended waits)",
        reads.load(Ordering::Acquire),
        waits.get() - before
    );
}
