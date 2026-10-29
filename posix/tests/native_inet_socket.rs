#[cfg(target_os = "mochios")]
mod libc_udp {
    include!("support/native_libc_udp.inc");
}
#[cfg(all(target_os = "mochios", mochios_tcp_provider_274))]
#[path = "native_tcp_provider.rs"]
mod tcp_provider;
#[cfg(all(target_os = "mochios", mochios_dns_handles_281))]
#[path = "native_resolver_provider.rs"]
mod resolver_provider;
#[cfg(all(target_os = "mochios", mochios_interfaces_284))]
#[path = "native_interface_snapshot.rs"]
mod interface_snapshot;
#[cfg(all(target_os = "mochios", mochios_netdb_public_285))]
#[path = "native_netdb.rs"]
mod netdb;
#[cfg(all(target_os = "mochios", mochios_llvm_runtime_probe_215))]
#[path = "native_llvm_runtime.rs"]
mod llvm_runtime;
#[cfg(all(target_os = "mochios", mochios_interpreter_probe_296))]
#[path = "interpreter_native.rs"]
mod interpreter;
#[cfg(all(target_os = "mochios", mochios_elf_mapping_probe_297))]
#[path = "native_elf_mapping.rs"]
mod elf_mapping;
#[cfg(all(
    target_os = "mochios",
    any(
        mochios_startup_metadata_probe_293,
        mochios_relro_probe_294,
        mochios_readonly_relocation_probe_295
    )
))]
#[path = "startup_metadata_native.rs"]
mod startup_metadata;
#[cfg(all(target_os = "mochios", mochios_read_scope_259))]
#[path = "native_read_scope.rs"]
mod read_scope;
#[cfg(all(target_os = "mochios", mochios_scoped_launch_261))]
#[path = "native_scoped_launch.rs"]
mod scoped_launch;
#[cfg(all(target_os = "mochios", mochios_scoped_application_263))]
#[path = "native_scoped_application.rs"]
mod scoped_application;
#[cfg(all(target_os = "mochios", mochios_shared_package_264))]
#[path = "native_shared_package.rs"]
mod shared_package;
#[cfg(all(target_os = "mochios", mochios_symbol_versions_265))]
#[path = "native_symbol_versions.rs"]
mod symbol_versions;
#[cfg(all(target_os = "mochios", mochios_copy_relocations_266))]
#[path = "native_copy_relocations.rs"]
mod copy_relocations;
// Executed only by a diagnostic manager after authenticated endpoint handoff.
// Socket/DNS fixtures request net.connect in their diagnostic manifest.
// The interface snapshot fixture uses the normal manager's empty network rights.
#[cfg(target_os = "mochios")]
#[path = "../../../user/crates/net-device-protocol/src/datagram_authority.rs"]
mod authority;
#[cfg(target_os = "mochios")]
pub fn run(posix: u32, network: u32) {
    use mochi_user_platform as p;
    use mochios_posix_client::{
        Client, ObjectHandleAttachment as Object, SyscallEndpointTransport, socket::ConnectStarted,
    };
    use mochios_posix_protocol::socket as w;
    unsafe extern "C" {
        fn alarm(seconds: u32) -> u32;
    }
    unsafe {
        // Real compiler images take substantially longer than socket probes.
        // Keep a finite watchdog, including both credential cases.
        alarm(if cfg!(mochios_llvm_runtime_probe_215) {
            900
        } else {
            90
        });
    }
    p::io::stdout(b"inet-socket: starting native factory/Provider checks\n").unwrap();
    #[cfg(mochios_netdb_public_285)]
    {
        llvm_runtime::run();
        netdb::run();
        unsafe { alarm(0); }
        return;
    }
    #[cfg(mochios_interfaces_284)]
    {
        interface_snapshot::run(network);
        unsafe { alarm(0); }
        return;
    }
    #[cfg(mochios_dns_handles_281)]
    {
        resolver_provider::run(network);
        unsafe { alarm(0); }
        return;
    }
    #[cfg(mochios_tcp_provider_274)]
    {
        tcp_provider::run(network);
    }
    #[cfg(mochios_copy_relocations_266)]
    {
        copy_relocations::run(posix);
        unsafe { alarm(0); }
        return;
    }
    #[cfg(mochios_symbol_versions_265)]
    {
        symbol_versions::run(posix);
        unsafe { alarm(0); }
        return;
    }
    #[cfg(mochios_shared_package_264)]
    {
        shared_package::run(posix);
        unsafe { alarm(0); }
        return;
    }
    #[cfg(mochios_scoped_application_263)]
    {
        scoped_application::run(posix);
        unsafe { alarm(0); }
        return;
    }
    #[cfg(mochios_scoped_launch_261)]
    {
        scoped_launch::run(posix);
        unsafe { alarm(0); }
        return;
    }
    #[cfg(mochios_read_scope_259)]
    {
        read_scope::run(posix);
        #[cfg(mochios_llvm_runtime_probe_215)]
        llvm_runtime::run();
        unsafe { alarm(0); }
        return;
    }
    #[cfg(mochios_llvm_runtime_probe_215)]
    {
        #[cfg(mochios_elf_mapping_probe_297)]
        {
            elf_mapping::run(posix);
            unsafe { alarm(0); }
            return;
        }
        #[cfg(any(
            mochios_startup_metadata_probe_293,
            mochios_relro_probe_294,
            mochios_readonly_relocation_probe_295
        ))]
        startup_metadata::run(posix);
        #[cfg(mochios_interpreter_probe_296)]
        interpreter::run(posix);
        llvm_runtime::run();
        #[cfg(not(mochios_tcp_socket_276))]
        {
            unsafe { alarm(0); }
            return;
        }
    }
    let client = Client::new(SyscallEndpointTransport::new(posix));
    let inherited = Client::from_syscall_launch_context().expect("libc POSIX launch endpoint");
    inherited
        .resource_limit(0, mochios_posix_protocol::RLIMIT_NOFILE, None)
        .expect("libc FD policy");
    let discovered = inherited
        .network_endpoint(|h| {
            p::handle::close(h).unwrap();
        })
        .expect("network endpoint getter");
    let checked = mochios_posix_client::network::acquire_factory(
        &SyscallEndpointTransport::new(discovered.handle),
        |h| {
            p::handle::close(h).unwrap();
        },
    )
    .expect("network factory acquisition");
    p::handle::close(checked.handle).unwrap();
    p::handle::close(discovered.handle).unwrap();
    p::io::stdout(b"libc-udp: endpoint discovery and caller authority PASS\n").unwrap();
    libc_udp::run();
    fn acquire(network: u32) -> Result<Object<u32>, i32> {
        let mut bytes = [0; authority::REPLY_LEN];
        let mut objects = p::ipc::IpcObjectHandles::default();
        let n = p::ipc::call_object_handles(network, &authority::ACQUIRE, &mut bytes, &mut objects)
            .unwrap() as u32 as usize;
        let status = authority::status(&bytes[..n]).unwrap();
        if status != 0 {
            assert_eq!(objects.count, 0);
            return Err(status);
        }
        assert_eq!(objects.count, 1);
        let source = objects.handles[0];
        assert_eq!(source.reserved, 0);
        Ok(Object {
            handle: source.handle,
            rights: source.rights,
        })
    }
    fn create() -> w::Create {
        w::Create {
            domain: w::Domain::Ipv4,
            kind: w::Kind::Datagram,
            protocol: 17,
            options: w::NONBLOCKING,
        }
    }
    fn address(port: u16) -> w::Address<'static> {
        w::Address::Ipv4 {
            address: [127, 0, 0, 1],
            port,
        }
    }
    fn bind(socket: u32, port: u16) {
        let mut bytes = [0; w::MAX_ADDRESS_LEN];
        let n = address(port).encode(&mut bytes).unwrap();
        assert_eq!(
            p::handle::control(socket, w::CONTROL_BIND, &bytes[..n], &mut []).unwrap(),
            0
        );
    }
    fn port(socket: u32) -> u16 {
        let mut bytes = [0; w::MAX_ADDRESS_LEN];
        let n = p::handle::control(socket, w::CONTROL_LOCAL_ADDRESS, &[], &mut bytes).unwrap();
        let w::Address::Ipv4 { port, .. } = w::Address::decode(&bytes[..n]).unwrap() else {
            panic!("expected IPv4")
        };
        port
    }
    fn close(handle: u32) {
        p::handle::close(handle).unwrap();
    }
    let factory = acquire(network).unwrap();
    let name = b"net.connect";
    mochi_user_syscall::call2(
        mnu_abi::SyscallNumber::CapDrop,
        name.as_ptr() as u64,
        name.len() as u64,
    )
    .unwrap();
    assert_eq!(acquire(network), Err(-13));
    libc_udp::denied_after_capability_drop();
    for _ in 0..64 {
        let socket = client.open_inet_datagram(create(), factory, close).unwrap();
        bind(socket.handle, 60000);
        close(socket.handle);
    }
    p::io::stdout(b"inet-socket: PASS delegated factory after Capability drop and 64 same-port final-close reopens\n").unwrap();
    let receiver = client.open_inet_datagram(create(), factory, close).unwrap();
    let sender = client.open_inet_datagram(create(), factory, close).unwrap();
    assert!(matches!(
        client.open_inet_datagram(create(), receiver, close),
        Err(mochios_posix_client::ClientError::Remote(-13))
    ));
    close(factory.handle);
    bind(receiver.handle, 0);
    let receiver_port = port(receiver.handle);
    assert_ne!(receiver_port, 0);
    assert!(matches!(
        client
            .connect_socket(sender, address(receiver_port), close)
            .unwrap(),
        ConnectStarted::Connected
    ));
    let alias = p::handle::duplicate(receiver.handle, w::descriptor_rights()).unwrap();
    close(receiver.handle);
    assert_eq!(
        p::handle::control(alias, w::CONTROL_SET_OPTIONS, &0u32.to_le_bytes(), &mut []).unwrap(),
        0
    );
    let mut options = [0; 4];
    p::handle::control(alias, w::CONTROL_GET_OPTIONS, &[], &mut options).unwrap();
    assert_eq!(options, [0; 4]);
    assert_eq!(p::handle::write(sender.handle, b"hello").unwrap(), 5);
    let mut waits = [mnu_abi::HandleWaitItem {
        handle: alias,
        interests: mnu_abi::HANDLE_SIGNAL_READABLE,
        ..Default::default()
    }];
    p::process::wait_many(
        &mut waits,
        p::time::monotonic_nanoseconds().unwrap() + 5_000_000_000,
    )
    .unwrap();
    assert_ne!(waits[0].observed & mnu_abi::HANDLE_SIGNAL_READABLE, 0);
    let mut output = [0; 64];
    for _ in 0..2 {
        assert_eq!(p::handle::read_at(alias, &mut output[..2], 0).unwrap(), 2);
        assert_eq!(&output[..2], b"he");
    }
    assert_eq!(p::handle::read(alias, &mut output).unwrap(), 5);
    assert_eq!(&output[..5], b"hello");
    assert_eq!(p::handle::read(alias, &mut output).unwrap_err().raw(), -11);
    p::io::stdout(b"inet-socket: PASS worker creation, trusted factory validation, connect, duplicate lifetime, readiness relay and peek\n").unwrap();
    p::handle::write(sender.handle, b"truncate").unwrap();
    p::process::wait_many(
        &mut waits,
        p::time::monotonic_nanoseconds().unwrap() + 5_000_000_000,
    )
    .unwrap();
    assert_eq!(p::handle::read(alias, &mut output[..2]).unwrap(), 2);
    assert_eq!(&output[..2], b"tr");
    assert_eq!(p::handle::read(alias, &mut output).unwrap_err().raw(), -11);
    let mut addr = [0; w::MAX_ADDRESS_LEN];
    let n = p::handle::control(sender.handle, w::CONTROL_LOCAL_ADDRESS, &[], &mut addr).unwrap();
    assert!(
        matches!(w::Address::decode(&addr[..n]).unwrap(),w::Address::Ipv4{address:[127,0,0,1],port} if port!=0)
    );
    close(sender.handle);
    close(alias);
    unsafe {
        alarm(0);
    }
    p::io::stdout(b"inet-socket: PASS whole-record truncation, routed local address and final resource cleanup\n").unwrap();
}
