//! Real native VM, shared-library lifecycle, and common-prompt IPC boundary.
#[cfg(not(target_os = "mochios"))]
fn main() {
    eprintln!("native-resident: requires mochiOS");
}

#[cfg(target_os = "mochios")]
fn main() {
    use mochi_user_platform as p;
    use mochios_posix_client::{
        Client, SyscallEndpointTransport,
        elf_mapping::native::{Critical, Memory},
        pie::{
            Pie,
            link_scope::{
                Object, Scope,
                lookup::Version,
                resident::{Phase, Resident},
            },
        },
    };
    struct NoAbandonment;
    impl Critical for NoAbandonment {
        fn run<T>(f: impl FnOnce() -> T) -> T {
            f()
        }
    }
    fn invoke(address: u64) -> Result<(), p::syscall::SysError> {
        // SAFETY: the captured library scope validates executable ranges. This
        // fixture has only C void(void) callbacks and never abandons a frame.
        unsafe { std::mem::transmute::<u64, unsafe extern "C" fn()>(address)() };
        Ok(())
    }
    fn unmapped(address: u64) {
        let mut byte = 0u8;
        let error = p::syscall::call3(
            p::syscall::SyscallNumber::MemoryCopy,
            (&mut byte as *mut u8) as u64,
            address,
            1,
        )
        .unwrap_err();
        assert_eq!(
            error.native_error(),
            Some(p::syscall::NativeError::InvalidAddress)
        );
    }
    unsafe {
        libc::alarm(90);
    }
    let endpoint = p::handle::inherited(mochios_posix_protocol::CONTROL_HANDLE_KEY).unwrap();
    let client = Client::new(SyscallEndpointTransport::new(endpoint));
    let ceiling = client
        .resource_limit(0, mochios_posix_protocol::RLIMIT_AS, None)
        .unwrap()
        .soft;
    let bytes = ["root.so", "libresident.so"]
        .map(|name| std::fs::read(format!("/system/tests/resident361/{name}")).unwrap());
    let images = bytes
        .each_ref()
        .map(|bytes| Pie::parse_object(bytes).unwrap());
    let objects = [
        Object {
            name: b"root.so",
            image: &images[0],
            bias: 0x2c000000,
        },
        Object {
            name: b"libresident.so",
            image: &images[1],
            bias: 0x2d000000,
        },
    ];
    let mut order = [0; 2];
    let scope = Scope::new(&objects, &mut order).unwrap();
    let mut slots = [const { None }; 2];
    let mut loader = Resident::new(&scope, &mut slots).unwrap();
    let mut output = vec![
        0;
        images
            .iter()
            .map(|image| image.output_length().unwrap())
            .max()
            .unwrap()
    ];
    loader
        .install(&mut output, || Memory::<NoAbandonment>::new(ceiling))
        .unwrap();
    output.fill(0xa5);
    assert_eq!(loader.phase(), Phase::Mapped);
    assert!(loader.symbol(b"evaluate", Version::Default).is_err());
    loader.initialize(&mut [0; 8], invoke).unwrap();
    let function = loader
        .symbol(b"evaluate", Version::Default)
        .unwrap()
        .unwrap();
    let address = function.address();
    let function = unsafe { std::mem::transmute::<u64, unsafe extern "C" fn(i32) -> i32>(address) };
    assert_eq!(unsafe { function(7) }, 82);
    assert!(
        loader
            .symbol(b"absent", Version::Default)
            .unwrap()
            .is_none()
    );
    let mut finalized = 0;
    loader
        .close(&mut [0; 8], |address| {
            finalized += 1;
            invoke(address)
        })
        .unwrap();
    assert_eq!(finalized, 2);
    assert_eq!(loader.phase(), Phase::Closed);
    assert_eq!(loader.retained(), 0);
    unmapped(address);
    println!(
        "native-resident: PASS real Clang/LLD DSOs, relocation, constructors, symbol call, finalizers and native unmap"
    );

    use p::capability::consent::{Correlation, Ticket, prompt};
    let broker = p::process::find_by_name("capability.service").unwrap();
    let request = prompt::encode_fetch(Correlation {
        ticket: Ticket {
            id: 1,
            challenge: [0x6d; 32],
        },
        display: 1,
    })
    .unwrap();
    for malformed in [false, true] {
        let mut request = request;
        if malformed {
            request[10] = 1;
        }
        let mut reply = [0; prompt::MAX_MESSAGE_BYTES];
        let mut handles = p::ipc::IpcObjectHandles::default();
        let received =
            p::ipc::call_object_handles(broker as u32, &request, &mut reply, &mut handles).unwrap();
        assert_eq!(received >> 32, broker);
        assert_eq!(received as u32, 8);
        assert_eq!(handles.count, 0);
        assert_eq!(
            u64::from_le_bytes(reply[..8].try_into().unwrap()),
            if malformed { 22 } else { 2 }
        );
    }
    println!(
        "native-resident: PASS unknown/forged prompt fetch refused over real broker IPC; no permission granted"
    );
    unsafe {
        libc::alarm(0);
    }
    println!("native-resident: PASS");
}
