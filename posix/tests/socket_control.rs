use mochios_posix_client::socket_control::{self as control, Error, HEADER_LEN, MAX_RIGHTS};

fn frame(fds: &[i32]) -> Vec<u8> {
    let mut bytes = vec![0xa5; control::cmsg_space(fds.len() * 4).unwrap()];
    let result = control::encode_rights(fds, &mut bytes).unwrap();
    bytes.truncate(result.length);
    bytes
}

#[test]
fn layout_checks_overflow_and_uses_cmsg_len_not_padded_space() {
    assert_eq!(control::cmsg_len(4), Some(20));
    assert_eq!(control::cmsg_space(4), Some(24));
    assert_eq!(control::cmsg_len(8), Some(24));
    assert_eq!(control::cmsg_space(8), Some(24));
    for length in [usize::MAX, usize::MAX - 7, usize::MAX - 15] {
        assert_eq!(control::cmsg_len(length), None);
        assert_eq!(control::cmsg_space(length), None);
    }
    assert_eq!(control::align(usize::MAX), None);
}

#[test]
fn multiple_headers_preserve_duplicate_descriptors_and_ignore_padding() {
    let mut bytes = frame(&[0, 17, 17]);
    bytes[28..32].fill(0xff);
    bytes.extend(frame(&[5]));
    bytes.extend([0xa5; 7]);
    let mut output = [-1; 5];
    assert_eq!(control::decode_rights(&bytes, &mut output), Ok(4));
    assert_eq!(output, [0, 17, 17, 5, -1]);
    bytes = frame(&[42]);
    bytes.truncate(20); // final CMSG_SPACE padding need not be supplied
    assert_eq!(control::decode_rights(&bytes, &mut output), Ok(1));
    assert_eq!(output[0], 42);
    assert_eq!(control::decode_rights(&[], &mut []), Ok(0));
    assert_eq!(control::decode_rights(&[0xff; 15], &mut []), Ok(0));
}

#[test]
fn malformed_late_headers_never_publish_a_valid_prefix() {
    let prefix = frame(&[7]);
    for length in [0u64, 15, 17, 19, 25, u64::MAX] {
        let mut bytes = prefix.clone();
        let mut bad = frame(&[8]);
        bad[..8].copy_from_slice(&length.to_ne_bytes());
        bytes.extend(bad);
        let mut output = [91; MAX_RIGHTS];
        assert_eq!(
            control::decode_rights(&bytes, &mut output),
            Err(Error::Malformed)
        );
        assert_eq!(output, [91; MAX_RIGHTS]);
    }
    for (offset, value, expected) in [
        (8, 0i32, Error::UnsupportedControl),
        (12, 99i32, Error::UnsupportedControl),
        (16, -1i32, Error::InvalidDescriptor),
    ] {
        let mut bytes = prefix.clone();
        let mut bad = frame(&[8]);
        bad[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
        bytes.extend(bad);
        let mut output = [91; MAX_RIGHTS];
        assert_eq!(control::decode_rights(&bytes, &mut output), Err(expected));
        assert_eq!(output, [91; MAX_RIGHTS]);
    }
    let mut output = [91];
    assert_eq!(
        control::decode_rights(&frame(&[7, 8]), &mut output),
        Err(Error::BufferTooSmall)
    );
    assert_eq!(output, [91]);
}

#[test]
fn descriptor_limit_is_per_message_not_per_header_or_ipc_batch() {
    let mut bytes = frame(&[3; 200]);
    bytes.extend(frame(&[4; 53]));
    let mut output = [0; MAX_RIGHTS];
    assert_eq!(control::decode_rights(&bytes, &mut output), Ok(MAX_RIGHTS));
    assert_eq!(&output[..200], &[3; 200]);
    assert_eq!(&output[200..], &[4; 53]);
    bytes.extend(frame(&[5]));
    let saved = output;
    assert_eq!(
        control::decode_rights(&bytes, &mut output),
        Err(Error::TooManyDescriptors)
    );
    assert_eq!(output, saved);
}

#[test]
fn every_output_capacity_emits_only_whole_fds_and_reports_truncation() {
    let descriptors = [7, 8, 9];
    for capacity in 0..48 {
        let mut bytes = [0xa5; 48];
        let result = control::encode_rights(&descriptors, &mut bytes[..capacity]).unwrap();
        let count = (capacity.saturating_sub(HEADER_LEN) / 4).min(3);
        assert_eq!(result.descriptors, count);
        assert_eq!(result.truncated, count != 3);
        assert!(result.length <= capacity);
        assert!(bytes[result.length..].iter().all(|byte| *byte == 0xa5));
        let mut decoded = [0; 3];
        assert_eq!(
            control::decode_rights(&bytes[..result.length], &mut decoded),
            Ok(count)
        );
        assert_eq!(&decoded[..count], &descriptors[..count]);
    }
    let mut bytes = [0xa5; 32];
    assert_eq!(
        control::encode_rights(&[-1], &mut bytes),
        Err(Error::InvalidDescriptor)
    );
    assert_eq!(
        control::encode_rights(&[1; MAX_RIGHTS + 1], &mut bytes),
        Err(Error::TooManyDescriptors)
    );
    assert_eq!(control::encode_rights(&[], &mut bytes).unwrap().length, 0);
    assert_eq!(bytes, [0xa5; 32]);
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn encoded_control_interoperates_with_host_rights_and_shared_open_file_description() {
    use std::{
        ffi::c_void,
        fs::OpenOptions,
        io::{Read, Seek, SeekFrom, Write},
        os::fd::{AsRawFd, FromRawFd, OwnedFd},
        os::unix::net::UnixDatagram,
    };
    #[repr(C)]
    struct Iovec {
        base: *mut c_void,
        length: usize,
    }
    #[repr(C)]
    struct Message {
        name: *mut c_void,
        name_length: u32,
        vectors: *mut Iovec,
        vector_count: usize,
        control: *mut c_void,
        control_length: usize,
        flags: i32,
    }
    unsafe extern "C" {
        fn sendmsg(fd: i32, message: *const Message, flags: i32) -> isize;
        fn recvmsg(fd: i32, message: *mut Message, flags: i32) -> isize;
        fn fcntl(fd: i32, command: i32, ...) -> i32;
    }
    assert_eq!(core::mem::size_of::<Message>(), 56);
    let path = std::env::temp_dir().join(format!(
        "mochios-control-ofd-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    let mut original = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    std::fs::remove_file(&path).unwrap();
    original.write_all(b"abcdef").unwrap();
    original.seek(SeekFrom::Start(0)).unwrap();
    let (sender, receiver) = UnixDatagram::pair().unwrap();
    let mut data = [42u8];
    let mut vector = Iovec {
        base: data.as_mut_ptr().cast(),
        length: data.len(),
    };
    let mut bytes = frame(&[original.as_raw_fd(), original.as_raw_fd()]);
    let mut message = Message {
        name: core::ptr::null_mut(),
        name_length: 0,
        vectors: &mut vector,
        vector_count: 1,
        control: bytes.as_mut_ptr().cast(),
        control_length: bytes.len(),
        flags: 0,
    };
    assert_eq!(unsafe { sendmsg(sender.as_raw_fd(), &message, 0) }, 1);
    let mut received_control = [0u8; 64];
    message.control = received_control.as_mut_ptr().cast();
    message.control_length = received_control.len();
    assert_eq!(
        unsafe { recvmsg(receiver.as_raw_fd(), &mut message, 0x40000040) },
        1
    );
    assert_eq!(message.flags & 8, 0); // MSG_CTRUNC
    let mut received_fds = [-1; 2];
    assert_eq!(
        control::decode_rights(
            &received_control[..message.control_length],
            &mut received_fds
        ),
        Ok(2)
    );
    let [first, second] = received_fds.map(|fd| unsafe { OwnedFd::from_raw_fd(fd) });
    assert_ne!(first.as_raw_fd(), second.as_raw_fd());
    for fd in [&first, &second] {
        assert_eq!(unsafe { fcntl(fd.as_raw_fd(), 1) } & 1, 1); // FD_CLOEXEC
    }
    let mut first = std::fs::File::from(first);
    let mut second = std::fs::File::from(second);
    let mut prefix = [0; 2];
    first.read_exact(&mut prefix).unwrap();
    assert_eq!(&prefix, b"ab");
    second.read_exact(&mut prefix).unwrap();
    assert_eq!(&prefix, b"cd");
    original.read_exact(&mut prefix).unwrap();
    assert_eq!(&prefix, b"ef");

    // Compare every small receive capacity with the host's actual ancillary
    // truncation behavior. Own every returned FD immediately, including cases
    // with MSG_CTRUNC, so the test itself cannot leak installed references.
    for capacity in 0..40 {
        let mut sent = frame(&[original.as_raw_fd(); 3]);
        message.control = sent.as_mut_ptr().cast();
        message.control_length = sent.len();
        assert_eq!(unsafe { sendmsg(sender.as_raw_fd(), &message, 0) }, 1);
        received_control.fill(0);
        message.control = received_control.as_mut_ptr().cast();
        message.control_length = capacity;
        assert_eq!(
            unsafe { recvmsg(receiver.as_raw_fd(), &mut message, 0x40000040) },
            1
        );
        let mut numbers = [-1; 3];
        let count =
            control::decode_rights(&received_control[..message.control_length], &mut numbers)
                .unwrap();
        let owned: Vec<_> = numbers[..count]
            .iter()
            .map(|fd| unsafe { OwnedFd::from_raw_fd(*fd) })
            .collect();
        let mut expected = [0; 64];
        // Use valid placeholder numbers for references the host discarded;
        // only the prefix fitting capacity is serialized by encode_rights.
        numbers[count..].fill(0);
        let result = control::encode_rights(&numbers, &mut expected[..capacity]).unwrap();
        assert_eq!(result.descriptors, owned.len());
        assert_eq!(result.length, message.control_length);
        assert_eq!(result.truncated, message.flags & 8 != 0);
        assert_eq!(
            &expected[..result.length],
            &received_control[..message.control_length]
        );
    }
}
