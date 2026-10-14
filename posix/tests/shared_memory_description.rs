use mnu_abi::{HANDLE_SEEK_CURRENT, HANDLE_SEEK_END, HANDLE_SEEK_START};
use posix_service::shared_memory_file::{Backing, Descriptions};

#[derive(Default)]
struct Ram {
    bytes: Vec<u8>,
    references: usize,
    fail: bool,
    oversized_read: bool,
}

impl Backing<u32> for Ram {
    fn retain(&mut self, handle: u32) -> Result<u32, i32> {
        if self.fail {
            return Err(-12);
        }
        self.references += 1;
        Ok(handle)
    }
    fn close(&mut self, _: u32) -> Result<(), i32> {
        if self.fail {
            return Err(-5);
        }
        self.references -= 1;
        Ok(())
    }
    fn length(&mut self, _: u32) -> Result<u64, i32> {
        Ok(self.bytes.len() as u64)
    }
    fn resize(&mut self, _: u32, length: u64) -> Result<(), i32> {
        if self.fail {
            return Err(-12);
        }
        self.bytes.resize(length as usize, 0);
        Ok(())
    }
    fn read_at(&mut self, _: u32, offset: u64, output: &mut [u8]) -> Result<usize, i32> {
        if self.fail {
            return Err(-5);
        }
        if self.oversized_read {
            return Ok(output.len() + 1);
        }
        let start = (offset as usize).min(self.bytes.len());
        let count = output.len().min(self.bytes.len() - start);
        output[..count].copy_from_slice(&self.bytes[start..start + count]);
        Ok(count)
    }
    fn write_at(&mut self, _: u32, offset: u64, input: &[u8]) -> Result<usize, i32> {
        if self.fail {
            return Err(-5);
        }
        let start = offset as usize;
        self.bytes[start..start + input.len()].copy_from_slice(input);
        Ok(input.len())
    }
}

#[test]
fn separate_opens_and_aliases_have_correct_positions() {
    let mut ram = Ram::default();
    let mut descriptions = Descriptions::new();
    let first = descriptions.open(1, true, &mut ram).unwrap();
    let second = descriptions.open(1, true, &mut ram).unwrap();
    assert_ne!(first, second);
    assert_eq!(ram.references, 2);
    descriptions.write(first, b"abc", &mut ram).unwrap();
    assert_eq!(
        descriptions.seek(first, 0, HANDLE_SEEK_CURRENT, &mut ram),
        Ok(3)
    );
    let mut output = [0; 2];
    assert_eq!(descriptions.read(second, &mut output, &mut ram), Ok((0, 2)));
    assert_eq!(&output, b"ab");
    // Dup/fork retain the same Provider description ID, not another open.
    let alias = second;
    assert_eq!(descriptions.read(alias, &mut output, &mut ram), Ok((2, 1)));
    assert_eq!(
        descriptions.seek(second, 0, HANDLE_SEEK_CURRENT, &mut ram),
        Ok(3)
    );
    descriptions.write_at(first, 1, b"X", &mut ram).unwrap();
    assert_eq!(
        descriptions.seek(first, 0, HANDLE_SEEK_CURRENT, &mut ram),
        Ok(3)
    );
    assert_eq!(descriptions.read_at(first, 0, &mut output, &mut ram), Ok(2));
    assert_eq!(&output, b"aX");
    descriptions.resize(first, 1, &mut ram).unwrap();
    assert_eq!(descriptions.read(second, &mut output, &mut ram), Ok((3, 0)));
    descriptions.resize(first, 4, &mut ram).unwrap();
    assert_eq!(ram.bytes, b"a\0\0\0");
}

#[test]
fn append_and_sparse_writes_are_serialized_and_zero_filled() {
    let mut ram = Ram::default();
    let mut descriptions = Descriptions::new();
    let first = descriptions.open(1, true, &mut ram).unwrap();
    let second = descriptions.open(1, true, &mut ram).unwrap();
    descriptions.set_append(first, true).unwrap();
    descriptions.set_append(second, true).unwrap();
    for id in [first, second, first, second] {
        descriptions.write(id, b"x", &mut ram).unwrap();
    }
    assert_eq!(ram.bytes, b"xxxx");
    descriptions.set_append(first, false).unwrap();
    descriptions
        .seek(first, 8, HANDLE_SEEK_START, &mut ram)
        .unwrap();
    descriptions.write(first, b"y", &mut ram).unwrap();
    assert_eq!(ram.bytes, b"xxxx\0\0\0\0y");
    assert_eq!(
        descriptions.seek(second, -1, HANDLE_SEEK_END, &mut ram),
        Ok(8)
    );
    assert_eq!(descriptions.append(second), Ok(true));
    assert_eq!(descriptions.append(first), Ok(false));
}

#[test]
fn readonly_bounds_failures_and_final_release_preserve_state() {
    let mut ram = Ram::default();
    let mut descriptions = Descriptions::new();
    let readonly = descriptions.open(1, false, &mut ram).unwrap();
    assert_eq!(descriptions.mapping_backing(readonly, false), Ok(1));
    assert_eq!(descriptions.mapping_backing(readonly, true), Err(-13));
    assert_eq!(descriptions.resize(readonly, 2, &mut ram), Err(-9));
    assert_eq!(descriptions.write(readonly, b"x", &mut ram), Err(-9));
    assert_eq!(descriptions.write_at(readonly, 0, b"x", &mut ram), Err(-9));
    let writable = descriptions.open(1, true, &mut ram).unwrap();
    assert_eq!(
        descriptions.seek(writable, -1, HANDLE_SEEK_START, &mut ram),
        Err(-22)
    );
    assert_eq!(descriptions.seek(writable, 0, 99, &mut ram), Err(-22));
    descriptions
        .seek(writable, i64::MAX, HANDLE_SEEK_START, &mut ram)
        .unwrap();
    assert_eq!(descriptions.write(writable, b"x", &mut ram), Err(-27));
    assert_eq!(descriptions.write(writable, b"", &mut ram), Ok(0));
    assert_eq!(descriptions.resize(writable, u64::MAX, &mut ram), Err(-22));
    descriptions
        .seek(writable, 0, HANDLE_SEEK_START, &mut ram)
        .unwrap();
    ram.fail = true;
    assert_eq!(descriptions.write(writable, b"x", &mut ram), Err(-12));
    assert_eq!(descriptions.read(writable, &mut [0], &mut ram), Err(-5));
    assert_eq!(descriptions.release(writable, &mut ram), Err(-5));
    assert_eq!(descriptions.open(1, true, &mut ram), Err(-12));
    assert_eq!(ram.references, 2);
    ram.fail = false;
    ram.oversized_read = true;
    assert_eq!(descriptions.read(writable, &mut [0], &mut ram), Err(-5));
    assert_eq!(
        descriptions.seek(writable, 0, HANDLE_SEEK_CURRENT, &mut ram),
        Ok(0)
    );
    descriptions.release(readonly, &mut ram).unwrap();
    descriptions.release(writable, &mut ram).unwrap();
    assert_eq!(ram.references, 0);
    assert_eq!(descriptions.release(writable, &mut ram), Err(-9));
    assert_eq!(descriptions.length(writable, &mut ram), Err(-9));
    assert_eq!(descriptions.mapping_backing(writable, false), Err(-9));
}

fn frame(opcode: u16, id: u64, basis: u64, argument: i64, length: u32, data: &[u8]) -> Vec<u8> {
    let mut frame = vec![0; mnu_abi::provider::REQUEST_HEADER_LEN + data.len()];
    mnu_abi::provider::RequestHeader {
        opcode,
        object_id: id,
        argument,
        basis,
        length,
        data_length: data.len() as u32,
    }
    .encode(data, &mut frame)
    .unwrap();
    frame
}

#[test]
fn provider_frames_require_native_delivery_and_preflight_reply_capacity() {
    use mnu_abi::{IPC_DELIVERY_NATIVE_OBJECT, provider};
    use posix_service::shared_memory_file::handle_provider_request;
    let mut descriptions = Descriptions::new();
    let mut ram = Ram::default();
    let id = descriptions.open(1, true, &mut ram).unwrap();
    let mut reply = [0; provider::RESPONSE_HEADER_LEN + provider::MAX_DATA_LEN];
    let write = frame(provider::OP_WRITE, id, 0, 0, 3, b"abc");
    for (flags, count, status) in [
        (0, 0, -13),
        (3, 0, -13),
        (IPC_DELIVERY_NATIVE_OBJECT, 1, -22),
    ] {
        let length = handle_provider_request(
            &mut descriptions,
            &write,
            flags,
            count,
            &mut ram,
            &mut reply,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            provider::ResponseHeader::decode(&reply[..length])
                .unwrap()
                .0
                .status,
            status
        );
        assert!(ram.bytes.is_empty());
    }
    assert_eq!(
        handle_provider_request(
            &mut descriptions,
            &write,
            IPC_DELIVERY_NATIVE_OBJECT,
            0,
            &mut ram,
            &mut [0; 1]
        ),
        Err(-22)
    );
    assert!(ram.bytes.is_empty());
    let length = handle_provider_request(
        &mut descriptions,
        &write,
        IPC_DELIVERY_NATIVE_OBJECT,
        0,
        &mut ram,
        &mut reply,
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        provider::ResponseHeader::decode(&reply[..length])
            .unwrap()
            .0
            .value,
        3
    );
    descriptions
        .seek(id, 0, HANDLE_SEEK_START, &mut ram)
        .unwrap();
    let read = frame(provider::OP_READ_WITH_POSITION, id, 0, 0, 2, &[]);
    assert_eq!(
        handle_provider_request(
            &mut descriptions,
            &read,
            IPC_DELIVERY_NATIVE_OBJECT,
            0,
            &mut ram,
            &mut [0; provider::RESPONSE_HEADER_LEN]
        ),
        Err(-22)
    );
    let length = handle_provider_request(
        &mut descriptions,
        &read,
        IPC_DELIVERY_NATIVE_OBJECT,
        0,
        &mut ram,
        &mut reply,
    )
    .unwrap()
    .unwrap();
    let (header, data) = provider::ResponseHeader::decode(&reply[..length]).unwrap();
    assert_eq!(header.value, 2);
    assert_eq!(&data[..8], &0u64.to_le_bytes());
    assert_eq!(&data[8..], b"ab");
    let release = frame(provider::OP_RELEASE, id, 0, 0, 0, &[]);
    handle_provider_request(&mut descriptions, &release, 0, 0, &mut ram, &mut reply).unwrap();
    assert_eq!(ram.references, 1);
    assert_eq!(
        handle_provider_request(
            &mut descriptions,
            &release,
            IPC_DELIVERY_NATIVE_OBJECT,
            0,
            &mut ram,
            &mut reply
        ),
        Ok(None)
    );
    assert_eq!(ram.references, 0);
}

#[test]
fn provider_seek_positioned_io_and_unsupported_requests_have_valid_responses() {
    use mnu_abi::{IPC_DELIVERY_NATIVE_OBJECT, provider};
    use posix_service::shared_memory_file::handle_provider_request;
    let mut descriptions = Descriptions::new();
    let mut ram = Ram::default();
    let id = descriptions.open(1, true, &mut ram).unwrap();
    let mut reply = [0; provider::RESPONSE_HEADER_LEN + provider::MAX_DATA_LEN];
    for (request, expected_value, expected_data, expected_status) in [
        (
            frame(provider::OP_WRITE_AT, id, 2, 0, 2, b"xy"),
            2,
            &b""[..],
            0,
        ),
        (
            frame(provider::OP_READ_AT, id, 1, 0, 3, &[]),
            3,
            &b"\0xy"[..],
            0,
        ),
        (
            frame(provider::OP_SEEK, id, HANDLE_SEEK_END, -1, 0, &[]),
            3,
            &b""[..],
            0,
        ),
        (frame(provider::OP_READ, id, 0, 0, 2, &[]), 1, &b"y"[..], 0),
        (frame(provider::OP_SYNC, id, 0, 0, 0, &[]), 0, &b""[..], 0),
        (
            frame(provider::OP_MEMORY_OBJECT, id, 0, 0, 0, &[]),
            0,
            &b""[..],
            -95,
        ),
        (
            frame(provider::OP_READ, id + 1, 0, 0, 0, &[]),
            0,
            &b""[..],
            -9,
        ),
    ] {
        let length = handle_provider_request(
            &mut descriptions,
            &request,
            IPC_DELIVERY_NATIVE_OBJECT,
            0,
            &mut ram,
            &mut reply,
        )
        .unwrap()
        .unwrap();
        let (header, data) = provider::ResponseHeader::decode(&reply[..length]).unwrap();
        assert_eq!(
            (header.value, data, header.status),
            (expected_value, expected_data, expected_status)
        );
    }
    let mut invalid = frame(provider::OP_WRITE, id, 0, 0, 1, b"z");
    invalid[40] = 1;
    assert_eq!(
        handle_provider_request(
            &mut descriptions,
            &invalid,
            IPC_DELIVERY_NATIVE_OBJECT,
            0,
            &mut ram,
            &mut reply
        ),
        Err(-22)
    );
    assert_eq!(ram.bytes, b"\0\0xy");
}

#[test]
fn provider_extent_control_enforces_access_and_exact_wire_lengths() {
    use mnu_abi::{IPC_DELIVERY_NATIVE_OBJECT, provider};
    use mochios_posix_protocol::shared_memory as wire;
    use posix_service::shared_memory_file::handle_provider_request;
    let mut descriptions = Descriptions::new();
    let mut ram = Ram::default();
    let writable = descriptions.open(1, true, &mut ram).unwrap();
    let readonly = descriptions.open(1, false, &mut ram).unwrap();
    let mut reply = [0; provider::RESPONSE_HEADER_LEN + 8];
    for (id, code, input, capacity, expected_status, expected_length) in [
        (
            readonly,
            wire::CONTROL_RESIZE,
            5u64.to_le_bytes().to_vec(),
            0,
            -9,
            0,
        ),
        (writable, wire::CONTROL_RESIZE, vec![0; 7], 0, -22, 0),
        (
            writable,
            wire::CONTROL_RESIZE,
            5u64.to_le_bytes().to_vec(),
            1,
            -22,
            0,
        ),
        (
            writable,
            wire::CONTROL_RESIZE,
            u64::MAX.to_le_bytes().to_vec(),
            0,
            -22,
            0,
        ),
        (
            writable,
            wire::CONTROL_RESIZE,
            5u64.to_le_bytes().to_vec(),
            0,
            0,
            5,
        ),
        (readonly, wire::CONTROL_LENGTH, vec![], 7, -22, 5),
        (readonly, wire::CONTROL_LENGTH, vec![0], 8, -22, 5),
        (readonly, wire::CONTROL_LENGTH, vec![], 8, 0, 5),
    ] {
        let request = frame(provider::OP_CONTROL, id, code, 0, capacity, &input);
        let length = handle_provider_request(
            &mut descriptions,
            &request,
            IPC_DELIVERY_NATIVE_OBJECT,
            0,
            &mut ram,
            &mut reply,
        )
        .unwrap()
        .unwrap();
        let (header, data) = provider::ResponseHeader::decode(&reply[..length]).unwrap();
        assert_eq!(header.status, expected_status);
        assert_eq!(ram.bytes.len(), expected_length);
        if code == wire::CONTROL_LENGTH && header.status == 0 {
            assert_eq!(data, &5u64.to_le_bytes());
        }
    }
    assert_eq!(
        descriptions.seek(writable, 0, HANDLE_SEEK_CURRENT, &mut ram),
        Ok(0)
    );
    assert_eq!(ram.bytes, [0; 5]);
}
