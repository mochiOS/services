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
}
