//! Small wire fixtures; real linker output is covered in pie_symbols_linker.
pub fn encode(preinit: &[u64], objects: &[(&[u64], &[u64])]) -> Vec<u8> {
    use mochios_posix_client::lifecycle_image::{HEADER_BYTES, MAGIC, OBJECT_BYTES, VERSION};
    let calls = preinit.len()
        + objects
            .iter()
            .map(|(init, fini)| init.len() + fini.len())
            .sum::<usize>();
    let mut output = vec![0; HEADER_BYTES + OBJECT_BYTES * objects.len() + calls * 8];
    let length = output.len();
    let mut put = |at, value: u64| output[at..at + 8].copy_from_slice(&value.to_le_bytes());
    put(0, MAGIC);
    put(8, u64::from(VERSION) | ((objects.len() as u64) << 32));
    put(16, length as u64);
    put(24, preinit.len() as u64);
    let mut cursor = HEADER_BYTES + OBJECT_BYTES * objects.len();
    for &address in preinit {
        put(cursor, address);
        cursor += 8;
    }
    for (index, (init, fini)) in objects.iter().enumerate() {
        let descriptor = HEADER_BYTES + index * OBJECT_BYTES;
        put(descriptor, cursor as u64);
        put(descriptor + 8, init.len() as u64);
        for &address in *init {
            put(cursor, address);
            cursor += 8;
        }
        put(descriptor + 16, cursor as u64);
        put(descriptor + 24, fini.len() as u64);
        for &address in *fini {
            put(cursor, address);
            cursor += 8;
        }
    }
    output
}
