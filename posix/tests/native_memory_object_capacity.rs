//! Run with the default native per-object extent ceiling (65536 pages).
#[cfg(not(target_os = "mochios"))]
fn main() {
    eprintln!("native-memory-object-capacity: requires mochiOS");
}

#[cfg(target_os = "mochios")]
fn main() {
    use mochi_user_platform as p;
    use mochi_user_syscall::{NativeError, SyscallNumber as S, call2};
    const CEILING: u64 = 256 * 1024 * 1024;
    let object = p::memory_object::MemoryObject::create_resizable(CEILING).unwrap();
    assert_eq!(object.length().unwrap(), CEILING);
    let offset = 32 * 1024 * 1024 - 3;
    let bytes = b"native-capacity325";
    assert_eq!(
        p::handle::write_at(object.handle(), bytes, offset).unwrap(),
        bytes.len()
    );
    let mut copy = [0; 18];
    assert_eq!(
        p::handle::read_at(object.handle(), &mut copy, offset).unwrap(),
        bytes.len()
    );
    assert_eq!(&copy, bytes);
    assert_eq!(
        call2(S::MemoryObjectResize, object.handle() as u64, CEILING + 1)
            .unwrap_err()
            .raw(),
        NativeError::ResourceUnavailable.into_raw() as i64
    );
    assert_eq!(object.length().unwrap(), CEILING);
    assert_eq!(
        p::memory_object::MemoryObject::create_resizable(CEILING + 1)
            .err()
            .unwrap()
            .raw(),
        NativeError::ResourceUnavailable.into_raw() as i64
    );
    println!(
        "memory-object-capacity-325: PASS large sparse native RAM, cross-page IO and retained resize ceiling"
    );
}
