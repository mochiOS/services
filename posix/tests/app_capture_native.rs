#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn executable_capture_uses_bounded_shared_reads_and_preserves_short_reads_and_errors() {
    let mut program = probe::program();
    program.push_str(
        r#"
use std::cell::RefCell;
type Error = SysError;
mod errno {pub const EIO:i32=5;pub const ENOMEM:i32=12;pub const EFBIG:i32=27;}
fn status(errno:i32)->Error {SysError::from_raw(-i64::from(errno))}
mod limits {pub const IMAGE:usize=1024*1024;pub const READ:usize=256*1024;}
#[derive(Default)]
struct Source {bytes:Vec<u8>,position:usize,short:usize,calls:usize,fail:Option<usize>,invalid:bool}
thread_local! {static SOURCE:RefCell<Source>=RefCell::default();}
mod p {pub mod handle {
    pub fn read_at(handle:u32,out:&mut[u8],offset:u64)->Result<usize,crate::Error>{
        assert_eq!(handle,42);assert_eq!(out.len(),crate::limits::READ);
        crate::SOURCE.with_borrow_mut(|s|{
            assert_eq!(offset,s.position as u64);s.calls+=1;
            if s.fail==Some(s.calls){return Err(crate::NativeError::PeerClosed.into_raw().into());}
            if s.invalid{return Ok(out.len()+1);}
            let n=(s.bytes.len()-s.position).min(out.len()).min(s.short);
            out[..n].copy_from_slice(&s.bytes[s.position..s.position+n]);s.position+=n;Ok(n)
        })
    }
}}
"#,
    );
    let capture = probe::between(
        include_str!("../../capability/src/app_image.rs"),
        "pub(crate) fn capture(",
        "\npub(crate) fn readonly(",
    );
    program.push_str(
        &capture
            .replace("mnu_abi::provider::MAX_SHARED_READ_LEN", "limits::READ")
            .replace("mnu_abi::exec::MAX_CAPTURED_IMAGE_BYTES", "limits::IMAGE"),
    );
    program.push_str(
        r#"
fn source(length:usize,short:usize) {
    SOURCE.set(Source {bytes:(0..length).map(|i|(i%251)as u8).collect(),short,..Source::default()});
}
fn main(){
    for length in [0,1,limits::READ*2+73,limits::IMAGE] {
        for short in [17003,limits::READ] {
            source(length,short);
            let bytes=capture(42).unwrap();
            SOURCE.with_borrow(|s|{
                assert_eq!(bytes,s.bytes);
                assert_eq!(s.calls,length.div_ceil(short)+1);
            });
        }
    }
    source(limits::IMAGE+1,limits::READ);
    assert_eq!(capture(42),Err(status(errno::EFBIG)));
    for call in [1,2,3] {
        source(limits::READ*3,limits::READ);
        SOURCE.with_borrow_mut(|s|s.fail=Some(call));
        assert_eq!(capture(42),Err(NativeError::PeerClosed.into_raw().into()));
        SOURCE.with_borrow(|s|assert_eq!(s.calls,call));
    }
    source(1,limits::READ);SOURCE.with_borrow_mut(|s|s.invalid=true);
    assert_eq!(capture(42),Err(status(errno::EIO)));
}
"#,
    );
    probe::run(&program);
}
