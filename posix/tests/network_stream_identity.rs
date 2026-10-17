//! Execute the actual HTTP/TLS stream lookup methods with service-local IDs.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn missing_streams_and_foreign_owners_remain_distinct_without_kernel_fd_errors() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let mut program = probe::program();
    program.push_str(&format!(
        "#[path={:?}]mod wire;use wire as mochios_net_device_protocol;\n",
        root.join("user/crates/net-device-protocol/src/lib.rs"),
    ));
    program.push_str(
        r#"
use wire::{HttpFailure,TlsFailure};
struct Record{handle:u64,owner:u64}
struct HttpManager{responses:Vec<Record>}
struct TlsManager{sessions:Vec<Record>}
#[derive(Debug,PartialEq)]struct HttpOperationError{errno:u64,failure:HttpFailure}
#[derive(Debug,PartialEq)]struct TlsOperationError{errno:u64,failure:TlsFailure}
impl HttpManager{
"#,
    );
    let http = include_str!("../../network/src/http.rs");
    let tls = include_str!("../../network/src/tls.rs");
    program.push_str(probe::between(
        http,
        "    fn response_index(",
        "    fn allocate_handle(",
    ));
    program.push_str("}\nimpl TlsManager{\n");
    program.push_str(probe::between(
        tls,
        "    fn session_index(",
        "    fn allocate_handle(",
    ));
    program.push_str("}\n");
    program.push_str(&http[http.find("const fn error(").unwrap()..]);
    program.push_str(probe::between(
        tls,
        "const fn operation_error(",
        "#[cfg(test)]",
    ));
    program.push_str(r#"
fn main(){
    assert_eq!(wire::STATUS_INVALID_STREAM,-9);
    let http=HttpManager{responses:vec![Record{handle:41,owner:7},Record{handle:43,owner:9}]};
    let tls=TlsManager{sessions:vec![Record{handle:41,owner:7},Record{handle:43,owner:9}]};
    assert_eq!(http.response_index(7,41),Ok(0));assert_eq!(tls.session_index(7,41),Ok(0));
    assert_eq!(http.response_index(9,43),Ok(1));assert_eq!(tls.session_index(9,43),Ok(1));
    for (owner,handle,expected) in [(9,41,-13_i64),(7,43,-13),(7,0,-9),(7,42,-9),(9,u64::MAX,-9)]{
        let h=http.response_index(owner,handle).unwrap_err();
        let t=tls.session_index(owner,handle).unwrap_err();
        assert_eq!(h.errno as i64,expected);assert_eq!(t.errno as i64,expected);
        assert_eq!(h.failure,HttpFailure::InvalidState);assert_eq!(t.failure,TlsFailure::InvalidState);
    }
    assert_eq!(http.responses.len(),2);assert_eq!(tls.sessions.len(),2);
}
"#);
    probe::run(&program);
}
