#[path = "support/native_error_probe.rs"]
mod probe;

fn run(test: &str) {
    let source = include_str!("../../package/src/main.rs");
    let mut program = probe::program();
    let mut statuses = String::new();
    probe::constants(
        &mut statuses,
        include_str!("../../../user/crates/posix-protocol/src/lib.rs"),
        &["STATUS_EEXIST"],
    );
    program = program.replacen(
        "mod mochios_posix_protocol {\n",
        &format!("mod mochios_posix_protocol {{\n{statuses}"),
        1,
    );
    program.push_str("mod signature_protocol {\n");
    program.push_str(
        include_str!("../../../user/crates/signature-protocol/src/lib.rs")
            .strip_prefix("#![no_std]")
            .unwrap(),
    );
    program.push_str("}\nuse signature_protocol::{InstallProvenance,InstallRecord,InstallRecordView,VerifiedResponse};\n");
    probe::constants(
        &mut program,
        source,
        &[
            "SIGNATURE_SYNC_RETRY_ATTEMPTS",
            "SIGNATURE_SYNC_RETRY_DELAY_MS",
            "FILE_MODE_755",
            "O_WRONLY",
            "O_CREAT",
            "O_EXCL",
            "FILE_WRITE_CHUNK_LEN",
        ],
    );
    program.push_str("#[derive(Debug,PartialEq,Eq)]\n");
    program.push_str(probe::between(
        source,
        "struct VerifiedPackage {",
        "\nfn diagnostic(",
    ));
    program.push_str(probe::between(
        source,
        "#[derive(Clone, Copy, Debug, PartialEq, Eq)]\nenum SignerContinuity",
        "#[derive(Clone, Copy, Debug, PartialEq, Eq)]\nenum PackageMutation",
    ));
    program.push_str(r#"
use std::{cell::RefCell,collections::VecDeque};
struct State {
    stat:Result<(),SysError>, read:Result<Vec<u8>,SysError>,
    verify:VecDeque<Result<VerifiedPackage,SysError>>, mkdir:VecDeque<Result<(),SysError>>,
    remove:VecDeque<Result<(),SysError>>, events:Vec<String>, diagnostics:Vec<String>, sleeps:usize,
}
impl Default for State {fn default()->Self{Self{
    stat:Ok(()),read:Ok(vec![]),verify:VecDeque::new(),mkdir:VecDeque::new(),remove:VecDeque::new(),
    events:vec![],diagnostics:vec![],sleeps:0,
}}}
thread_local!{static STATE:RefCell<State>=RefCell::new(State::default());}
fn error(status:u64)->SysError{SysError::from_raw(status as i64)}
fn diagnostic(message:&str){STATE.with_borrow_mut(|s|s.diagnostics.push(message.to_string()));}
fn verified()->VerifiedPackage{VerifiedPackage{
    provenance:InstallProvenance::VerifiedPackage,developer_id:"developer".into(),certificate_serial:1,
    subject_key_id:[2;32],verified_package_id:"org.test".into(),allowed_capabilities:vec![],manifest_digest:[3;32],package_digest:[4;32],
}}
fn verify_with_signature_service(path:&str)->Result<VerifiedPackage,SysError>{
    assert_eq!(path,"/incoming.mpkg");STATE.with_borrow_mut(|s|{s.events.push("verify".into());s.verify.pop_front().expect("extra verification")})
}
mod platform {
    pub mod thread {
        pub fn sleep_milliseconds(delay:u64)->Result<(),crate::SysError>{
            assert_eq!(delay,crate::SIGNATURE_SYNC_RETRY_DELAY_MS);crate::STATE.with_borrow_mut(|s|s.sleeps+=1);Ok(())
        }
    }
    pub mod handle {
        pub fn write(handle:u64,bytes:&[u8])->Result<usize,crate::SysError>{
            assert_eq!(handle,47);assert_eq!(bytes,b"payload");crate::STATE.with_borrow_mut(|s|s.events.push("write".into()));Ok(bytes.len())
        }
    }
}
enum StatAtBase {ProcessRoot}
struct Client;
impl Client {fn stat_at(&self,_:StatAtBase,flags:u32,path:&str)->Result<(),SysError>{
    assert_eq!(flags,0);assert_eq!(path,"/target");STATE.with_borrow_mut(|s|{s.events.push("stat".into());s.stat})
}}
mod posix_io {
    use super::*;
    fn with_client<T>(operation:impl FnOnce(&Client)->Result<T,SysError>)->Result<T,SysError>{operation(&Client)}
    pub fn create_dir(path:&str,mode:u64)->Result<(),SysError>{
        assert_eq!(mode,FILE_MODE_755);STATE.with_borrow_mut(|s|{s.events.push(format!("mkdir:{path}"));s.mkdir.pop_front().expect("extra mkdir")})
    }
    pub fn open_path(path:&str,flags:u64,mode:u64)->Result<u64,SysError>{
        assert_eq!(path,"/applications/Test.app/main");assert_eq!(flags,O_WRONLY|O_CREAT|O_EXCL);assert_eq!(mode,0o644);
        STATE.with_borrow_mut(|s|s.events.push("open".into()));Ok(47)
    }
    pub fn sync(handle:u64)->Result<(),SysError>{assert_eq!(handle,47);STATE.with_borrow_mut(|s|s.events.push("sync".into()));Ok(())}
    pub fn close(handle:u64)->Result<(),SysError>{assert_eq!(handle,47);STATE.with_borrow_mut(|s|s.events.push("close".into()));Ok(())}
    pub fn remove(path:&str)->Result<(),SysError>{STATE.with_borrow_mut(|s|{s.events.push(format!("remove:{path}"));s.remove.pop_front().expect("extra remove")})}
    pub fn read_to_end_path(path:&str)->Result<Vec<u8>,SysError>{assert_eq!(path,"/record");STATE.with_borrow(|s|s.read.clone())}
"#);
    program.push_str(probe::between(
        include_str!("../../package/src/posix_io.rs"),
        "pub fn path_exists(",
        "\npub fn read_to_end_path(",
    ));
    program.push_str("}\n");
    program.push_str(probe::between(
        source,
        "fn verify_when_database_ready(",
        "\nfn notify_package_index_changed(",
    ));
    program.push_str(probe::between(
        source,
        "fn validate_update_owner(",
        "\nfn install_package(",
    ));
    program.push_str(r#"
fn exists(){
    STATE.set(State::default());assert_eq!(posix_io::path_exists("/target"),Ok(true));
    STATE.with_borrow_mut(|s|s.stat=Err(error(ENOENT)));assert_eq!(posix_io::path_exists("/target"),Ok(false));
    for status in [EACCES,EIO,mochios_posix_protocol::STATUS_ENOTDIR as u64] {
        STATE.with_borrow_mut(|s|s.stat=Err(error(status)));assert_eq!(posix_io::path_exists("/target"),Err(error(status)));
    }
}
fn signature(){
    STATE.set(State{verify:vec![Err(error(EAGAIN)),Ok(verified())].into(),..State::default()});
    assert_eq!(verify_when_database_ready("/incoming.mpkg"),Ok(verified()));
    STATE.with_borrow(|s|{assert_eq!(s.sleeps,1);assert!(s.verify.is_empty());});
    STATE.set(State{verify:std::iter::repeat_with(||Err(error(EAGAIN))).take(SIGNATURE_SYNC_RETRY_ATTEMPTS+1).collect(),..State::default()});
    assert_eq!(verify_when_database_ready("/incoming.mpkg"),Err(error(EAGAIN)));
    STATE.with_borrow(|s|{assert_eq!(s.sleeps,SIGNATURE_SYNC_RETRY_ATTEMPTS);assert!(s.verify.is_empty());});
    for status in [EACCES,EIO,ENOENT] {
        STATE.set(State{verify:vec![Err(error(status))].into(),..State::default()});
        assert_eq!(verify_when_database_ready("/incoming.mpkg"),Err(error(status)));
        STATE.with_borrow(|s|{assert_eq!(s.sleeps,0);assert!(s.verify.is_empty());});
    }
}
fn parents(){
    let exists = mochios_posix_protocol::STATUS_EEXIST as i64 as u64;
    for results in [vec![Ok(()),Ok(())],vec![Err(error(exists)),Err(error(exists))],vec![Ok(()),Err(error(exists))]] {
        STATE.set(State{mkdir:results.into(),..State::default()});
        assert_eq!(write_file("/applications/Test.app/main",b"payload",0o644),Ok(()));
        STATE.with_borrow(|s|assert_eq!(s.events,["mkdir:/applications","mkdir:/applications/Test.app","open","write","sync","close"]));
    }
    for status in [EACCES,EIO,NativeError::AlreadyExists.into_raw()] {
        STATE.set(State{mkdir:vec![Err(error(status))].into(),..State::default()});
        assert_eq!(write_file("/applications/Test.app/main",b"payload",0o644),Err(error(status)));
        STATE.with_borrow(|s|assert_eq!(s.events,["mkdir:/applications"]));
    }
}
fn rollback(){
    STATE.set(State{remove:vec![Err(error(ENOENT)),Err(error(EACCES)),Ok(())].into(),..State::default()});
    rollback_created_files(&["/first".into(),"/second".into(),"/third".into()]);
    STATE.with_borrow(|s|{
        assert_eq!(s.events,["remove:/third","remove:/second","remove:/first"]);
        assert_eq!(s.diagnostics.len(),1);assert!(s.diagnostics[0].contains("path=/second"));
    });
}
fn owner(){
    STATE.set(State{read:Err(error(ENOENT)),..State::default()});
    assert_eq!(validate_update_owner("/record",&verified()),Ok(SignerContinuity::NewInstall));
    for status in [EACCES,EIO,mochios_posix_protocol::STATUS_ENOTDIR as u64] {
        STATE.with_borrow_mut(|s|s.read=Err(error(status)));
        assert_eq!(validate_update_owner("/record",&verified()),Err(error(status)));
    }
    STATE.with_borrow_mut(|s|s.read=Ok(vec![0;8]));
    assert_eq!(validate_update_owner("/record",&verified()),Err(error(EACCES)));
    let record=InstallRecord{provenance:InstallProvenance::VerifiedPackage,verification:VerifiedResponse{
        request_id:1,provenance:InstallProvenance::VerifiedPackage,developer_id:"developer",certificate_serial:1,subject_key_id:[2;32],verified_package_id:"org.test",
        allowed_capabilities:&[],manifest_digest:[3;32],package_digest:[4;32],
    }};
    let mut bytes=vec![0;record.encoded_len()];record.encode(&mut bytes).unwrap();
    STATE.with_borrow_mut(|s|s.read=Ok(bytes));
    assert_eq!(validate_update_owner("/record",&verified()),Ok(SignerContinuity::SameSigningKey));
    for field in 0..3 {
        let mut incoming=verified();match field{0=>incoming.verified_package_id.push('x'),1=>incoming.developer_id.push('x'),_=>incoming.subject_key_id[0]^=1};
        assert_eq!(validate_update_owner("/record",&incoming),Err(error(EACCES)));
    }
}
"#);
    program.push_str(&format!("fn main(){{{test}();}}\n"));
    probe::run(&program);
}

#[test]
fn missing_path_is_distinct_from_access_or_io_failure() {
    run("exists");
}
#[test]
fn signature_database_wait_is_bounded_and_retries_only_not_ready() {
    run("signature");
}
#[test]
fn existing_parents_do_not_prevent_exclusive_file_creation() {
    run("parents");
}
#[test]
fn rollback_ignores_only_already_absent_files() {
    run("rollback");
}
#[test]
fn only_absent_install_record_is_a_new_install() {
    run("owner");
}
