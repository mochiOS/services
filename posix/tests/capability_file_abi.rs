#[test]
fn runtime_capability_digest_reads_use_the_installed_posix_endpoint() {
    let grant = include_str!("../../capability/src/dynamic_grant.rs");
    let server = include_str!("../../capability/src/server.rs");
    let reader = include_str!("../../capability/src/persistent_grant.rs");
    assert!(!grant.contains("platform::file::"));
    assert!(!server.contains("platform::file::"));
    assert!(grant.contains("read_file(executable)?"));
    assert!(server.contains("crate::persistent_grant::read_file(path)?"));
    let start = reader.find("pub(crate) fn read_file(").unwrap();
    let end = reader[start..].find("\nfn path_exists(").unwrap() + start;
    let operation = &reader[start..end];
    assert!(operation.contains("client.open_at(OpenAtBase::ProcessRoot, posix::OPEN_READ"));
    assert!(operation.contains("platform::handle::read(file.handle"));
    assert!(operation.contains("platform::handle::close(file.handle)"));
    assert!(!operation.contains("platform::file::"));
    assert!(!reader.contains("find_by_name"));
    assert!(reader.contains("ok_or_else(|| sys_error(mochi_user_syscall::EAGAIN))"));
}
