use ext4plus::{Ext4, Ext4Read};
use filesystem_service::service::{FilesystemService, PathAnchors};
use mochios_filesystem_protocol::{self as protocol, whole_file_lock as wire};
use std::{path::PathBuf, process::Command};

struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
struct Image(Vec<u8>);
impl Ext4Read for Image {
    fn read(
        &self,
        offset: u64,
        output: &mut [u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let start = usize::try_from(offset)?;
        output.copy_from_slice(
            self.0
                .get(start..start.checked_add(output.len()).ok_or("overflow")?)
                .ok_or("outside image")?,
        );
        Ok(())
    }
}
fn fixture() -> (Fixture, FilesystemService) {
    let dir = std::env::temp_dir().join(format!("mochi-flock-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("source")).unwrap();
    let fixture = Fixture(dir);
    std::fs::write(fixture.0.join("source/file"), b"data").unwrap();
    std::fs::hard_link(
        fixture.0.join("source/file"),
        fixture.0.join("source/alias"),
    )
    .unwrap();
    let image = fixture.0.join("fs.img");
    std::fs::File::create(&image)
        .unwrap()
        .set_len(8 * 1024 * 1024)
        .unwrap();
    let output = Command::new("mke2fs")
        .args(["-q", "-t", "ext4", "-I", "256", "-F", "-d"])
        .arg(fixture.0.join("source"))
        .arg(&image)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let fs = Ext4::load(Box::new(Image(std::fs::read(image).unwrap()))).unwrap();
    (fixture, FilesystemService::new(fs))
}
fn open(service: &mut FilesystemService, name: &[u8]) -> u64 {
    let mut bytes = [0; protocol::CREDENTIALS_MAX_LEN];
    let n = protocol::encode_credentials_payload(0, 0, &[], &[], &mut bytes).unwrap();
    let credentials = protocol::decode_credentials_payload(&bytes[..n]).unwrap().0;
    service
        .open_at(
            protocol::Header {
                opcode: protocol::OP_OPEN_AT,
                flags: protocol::OPEN_AT_READ,
                ..Default::default()
            },
            name,
            PathAnchors::default(),
            credentials,
        )
        .unwrap()
        .header
        .open_id
}
fn lock(service: &mut FilesystemService, id: u64, mode: u32) -> Result<(), i32> {
    let mut header = mnu_abi::provider::RequestHeader {
        opcode: 0,
        object_id: 0,
        argument: 0,
        basis: 0,
        length: 0,
        data_length: 0,
    };
    header.opcode = mnu_abi::provider::OP_CONTROL;
    header.basis = wire::UPDATE;
    header.object_id = id;
    header.data_length = 4;
    filesystem_service::whole_file_lock::handle(service, header, &mode.to_le_bytes(), 0).map(|_| ())
}

#[test]
fn real_ext4_descriptions_conflict_across_hard_links_and_release_on_final_provider_close() {
    let (_fixture, mut fs) = fixture();
    let a = open(&mut fs, b"/file");
    let b = open(&mut fs, b"/alias");
    assert_ne!(a, b);
    assert_eq!(lock(&mut fs, a, wire::EXCLUSIVE), Ok(()));
    assert_eq!(lock(&mut fs, b, wire::SHARED), Err(11));
    assert_eq!(lock(&mut fs, a, wire::EXCLUSIVE), Ok(()));
    assert_eq!(lock(&mut fs, a, wire::SHARED), Ok(()));
    assert_eq!(lock(&mut fs, b, wire::SHARED), Ok(()));
    assert_eq!(lock(&mut fs, a, wire::EXCLUSIVE), Err(11));
    // Failed conversion released A's prior shared lock; B can now convert.
    assert_eq!(lock(&mut fs, b, wire::EXCLUSIVE), Ok(()));
    fs.provider_close(a).unwrap();
    let c = open(&mut fs, b"/file");
    assert_eq!(lock(&mut fs, c, wire::EXCLUSIVE), Err(11));
    fs.provider_close(b).unwrap();
    assert_eq!(lock(&mut fs, c, wire::EXCLUSIVE), Ok(()));
    assert_eq!(lock(&mut fs, c, wire::UNLOCK), Ok(()));
    assert_eq!(lock(&mut fs, c, wire::UNLOCK), Ok(()));
    assert_eq!(lock(&mut fs, b, wire::SHARED), Err(9));
    assert_eq!(lock(&mut fs, c, 3), Err(22));
}
