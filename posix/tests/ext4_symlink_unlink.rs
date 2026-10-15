use std::{
    error::Error,
    fs, io,
    process::Command,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use ext4plus::{dir::Dir, path::PathBuf, DirEntryName, Ext4, Ext4Read, Ext4Write};

#[derive(Clone)]
struct Image(Arc<Mutex<Vec<u8>>>);
struct Directory(std::path::PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
impl Ext4Read for Image {
    fn read(&self, offset: u64, output: &mut [u8]) -> Result<(), Box<dyn Error + Send + Sync>> {
        let start = usize::try_from(offset)?;
        let end = start
            .checked_add(output.len())
            .ok_or_else(|| io::Error::other("overflow"))?;
        output.copy_from_slice(
            self.0
                .lock()
                .unwrap()
                .get(start..end)
                .ok_or_else(|| io::Error::other("outside image"))?,
        );
        Ok(())
    }
}
impl Ext4Write for Image {
    fn write(&self, offset: u64, input: &[u8]) -> Result<(), Box<dyn Error + Send + Sync>> {
        let start = usize::try_from(offset)?;
        let end = start
            .checked_add(input.len())
            .ok_or_else(|| io::Error::other("overflow"))?;
        self.0
            .lock()
            .unwrap()
            .get_mut(start..end)
            .ok_or_else(|| io::Error::other("outside image"))?
            .copy_from_slice(input);
        Ok(())
    }
}

#[test]
fn inline_and_block_backed_symlinks_read_and_unlink_without_treating_text_as_blocks() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory =
        std::env::temp_dir().join(format!("mochios-fastlink-{}-{nonce}", std::process::id()));
    fs::create_dir(&directory).unwrap();
    let _owned = Directory(directory.clone());
    let path = directory.join("volume.ext4");
    let created = Command::new("mke2fs")
        .args(["-q", "-t", "ext4", "-F"])
        .arg(&path)
        .arg("8192")
        .output()
        .unwrap();
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    let image = Image(Arc::new(Mutex::new(fs::read(&path).unwrap())));
    let volume =
        Ext4::load_with_writer(Box::new(image.clone()), Some(Box::new(image.clone()))).unwrap();
    let mut root = Dir::open_inode(&volume, volume.read_root_inode().unwrap()).unwrap();
    for length in [1, 30, 59, 60, 61, 255, 4095] {
        let name = format!("link-{length}");
        let name = DirEntryName::try_from(name.as_str()).unwrap();
        let mut target = vec![b'x'; length];
        for separator in (63..length).step_by(64) {
            target[separator] = b'/';
        }
        let inode = volume
            .symlink(
                &mut root,
                name,
                PathBuf::try_from(target.as_slice()).unwrap(),
                0,
                0,
                Duration::ZERO,
            )
            .unwrap();
        assert_eq!(inode.blocks() == 0, length < 60);
        assert_eq!(inode.symlink_target(&volume).unwrap().as_ref(), target);
        assert!(root.unlink(name, inode).unwrap().is_none());
    }
    // Reuse released inode slots and blocks, not just fresh ones.
    for iteration in 0..32 {
        let name = DirEntryName::try_from("reuse").unwrap();
        let target = if iteration % 2 == 0 {
            b"/tmp/inline".to_vec()
        } else {
            vec![b'x'; 61]
        };
        let inode = volume
            .symlink(
                &mut root,
                name,
                PathBuf::try_from(target.as_slice()).unwrap(),
                0,
                0,
                Duration::ZERO,
            )
            .unwrap();
        assert_eq!(inode.symlink_target(&volume).unwrap().as_ref(), target);
        assert!(root.unlink(name, inode).unwrap().is_none());
    }
    drop(root);
    drop(volume);
    fs::write(&path, &*image.0.lock().unwrap()).unwrap();
    let checked = Command::new("e2fsck")
        .args(["-f", "-n"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        checked.status.success(),
        "{}{}",
        String::from_utf8_lossy(&checked.stdout),
        String::from_utf8_lossy(&checked.stderr)
    );
}
