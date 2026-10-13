use std::{fs, process::Command};

#[test]
fn production_protection_restores_denied_cow_state_if_write_grant_fails() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let paging = fs::read_to_string(root.join("core/src/mem/paging.rs")).unwrap();
    let function = paging
        .split("pub fn protect_user_page_if_mapped(")
        .nth(1)
        .unwrap()
        .split("pub(crate) fn retain_shared_user_frame(")
        .next()
        .unwrap();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let temp =
        std::env::temp_dir().join(format!("mochios-cow-grant-{}-{nonce}", std::process::id()));
    fs::create_dir(&temp).unwrap();
    let source = format!(
        r#"
#[path = {:?}] mod cow_access;
mod result {{
    #[derive(Debug, PartialEq)] pub enum Memory {{ PermissionDenied, NotMapped, OutOfMemory }}
    #[derive(Debug, PartialEq)] pub enum Kernel {{ Memory(Memory) }}
    pub type Result<T> = core::result::Result<T, Kernel>;
}}
mod paging {{
    use crate::result::Result;
    #[derive(Clone, Copy, Debug, PartialEq)] struct PageTableFlags(u64);
    impl PageTableFlags {{
        const PRESENT: Self = Self(1);
        const WRITABLE: Self = Self(2);
        const USER_ACCESSIBLE: Self = Self(4);
        const NO_EXECUTE: Self = Self(1 << 63);
        const fn from_bits_retain(bits: u64) -> Self {{ Self(bits) }}
        fn bits(self) -> u64 {{ self.0 }}
        fn contains(self, other: Self) -> bool {{ self.0 & other.0 == other.0 }}
        fn insert(&mut self, other: Self) {{ self.0 |= other.0; }}
        fn remove(&mut self, other: Self) {{ self.0 &= !other.0; }}
    }}
    impl core::ops::BitOr for PageTableFlags {{ type Output = Self; fn bitor(self, rhs: Self) -> Self {{ Self(self.0|rhs.0) }} }}
    const COPY_ON_WRITE: PageTableFlags = PageTableFlags(super::cow_access::COPY_ON_WRITE);
    const COW_WRITE_DISABLED: PageTableFlags = PageTableFlags(super::cow_access::WRITE_DISABLED);
    struct Entry {{ flags: PageTableFlags }}
    impl Entry {{ fn is_unused(&self) -> bool {{ false }} fn flags(&self) -> PageTableFlags {{ self.flags }} fn addr(&self) -> u64 {{ 4096 }} fn set_addr(&mut self, _: u64, flags: PageTableFlags) {{ self.flags = flags; }} }}
    thread_local! {{ static ENTRY: std::cell::RefCell<Entry> = const {{ std::cell::RefCell::new(Entry {{ flags: PageTableFlags(0) }}) }}; static MODE: std::cell::Cell<u8> = const {{ std::cell::Cell::new(0) }}; }}
    fn with_user_leaf_entry_mut<T>(_: u64, _: u64, f: impl FnOnce(&mut Entry) -> T) -> Option<T> {{ Some(ENTRY.with(|entry| f(&mut entry.borrow_mut()))) }}
    fn flush_page_if_active(_: u64, _: u64) {{}}
    fn resolve_copy_on_write(_: u64, _: u64) -> Result<bool> {{
        ENTRY.with(|entry| {{
            let flags = entry.borrow().flags.0;
            assert!(super::cow_access::may_resolve(flags));
            assert_ne!(flags & (1 << 63), 0, "write grant must become NX before COW");
        }});
        match MODE.with(|mode| mode.get()) {{
            0 => Err(crate::result::Kernel::Memory(crate::result::Memory::OutOfMemory)),
            1 => Ok(false),
            _ => {{ ENTRY.with(|entry| {{ let mut entry = entry.borrow_mut(); entry.flags.0 = (entry.flags.0 | 2) & !(super::cow_access::COPY_ON_WRITE | super::cow_access::WRITE_DISABLED); }}); Ok(true) }}
        }}
    }}
    pub fn protect_user_page_if_mapped({}
    pub fn check() {{
        for present in [true, false] {{ for mode in 0..3 {{
            let original = (if present {{ 1 }} else {{ 0 }}) | 4 | super::cow_access::COPY_ON_WRITE | super::cow_access::WRITE_DISABLED;
            ENTRY.with(|entry| entry.borrow_mut().flags = PageTableFlags(original));
            MODE.with(|value| value.set(mode));
            let result = protect_user_page_if_mapped(4096, 8192, true, true, false);
            let flags = ENTRY.with(|entry| entry.borrow().flags.0);
            if mode < 2 {{ assert!(result.is_err()); assert_eq!(flags, original); assert!(!super::cow_access::may_resolve(flags)); }}
            else {{ assert_eq!(result, Ok(true)); assert_eq!(flags & 3, 3); assert_ne!(flags & (1 << 63), 0); }}
        }} }}
    }}
}}
fn main() {{ paging::check(); }}
"#,
        root.join("core/src/mem/cow_access.rs"),
        function
    );
    let source_path = temp.join("check.rs");
    fs::write(&source_path, source).unwrap();
    let binary = temp.join("check");
    let compile = Command::new("rustc")
        .arg(&source_path)
        .args(["--edition=2024", "-o"])
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        compile.status.success(),
        "{}",
        String::from_utf8_lossy(&compile.stderr)
    );
    assert!(Command::new(binary).status().unwrap().success());
    fs::remove_dir_all(temp).unwrap();
}
