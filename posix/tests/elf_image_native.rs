//! Real ELF parsers and image preparation; only page mapping is replaced.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn elf_validation_bounds_and_mapping_failures_use_native_errors() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let mut program = String::from(
        "#![allow(dead_code)]\nextern crate alloc;\nextern crate self as mnu_abi;\nmod status {\n",
    );
    program.push_str(include_str!("../../../core/crates/abi/src/status.rs"));
    program.push_str("}\nmod elf {\n");
    program.push_str(probe::between(
        include_str!("../../../core/src/elf/loader.rs"),
        "/// ELF64ヘッダ",
        "/// ロード可能セグメントのリスト",
    ));
    program.push_str("}\n");
    program.push_str("mod result {\n");
    program.push_str(probe::between(
        include_str!("../../../core/src/result.rs"),
        "/// トップレベル",
        "impl Kernel {",
    ));
    program.push_str("}\nuse result::Kernel;\n");
    program.push_str(&format!(
        "#[path={:?}]mod image;\n",
        root.join("core/src/syscall/exec/image.rs")
    ));
    program.push_str(probe::between(
        include_str!("../../../core/src/syscall/exec.rs"),
        "fn mapping_error_native(",
        "#[inline]\nfn aslr_mix64",
    ));
    program.push_str(
        r#"
use std::cell::Cell;
use status::Error;
const MEMORY_ACCESS_READ:u64=1;
const MEMORY_ACCESS_WRITE:u64=2;
thread_local! {
    static MAPS:Cell<usize>=const {Cell::new(0)};
    static MAPPING_ERROR:Cell<Option<Kernel>>=const {Cell::new(None)};
}
struct ExecMeasurement;
impl ExecMeasurement {
    fn parse<T>(&mut self,body:impl FnOnce()->T)->T {body()}
    fn load<T>(&mut self,body:impl FnOnce()->T)->T {body()}
}
mod task {
    pub struct MemoryRegion {pub start:u64,pub length:u64}
    impl MemoryRegion {
        pub fn anonymous(start:u64,length:u64,access:u64,offset:u64,private:bool,shared:bool)->Self {
            assert_eq!(access,3);assert_eq!(offset,0);assert!(private);assert!(!shared);Self{start,length}
        }
    }
}
mod mem {pub mod paging {
    pub fn map_and_copy_segment_to(table:u64,_:u64,filesz:u64,memsz:u64,data:&[u8],write:bool,exec:bool)->Result<(),crate::Kernel> {
        assert_eq!(table,17);assert_eq!(data.len() as u64,filesz);assert!(memsz>=filesz);assert!(!(write&&exec));
        crate::MAPS.set(crate::MAPS.get()+1);crate::MAPPING_ERROR.get().map_or(Ok(()),Err)
    }
}}
fn put16(data:&mut [u8],at:usize,value:u16){data[at..at+2].copy_from_slice(&value.to_le_bytes());}
fn put32(data:&mut [u8],at:usize,value:u32){data[at..at+4].copy_from_slice(&value.to_le_bytes());}
fn put64(data:&mut [u8],at:usize,value:u64){data[at..at+8].copy_from_slice(&value.to_le_bytes());}
fn valid()->[u8;8192] {
    let mut data=[0;8192];data[..4].copy_from_slice(b"\x7fELF");put16(&mut data,18,0x3e);
    put64(&mut data,24,0x400000);put64(&mut data,32,64);put16(&mut data,54,56);put16(&mut data,56,2);
    for (at,flags,offset,address,memsz) in [(64,1,0,0x400000,4096),(120,2,4096,0x500000,8192)] {
        put32(&mut data,at,1);put32(&mut data,at+4,flags);put64(&mut data,at+8,offset);
        put64(&mut data,at+16,address);put64(&mut data,at+32,4096);put64(&mut data,at+40,memsz);put64(&mut data,at+48,4096);
    }
    data
}
fn reject(data:&[u8]) {
    MAPS.set(0);assert_eq!(image::map_elf_image(data,17,&mut ExecMeasurement).err(),Some(Error::InvalidArgument));
    assert_eq!(MAPS.get(),0,"invalid ELF must not mutate any page table");
}
fn main() {
    let data=valid();for len in [0,4,63,64,119,175] {reject(&data[..len]);}
    for (offset,value) in [(24,0),(24,0x500000),(32,u64::MAX),(32,u64::MAX-55),
        (64+8,u64::MAX),(64+16,0x1000),(64+16,0x800000000000),(64+40,4095),
        (64+40,u64::MAX),(64+48,3),(64+16,0x400001)] {
        let mut data=valid();put64(&mut data,offset,value);reject(&data);
    }
    for (offset,value) in [(18,3),(54,0),(54,55),(56,0)] {
        let mut data=valid();put16(&mut data,offset,value);reject(&data);
    }
    for (offset,value) in [(64,0),(64+4,3)] {
        let mut data=valid();put32(&mut data,offset,value);reject(&data);
    }
    for (failure,expected) in [(Kernel::Memory(result::Memory::OutOfMemory),Error::ResourceUnavailable),
        (Kernel::Memory(result::Memory::InvalidAddress),Error::InvalidArgument),(Kernel::InvalidParam,Error::InvalidArgument)] {
        MAPS.set(0);MAPPING_ERROR.set(Some(failure));
        assert_eq!(image::map_elf_image(&valid(),17,&mut ExecMeasurement).err(),Some(expected));assert_eq!(MAPS.get(),1);
    }
    MAPPING_ERROR.set(None);MAPS.set(0);let layout=image::map_elf_image(&valid(),17,&mut ExecMeasurement).unwrap();
    assert_eq!((layout.entry,layout.phdr_vaddr,layout.phentsize,layout.phnum),(0x400000,0x400040,56,2));
    assert_eq!(MAPS.get(),2);assert_eq!(layout.deferred_zero_regions.len(),1);
    assert_eq!((layout.deferred_zero_regions[0].start,layout.deferred_zero_regions[0].length),(0x501000,4096));
}
"#,
    );
    probe::run(&program);
}
