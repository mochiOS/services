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
use std::cell::{Cell,RefCell};
use status::Error;
const MEMORY_ACCESS_READ:u64=1;
const MEMORY_ACCESS_WRITE:u64=2;
thread_local! {
    static MAPS:Cell<usize>=const {Cell::new(0)};
    static RECORDS:RefCell<Vec<(u64,u64,u64,bool,bool,Vec<u8>)>>=const{RefCell::new(Vec::new())};
    static FAIL_AT:Cell<usize>=const{Cell::new(0)};
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
    pub fn map_and_copy_segment_to(table:u64,address:u64,filesz:u64,memsz:u64,data:&[u8],write:bool,exec:bool)->Result<(),crate::Kernel> {
        assert_eq!(table,17);assert!(address>=0x400000,"metadata must respect the user-image window");assert_eq!(data.len() as u64,filesz);assert!(memsz>=filesz);assert!(!(write&&exec));
        crate::MAPS.set(crate::MAPS.get()+1);
        if crate::FAIL_AT.get()==0 || crate::FAIL_AT.get()==crate::MAPS.get(){
            if let Some(error)=crate::MAPPING_ERROR.get(){return Err(error)}
        }
        crate::RECORDS.with_borrow_mut(|v|v.push((address,filesz,memsz,write,exec,data.to_vec())));Ok(())
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
    MAPS.set(0);assert_eq!(image::map_elf_image(data,17,&mut ExecMeasurement).err(),Some(Error::InvalidFormat));
    assert_eq!(MAPS.get(),0,"invalid ELF must not mutate any page table");
}
fn metadata(data: &[u8], address: u64, expected_maps: usize, private: bool) {
    RECORDS.with_borrow_mut(Vec::clear);
    MAPS.set(0);
    MAPPING_ERROR.set(None);
    FAIL_AT.set(0);
    let layout = image::map_elf_image(data, 17, &mut ExecMeasurement).unwrap();
    assert_eq!(layout.phdr_vaddr, address);
    assert_eq!(MAPS.get(), expected_maps);
    let start = u64::from_le_bytes(data[32..40].try_into().unwrap()) as usize;
    let size = usize::from(u16::from_le_bytes(data[54..56].try_into().unwrap()))
        * usize::from(u16::from_le_bytes(data[56..58].try_into().unwrap()));
    RECORDS.with_borrow(|records| {
        let record = records
            .iter()
            .find(|r| address >= r.0 && address + size as u64 <= r.0 + r.1)
            .unwrap();
        let offset = (address - record.0) as usize;
        assert_eq!(&record.5[offset..offset + size], &data[start..start + size]);
        if private {
            assert_eq!(
                (record.0, record.1, record.2, record.3, record.4),
                (address, size as u64, size as u64, false, false)
            );
        }
    });
}
fn metadata_cases() {
    // An unmapped ELF prefix: the actual C target layout.
    let mut data = valid();
    put64(&mut data, 64 + 8, 4096);
    metadata(&data, 0x502000, 3, true);
    // A prefix is usable when it stays inside the same user-image window.
    let mut higher = data;
    put64(&mut higher, 24, 0x800000);
    put64(&mut higher, 64 + 16, 0x800000);
    put64(&mut higher, 120 + 16, 0x900000);
    metadata(&higher, 0x7ff000, 3, true);
    // Reuse the segment which really contains the source table, not a bias
    // guessed from the first LOAD or the smallest virtual address.
    put64(&mut data, 120 + 8, 0);
    metadata(&data, 0x500040, 2, false);
    // Headers can begin at a nonzero file offset inside a LOAD.
    let mut data = valid();
    let table = data[64..176].to_vec();
    data[4096..4208].copy_from_slice(&table);
    put64(&mut data, 32, 4096);
    put64(&mut data, 4096 + 8, 4096);
    metadata(&data, 0x400000, 2, false);
    // Another LOAD touches the metadata's page: retain an independent copy.
    let mut data = valid();
    put64(&mut data, 120 + 8, 0xf00);
    put64(&mut data, 120 + 16, 0x400f00);
    put64(&mut data, 120 + 32, 0x100);
    put64(&mut data, 120 + 40, 0x100);
    put64(&mut data, 120 + 48, 0x100);
    metadata(&data, 0x401000, 3, true);
    // Preserve unknown bytes in a larger program-header stride, and validate
    // its complete last entry before doing any page-table work.
    let mut data = valid();
    let second = data[120..176].to_vec();
    data[192..248].copy_from_slice(&second);
    put16(&mut data, 54, 128);
    put64(&mut data, 64 + 8, 4096);
    put64(&mut data, 192 + 8, 4096);
    data[248..320].fill(0x7b);
    metadata(&data, 0x502000, 3, true);
    put64(&mut data, 64 + 8, 0);
    put64(&mut data, 64 + 32, 0);
    put64(&mut data, 192 + 8, 0);
    put64(&mut data, 192 + 32, 0);
    reject(&data[..319]);
    // A large valid table need not fit below the first LOAD: use a disjoint
    // range above the last LOAD rather than truncate or overlap metadata.
    let mut large = vec![0u8; 64 + 65 * 65535];
    let data = valid();
    large[..64].copy_from_slice(&data[..64]);
    large[64..120].copy_from_slice(&data[64..120]);
    large[64 + 65535..64 + 65535 + 56].copy_from_slice(&data[120..176]);
    put16(&mut large, 54, 65535);
    put16(&mut large, 56, 65);
    put64(&mut large, 64 + 8, 4096);
    metadata(&large, 0x502000, 3, true);
    // The metadata map, and then a LOAD after it, can fail independently.
    for failing in [1, 2, 3] {
        let mut data = valid();
        put64(&mut data, 64 + 8, 4096);
        MAPS.set(0);
        FAIL_AT.set(failing);
        MAPPING_ERROR.set(Some(Kernel::Memory(result::Memory::OutOfMemory)));
        assert_eq!(
            image::map_elf_image(&data, 17, &mut ExecMeasurement).err(),
            Some(Error::ResourceUnavailable)
        );
        assert_eq!(MAPS.get(), failing);
    }
    MAPPING_ERROR.set(None);
    FAIL_AT.set(0);
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
    metadata_cases();
}
"#,
    );
    probe::run(&program);
}
