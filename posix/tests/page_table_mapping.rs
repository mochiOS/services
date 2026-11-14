#[test]
fn segment_population_does_not_alias_a_shared_kernel_scratch_mapping() {
    // Structural regression guard, not a substitute for the native concurrent
    // population test in heap_mapping.c: host tests cannot execute page tables.
    let paging = include_str!("../../../core/src/mem/paging.rs");
    let start = paging
        .find("pub(crate) unsafe fn map_and_copy_segment_to(")
        .unwrap();
    let rest = &paging[start..];
    let end = rest.find("\n}").unwrap() + 2;
    let population = &rest[..end];
    assert!(population.contains("let l4_virt = table_phys\n        .checked_add(phys_off)"));
    assert!(population.contains("ensure_user_page_table_hierarchy(l4_virt, page_addr, phys_off)"));
    assert!(!population.contains("temp_kern_virt"));
    assert!(!population.contains("TempMapGuard"));
    assert!(!population.contains("PAGE_TABLE.lock()"));
}

#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn user_placement_preserves_kernel_ranges_and_supervisor_references() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    // Execute the actual admission walker against owned, aligned tables.
    // Hardware descriptors and SMAP are the only platform substitutions.
    let mut program = r#"
extern crate self as x86_64;
pub mod structures {pub mod paging {pub use crate::mem::paging::PageTableFlags;}}
#[macro_export]macro_rules! debug{($($arg:tt)*)=>{{}}}
#[derive(Debug,PartialEq,Eq)]pub enum Memory{InvalidAddress,NotMapped,PermissionDenied,AlreadyMapped}
#[derive(Debug,PartialEq,Eq)]pub enum Kernel{Memory(Memory)}
mod cpu{pub struct SmapSmepGuard;impl SmapSmepGuard{pub fn new()->Self{Self}}}
mod mem{
 #[path="@WALKER@"]pub mod sparse_page_walk;
 pub mod paging{
  pub use crate::{Kernel,Memory};
  pub type Result<T>=core::result::Result<T,Kernel>;
  pub const USER_SPACE_END:u64=(1<<47)-1;
  pub const KERNEL_MAPPING:PageTableFlags=PageTableFlags(1<<52);
  pub fn physical_memory_offset()->Option<u64>{Some(0)}
  pub fn required_kernel_ranges()->[(u64,u64);4]{[(0x208000,0x209000),(0x7fff00000000,0x7fff00080000),(0,0),(0,0)]}
  #[derive(Clone,Copy,Debug,PartialEq,Eq)]pub struct PageTableFlags(pub u64);
  impl PageTableFlags{
   pub const PRESENT:Self=Self(1);pub const WRITABLE:Self=Self(2);
   pub const USER_ACCESSIBLE:Self=Self(4);pub const HUGE_PAGE:Self=Self(128);pub const NO_EXECUTE:Self=Self(1<<63);
   pub fn contains(self,other:Self)->bool{self.0&other.0==other.0}
  }
  impl core::ops::BitOr for PageTableFlags{type Output=Self;fn bitor(self,rhs:Self)->Self{Self(self.0|rhs.0)}}
  impl PageTableFlags{pub fn remove(&mut self,flag:Self){self.0&=!flag.0;}pub fn insert(&mut self,flag:Self){self.0|=flag.0;}}
  #[derive(Clone,Copy,Debug,PartialEq,Eq)]pub struct PhysAddr(u64);
  impl PhysAddr{pub fn new(v:u64)->Self{Self(v)}pub fn as_u64(self)->u64{self.0}}
  #[derive(Clone,Copy,Debug,PartialEq,Eq)]pub struct Entry{pub address:u64,pub flags:PageTableFlags}
  impl Entry{
   pub fn flags(&self)->PageTableFlags{self.flags}pub fn addr(&self)->PhysAddr{PhysAddr(self.address)}
   pub fn is_unused(&self)->bool{self.address==0&&self.flags.0==0}
   pub fn set_addr(&mut self,address:PhysAddr,flags:PageTableFlags){self.address=address.0;self.flags=flags;}
  }
  #[repr(align(4096))]pub struct PageTable(pub [Entry;512]);
  impl PageTable{pub fn new()->Self{Self([Entry{address:0,flags:PageTableFlags(0)};512])}}
  impl core::ops::Index<usize> for PageTable{type Output=Entry;fn index(&self,i:usize)->&Entry{&self.0[i]}}
  impl core::ops::IndexMut<usize> for PageTable{fn index_mut(&mut self,i:usize)->&mut Entry{&mut self.0[i]}}
  use PageTableFlags as Flags;
  mod frame {
   thread_local!{static OWNED:std::cell::RefCell<Vec<Box<super::PageTable>>>=const{std::cell::RefCell::new(Vec::new())};}
   pub struct Frame(super::PhysAddr);impl Frame{pub fn start_address(&self)->super::PhysAddr{self.0}}
   pub fn allocate_zeroed_frame()->super::Result<Frame>{
    let table=Box::new(super::PageTable::new());let pointer=&*table as *const _ as u64;
    OWNED.with_borrow_mut(|owned|owned.push(table));Ok(Frame(super::PhysAddr::new(pointer)))
   }
  }
  @HIERARCHY@
  #[path="@RESERVED@"]mod reserved;
  pub(crate) use reserved::check_user_mapping_range;
 }
}
use mem::paging::*;
fn pointer(table:&PageTable)->u64{table as *const _ as u64}
fn entry(address:u64,flags:u64)->Entry{Entry{address,flags:PageTableFlags(flags)}}
fn main(){
 let mut l4=Box::new(PageTable::new());let mut l3=Box::new(PageTable::new());
 let mut l2=Box::new(PageTable::new());let mut l1=Box::new(PageTable::new());
 l4[0]=entry(pointer(&l3),7);l3[0]=entry(pointer(&l2),7);l2[0]=entry(pointer(&l1),7);
 let root=pointer(&l4);
 l1[3]=entry(0x9000,3);let before=l1[3];
 assert_eq!(check_user_mapping_range(root,0x3000,4096),Err(Kernel::Memory(Memory::PermissionDenied)));
 assert_eq!(l1[3],before);
 l1[3]=entry(0x9000,7);assert_eq!(check_user_mapping_range(root,0x3000,4096),Ok(()));
 l4[0].flags=PageTableFlags(3);
 assert_eq!(check_user_mapping_range(root,0x3000,4096),Err(Kernel::Memory(Memory::PermissionDenied)));
 l4[0].flags=PageTableFlags(7);
 // Discardable bootstrap identity aliases remain usable by ordinary ELF loads.
 l1[3]=entry(0x3000,3);assert_eq!(check_user_mapping_range(root,0x3000,4096),Ok(()));
 // Explicit kernel ownership also protects identity addresses on other CPUs.
 l1[3].flags=PageTableFlags(3|(1<<52));
 assert_eq!(check_user_mapping_range(root,0x3000,4096),Err(Kernel::Memory(Memory::PermissionDenied)));
 l1[3]=entry(0x3000,3);
 // Required kernel pages stay reserved even if no present leaf was installed.
 assert_eq!(check_user_mapping_range(root,0x208000,4096),Err(Kernel::Memory(Memory::PermissionDenied)));
 assert_eq!(check_user_mapping_range(root,0x207fff,2),Err(Kernel::Memory(Memory::PermissionDenied)));
 assert_eq!(check_user_mapping_range(root,0x7fff00001000,4096),Err(Kernel::Memory(Memory::PermissionDenied)));
 assert_eq!(check_user_mapping_range(root,u64::MAX,2),Err(Kernel::Memory(Memory::InvalidAddress)));
 assert_eq!(check_user_mapping_range(root,(1<<47)-4096,8192),Err(Kernel::Memory(Memory::InvalidAddress)));
 // A supervisor huge alias is replaceable only when it is the inherited identity map.
 l2[1]=entry(0x600000,131);
 assert_eq!(check_user_mapping_range(root,0x203000,4096),Err(Kernel::Memory(Memory::PermissionDenied)));
 l2[1]=entry(0x201000,131); // huge-page PAT bit, physical base is 0x200000
 assert_eq!(check_user_mapping_range(root,0x203000,4096),Ok(()));
 assert_eq!(check_user_mapping_range(root,0x208000,4096),Err(Kernel::Memory(Memory::PermissionDenied)));
 // Splitting this alias for a different page preserves its kernel neighbour,
 // including conversion of the huge PAT bit to the 4KiB PAT bit.
 mem::paging::ensure_user_page_table_hierarchy(root,0x203000,0).unwrap();
 let leaves=unsafe{&*(l2[1].addr().as_u64() as *const PageTable)};
 for index in 0..512{
  assert_eq!(leaves[index].addr().as_u64(),0x200000+index as u64*4096);
  assert_eq!(leaves[index].flags().0,131);
 }
 assert_eq!(check_user_mapping_range(root,0x208000,4096),Err(Kernel::Memory(Memory::PermissionDenied)));
}
"#.replace("@WALKER@",root.join("core/src/mem/sparse_page_walk.rs").to_str().unwrap())
.replace("@RESERVED@",root.join("core/src/mem/paging/reserved.rs").to_str().unwrap());
    program = program.replace(
        "@HIERARCHY@",
        &probe::definition(
            include_str!("../../../core/src/mem/paging.rs"),
            "fn ensure_user_page_table_hierarchy(",
        )
        .replace(
            "fn ensure_user_page_table_hierarchy(",
            "pub(crate) fn ensure_user_page_table_hierarchy(",
        ),
    );
    probe::run(&program);
}
