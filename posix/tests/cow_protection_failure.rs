#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn production_protection_prepares_without_mutation_rolls_back_and_preserves_cow_isolation() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    // Only hardware leaf access is modeled. The actual permission journal runs
    // through prepare, apply, rollback and commit against one controlled PTE.
    let program=r#"mod cpu {pub struct SmapSmepGuard;impl SmapSmepGuard{pub fn new()->Self{Self}}}
mod mem {
 #[path="@COW@"]pub mod cow_access;
 pub mod paging {
  use core::marker::PhantomData;
  #[derive(Clone,Copy,Debug,PartialEq)]pub struct PageTableFlags(u64);
  impl PageTableFlags {
   pub const PRESENT:Self=Self(1);pub const WRITABLE:Self=Self(2);pub const USER_ACCESSIBLE:Self=Self(4);pub const ACCESSED:Self=Self(32);pub const DIRTY:Self=Self(64);pub const NO_EXECUTE:Self=Self(1<<63);
   pub fn bits(self)->u64{self.0}pub fn from_bits_retain(v:u64)->Self{Self(v)}pub fn contains(self,f:Self)->bool{self.0&f.0==f.0}pub fn insert(&mut self,f:Self){self.0|=f.0}pub fn remove(&mut self,f:Self){self.0&=!f.0}
  }
  impl core::ops::BitOr for PageTableFlags{type Output=Self;fn bitor(self,rhs:Self)->Self{Self(self.0|rhs.0)}}
  impl core::ops::BitAnd for PageTableFlags{type Output=Self;fn bitand(self,rhs:Self)->Self{Self(self.0&rhs.0)}}
  pub const COPY_ON_WRITE:PageTableFlags=PageTableFlags(super::cow_access::COPY_ON_WRITE);
  pub struct PageTableEntry{flags:PageTableFlags}impl PageTableEntry{fn flags(&self)->PageTableFlags{self.flags}fn is_unused(&self)->bool{self.flags.0==0}fn addr(&self)->u64{0x9000}fn set_addr(&mut self,_:u64,f:PageTableFlags){self.flags=f}}
  #[derive(Debug)]pub enum Memory{PermissionDenied}#[derive(Debug)]pub enum Kernel{Memory(Memory)}
  pub type Result<T>=core::result::Result<T,Kernel>;
  pub struct TableEdit<'a>{_owner:PhantomData<&'a mut ()>}impl TableEdit<'_>{fn table(&self)->u64{0x1000}}
  thread_local!{static ENTRY:std::cell::RefCell<PageTableEntry>=const{std::cell::RefCell::new(PageTableEntry{flags:PageTableFlags(0)})};}
  fn with_user_leaf_entry_mut<R>(_:u64,_:u64,f:impl FnOnce(&mut PageTableEntry)->R)->Option<R>{Some(ENTRY.with_borrow_mut(f))}
  fn record_user_leaf_change(_:u64,_:PageTableFlags,_:PageTableFlags){}fn flush_page_if_active(_:u64,_:u64){}
  #[path="@PROTECTION@"]mod protection;
  pub fn check(){
   let original=1|4|super::cow_access::COPY_ON_WRITE|super::cow_access::WRITE_DISABLED;
   ENTRY.with_borrow_mut(|e|e.flags=PageTableFlags(original));
   let mut edit=TableEdit{_owner:PhantomData};
   {let mut plan=edit.prepare_protection(0x2000,true,true,false).unwrap().unwrap();
    ENTRY.with_borrow(|e|assert_eq!(e.flags.0,original));plan.apply();
    ENTRY.with_borrow(|e|{assert_eq!(e.flags.0&2,0);assert!(super::cow_access::may_resolve(e.flags.0));});}
   ENTRY.with_borrow(|e|assert_eq!(e.flags.0,original));
   {let mut plan=edit.prepare_protection(0x2000,true,true,false).unwrap().unwrap();plan.apply();plan.commit();}
   ENTRY.with_borrow(|e|assert!(super::cow_access::may_resolve(e.flags.0)));
   assert!(edit.prepare_protection(0x2000,true,true,true).is_err());
   {let mut plan=edit.prepare_protection(0x2000,false,false,false).unwrap().unwrap();plan.apply();plan.commit();}
   ENTRY.with_borrow(|e|{assert_eq!(e.flags.0&1,0);assert!(!super::cow_access::may_resolve(e.flags.0));});
  }
 }
}
fn main(){mem::paging::check();}
"#.replace("@COW@",root.join("core/src/mem/cow_access.rs").to_str().unwrap())
 .replace("@PROTECTION@",root.join("core/src/mem/paging/protection.rs").to_str().unwrap());
    probe::run(&program);
}
