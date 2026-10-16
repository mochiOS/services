//! Execute the production table/entry/rights code with observable Arc payloads.
//! Compare numbering and ordering with the previous BTreeMap allocation policy.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn table_growth_is_fallible_and_preserves_numbering_order_authority_and_ownership() {
    let source = include_str!("../../../core/src/task/handle_table.rs");
    let mut program = String::from(
        r#"
#![allow(dead_code)]
extern crate alloc;
extern crate self as mnu_abi;
use std::sync::{Arc,atomic::{AtomicBool,Ordering}};
static FAIL_NEXT:AtomicBool=AtomicBool::new(false);
struct Allocator;
unsafe impl std::alloc::GlobalAlloc for Allocator{
    unsafe fn alloc(&self,layout:std::alloc::Layout)->*mut u8{
        if FAIL_NEXT.swap(false,Ordering::Relaxed){return std::ptr::null_mut();}
        unsafe{std::alloc::System.alloc(layout)}
    }
    unsafe fn realloc(&self,pointer:*mut u8,layout:std::alloc::Layout,size:usize)->*mut u8{
        if FAIL_NEXT.swap(false,Ordering::Relaxed){return std::ptr::null_mut();}
        unsafe{std::alloc::System.realloc(pointer,layout,size)}
    }
    unsafe fn dealloc(&self,pointer:*mut u8,layout:std::alloc::Layout){
        unsafe{std::alloc::System.dealloc(pointer,layout)}
    }
}
#[global_allocator]static ALLOCATOR:Allocator=Allocator;
#[derive(Debug)]pub struct HandleInfo{pub handle:u32,pub reserved:u32,pub rights:u64}
"#,
    );
    probe::constants(
        &mut program,
        include_str!("../../../core/crates/abi/src/lib.rs"),
        &["PROCESS_MAX_OBJECT_HANDLES"],
    );
    program.push_str(r#"
mod task{
    pub mod handle_snapshot{
        pub struct HandleSnapshot;
        impl HandleSnapshot{
            pub fn capture(_:impl IntoIterator<Item=(super::handle_table::ObjectHandle,super::handle_table::ObjectHandleEntry)>)->Result<Self,()>{Ok(Self)}
        }
    }
    pub mod handle_table{
        use alloc::{boxed::Box,vec::Vec};
        use std::collections::BTreeMap;
        use crate::*;
        const PROCESS_MAX_OBJECT_HANDLES:usize=crate::PROCESS_MAX_OBJECT_HANDLES;
        #[derive(Clone,Debug)]pub struct KernelObject(pub Arc<u64>);
"#);
    program.push_str(probe::between(
        source,
        "#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]",
        "/// Kernel object identity",
    ));
    program.push_str(probe::between(
        source,
        "#[derive(Clone, Debug)]\npub struct ObjectHandleEntry",
        "#[cfg(test)]",
    ));
    program.push_str(r#"
fn entry(value:&Arc<u64>)->ObjectHandleEntry{
    ObjectHandleEntry::new(KernelObject(value.clone()),HandleRights::READ.union(HandleRights::DUPLICATE).union(HandleRights::TRANSFER))
}
type Model=BTreeMap<u32,(Arc<u64>,u64)>;
fn model_insert(model:&mut Model,next:&mut u32,value:Arc<u64>,rights:u64)->Option<u32>{
    if model.len()>=PROCESS_MAX_OBJECT_HANDLES{return None;}
    for _ in 0..PROCESS_MAX_OBJECT_HANDLES{
        let raw=(*next).clamp(1,PROCESS_MAX_OBJECT_HANDLES as u32);
        *next=if raw==PROCESS_MAX_OBJECT_HANDLES as u32{1}else{raw+1};
        if let std::collections::btree_map::Entry::Vacant(slot)=model.entry(raw){
            slot.insert((value,rights));return Some(raw);
        }
    }None
}
pub fn exercise(){
    let value=Arc::new(7);
    let mut table=ObjectHandleTable::new_boxed();
    FAIL_NEXT.store(true,Ordering::Relaxed);
    let result=table.insert(entry(&value));
    assert!(!FAIL_NEXT.load(Ordering::Relaxed));assert!(result.is_none());
    assert_eq!(table.next,1);assert!(table.entries.is_empty());assert_eq!(Arc::strong_count(&value),1);
    FAIL_NEXT.store(true,Ordering::Relaxed);
    let result=table.insert_at(ObjectHandle(3),entry(&value));
    assert!(!FAIL_NEXT.load(Ordering::Relaxed));assert!(!result);
    assert_eq!(table.next,1);assert!(table.entries.is_empty());assert_eq!(Arc::strong_count(&value),1);
    let first=table.insert(entry(&value)).unwrap();
    while table.entries.len()<table.entries.capacity(){table.insert(entry(&value)).unwrap();}
    let cursor=table.next;let count=table.describe().len();let references=Arc::strong_count(&value);
    FAIL_NEXT.store(true,Ordering::Relaxed);
    let result=table.duplicate_restricted(first,HandleRights::READ);
    assert!(!FAIL_NEXT.load(Ordering::Relaxed));assert!(result.is_none());
    assert_eq!(table.next,cursor);assert_eq!(table.describe().len(),count);
    assert_eq!(Arc::strong_count(&value),references);
    FAIL_NEXT.store(true,Ordering::Relaxed);
    let result=table.insert_at(ObjectHandle(PROCESS_MAX_OBJECT_HANDLES as u32),entry(&value));
    assert!(!FAIL_NEXT.load(Ordering::Relaxed));assert!(!result);
    assert_eq!(table.next,cursor);assert_eq!(table.describe().len(),count);
    assert_eq!(Arc::strong_count(&value),references);
    // Occupied/out-of-range selectors do not try to allocate or replace owners.
    for handle in [first,ObjectHandle(PROCESS_MAX_OBJECT_HANDLES as u32+1)]{
        FAIL_NEXT.store(true,Ordering::Relaxed);
        let result=table.insert_at(handle,entry(&value));
        let pending=FAIL_NEXT.swap(false,Ordering::Relaxed);
        assert!(pending);assert!(!result);assert_eq!(Arc::strong_count(&value),references);
    }
    FAIL_NEXT.store(true,Ordering::Relaxed);
    assert!(table.get(first).is_some());assert_eq!(table.describe().len(),count);
    assert!(table.close(first));table.retain(|_|true);
    assert!(FAIL_NEXT.swap(false,Ordering::Relaxed),"lookup/close/retain must not allocate");
    drop(table);assert_eq!(Arc::strong_count(&value),1);

    let mut table=ObjectHandleTable::new_boxed();
    let mut model=Model::new();let mut next=1;let mut random=0x12345678_u64;
    let resources=[Arc::new(11),Arc::new(13),Arc::new(17),Arc::new(19)];
    for step in 0..12000{
        random=random.wrapping_mul(6364136223846793005).wrapping_add(1);
        let value=resources[((random>>16) as usize)%resources.len()].clone();
        let raw=((random>>32) as usize%PROCESS_MAX_OBJECT_HANDLES) as u32+1;
        let handle=ObjectHandle(raw);
        match step%6{
            0=>{
                let item=entry(&value);let rights=item.rights().bits();
                assert_eq!(table.insert(item).map(ObjectHandle::raw),
                    model_insert(&mut model,&mut next,value.clone(),rights));
            }
            1=>assert_eq!(table.close(handle),model.remove(&raw).is_some()),
            2=>{
                let item=entry(&value);let rights=item.rights().bits();
                let expected=model.len()<PROCESS_MAX_OBJECT_HANDLES && !model.contains_key(&raw);
                assert_eq!(table.insert_at(handle,item),expected);
                if expected{model.insert(raw,(value.clone(),rights));}
            }
            3=>{
                // Exercise holes without replacing the allocation cursor.
                let divisor=(random%23+2) as u32;
                table.retain(|handle|handle.raw()%divisor!=0);
                model.retain(|handle,_|handle%divisor!=0);
            }
            4=>{
                let source=model.get(&raw).filter(|(_,rights)|rights&HandleRights::DUPLICATE.bits()!=0).cloned();
                let expected=source.and_then(|(value,_)|model_insert(&mut model,&mut next,value,HandleRights::READ.bits()));
                assert_eq!(table.duplicate_restricted(handle,HandleRights::READ).map(ObjectHandle::raw),expected);
            }
            _=>{
                let actual=table.get(handle);assert_eq!(actual.is_some(),model.contains_key(&raw));
                if let Some(actual)=actual{assert!(Arc::ptr_eq(&actual.object().0,&model[&raw].0));assert_eq!(actual.rights().bits(),model[&raw].1);}
            }
        }
        assert_eq!(table.next,next);assert_eq!(table.describe().len(),model.len());
        if step%17==0{
            let actual:Vec<_>=table.describe().map(|entry|(entry.handle,entry.rights)).collect();
            let expected:Vec<_>=model.iter().map(|(handle,(_,rights))|(*handle,*rights)).collect();
            assert_eq!(actual,expected);
        }
    }
    drop(table);drop(model);assert_eq!(Arc::strong_count(&value),1);
    for resource in &resources{assert_eq!(Arc::strong_count(resource),1);}
    // Bound and wrap-around remain identical, including a released low slot.
    let mut table=ObjectHandleTable::new_boxed();
    for raw in 1..=PROCESS_MAX_OBJECT_HANDLES as u32{assert_eq!(table.insert(entry(&value)).unwrap().raw(),raw);}
    assert!(table.insert(entry(&value)).is_none());assert_eq!(table.next,1);
    assert!(table.close(ObjectHandle(3)));
    assert_eq!(table.insert(entry(&value)).unwrap().raw(),3);
    assert_eq!(table.next,4);
    drop(table);assert_eq!(Arc::strong_count(&value),1);
}
}}
fn main(){task::handle_table::exercise();}
"#);
    probe::run(&program);
}
