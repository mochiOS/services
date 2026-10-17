//! Exercise the production growth scope and mapping loop. The host substitutes
//! interrupt state and physical mappings, not the allocator's lock ordering.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn heap_growth_defers_local_timer_until_all_mapping_locks_are_released() {
    let source = include_str!("../../../core/src/mem/allocator.rs");
    let mut program = String::from(
        r#"
#![allow(dead_code)]
use std::{cell::{Cell,UnsafeCell},ops::{Deref,DerefMut},sync::atomic::{AtomicUsize,Ordering}};
thread_local! {
    static IRQ:Cell<bool>=const{Cell::new(true)};
    static LOCKS:Cell<usize>=const{Cell::new(0)};
    static MODE:Cell<u8>=const{Cell::new(0)};
    static EXTENDED:Cell<usize>=const{Cell::new(0)};
    static ALLOCATED:Cell<usize>=const{Cell::new(0)};
    static FREED:Cell<usize>=const{Cell::new(0)};
}
mod x86_64 {pub mod instructions {pub mod interrupts {
    pub fn without_interrupts<T>(body:impl FnOnce()->T)->T{
        let previous=crate::IRQ.replace(false);
        let result=body();
        assert_eq!(crate::LOCKS.get(),0,"do not restore IRQs while a mapping lock is live");
        crate::IRQ.set(previous);result
    }
}}}
struct Lock<T>(UnsafeCell<T>);
unsafe impl<T> Sync for Lock<T>{}
impl<T> Lock<T>{
    const fn new(value:T)->Self{Self(UnsafeCell::new(value))}
    fn lock(&self)->Guard<'_,T>{
        assert!(!IRQ.get(),"local timer could enter ThreadQueue while this lock is held");
        LOCKS.set(LOCKS.get()+1);Guard(self)
    }
}
struct Guard<'a,T>(&'a Lock<T>);
impl<T> Deref for Guard<'_,T>{type Target=T;fn deref(&self)->&T{unsafe{&*self.0.0.get()}}}
impl<T> DerefMut for Guard<'_,T>{fn deref_mut(&mut self)->&mut T{unsafe{&mut*self.0.0.get()}}}
impl<T> Drop for Guard<'_,T>{fn drop(&mut self){assert!(!IRQ.get());LOCKS.set(LOCKS.get()-1);}}
const HEAP_START:usize=0x44440000;
const HEAP_SIZE:usize=64*4096;
const HEAP_GROWTH_SIZE:usize=2*4096;
struct Size4KiB;
struct VirtAddr(u64);
impl VirtAddr{fn new(value:u64)->Self{Self(value)}}
struct Page<T>(u64,std::marker::PhantomData<T>);
impl<T> Page<T>{fn containing_address(address:VirtAddr)->Self{Self(address.0,std::marker::PhantomData)}}
struct PageTableFlags;
impl PageTableFlags{const PRESENT:u8=1;const WRITABLE:u8=2;const NO_EXECUTE:u8=4;}
struct Frames;
impl Frames{
    fn allocate_frame(&mut self)->Option<usize>{
        assert!(!IRQ.get());
        if MODE.get()==4{return None}
        ALLOCATED.set(ALLOCATED.get()+1);Some(ALLOCATED.get())
    }
    fn deallocate_frame(&mut self,_:usize)->bool{assert!(!IRQ.get());FREED.set(FREED.get()+1);true}
}
struct Mapper;
impl Mapper{unsafe fn map_to(&mut self,page:Page<Size4KiB>,_:usize,flags:u8,_:&mut Frames)->Result<Flush,()>{
    assert!(!IRQ.get());assert_eq!(flags,7);assert!(page.0>=HEAP_START as u64);
    if MODE.get()==6{Err(())}else{Ok(Flush)}
}}
struct Flush;
impl Flush{fn flush(self){assert!(!IRQ.get());}}
struct Inner;
impl Inner{unsafe fn extend(&mut self,bytes:usize){assert!(!IRQ.get());EXTENDED.set(EXTENDED.get()+bytes);}}
mod mem{
    pub mod paging{pub static PAGE_TABLE:crate::Lock<Option<crate::Mapper>>=crate::Lock::new(Some(crate::Mapper));}
    pub mod frame{
        pub static FRAMES:crate::Lock<Option<crate::Frames>>=crate::Lock::new(Some(crate::Frames));
        pub fn lock_allocator()->crate::Guard<'static,Option<crate::Frames>>{FRAMES.lock()}
        pub fn zero_frame(_:usize)->Result<(),()>{
            assert!(!crate::IRQ.get());
            if crate::MODE.get()==5{Err(())}else{Ok(())}
        }
    }
}
enum CounterMetric{FrameFrees}
enum GaugeMetric{FramesInUse,FramesQuarantined}
mod performance{
    pub fn increment(_:crate::CounterMetric,_:u64){}
    pub fn gauge_subtract(_:crate::GaugeMetric,_:u64){}
    pub fn gauge_add(_:crate::GaugeMetric,_:u64){}
}
struct HardenedKernelHeap{growth:Lock<()>,committed_bytes:AtomicUsize,inner:Lock<Inner>}
impl HardenedKernelHeap{
"#,
    );
    program.push_str(probe::between(
        source,
        "    fn grow(&self,",
        "\n}\n\nunsafe impl GlobalAlloc",
    ));
    program.push_str(
        r#"
}
fn main(){
    for enabled in [false,true]{for mode in 0..=7{
        IRQ.set(enabled);MODE.set(mode);EXTENDED.set(0);ALLOCATED.set(0);FREED.set(0);
        // Fixture setup is outside the production critical section.
        unsafe{*mem::paging::PAGE_TABLE.0.get()=if mode==2{None}else{Some(Mapper)};}
        unsafe{*mem::frame::FRAMES.0.get()=if mode==3{None}else{Some(Frames)};}
        let committed=if mode==1{HEAP_SIZE}else{0};
        let heap=HardenedKernelHeap{growth:Lock::new(()),committed_bytes:AtomicUsize::new(committed),inner:Lock::new(Inner)};
        let requested=if mode==7{3*4096+1}else{1};
        assert_eq!(heap.grow(requested),mode==0||mode==7);
        assert_eq!(IRQ.get(),enabled,"restore the caller's original interrupt state");
        assert_eq!(LOCKS.get(),0);
        let expected=if mode==0{2*4096}else if mode==7{4*4096}else{0};
        assert_eq!(EXTENDED.get(),expected);
        assert_eq!(heap.committed_bytes.load(Ordering::Relaxed),committed+expected);
        assert_eq!(FREED.get(),if mode==5||mode==6{1}else{0});
    }}
}
"#,
    );
    probe::run(&program);
}
