//! Execute the production generation gates with controlled backing state.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn typed_gates_keep_exclusion_and_do_not_translate_callback_failures() {
    let mut program = probe::program();
    program.push_str(
        r#"
use std::{cell::Cell,sync::{Arc,Mutex},sync::atomic::{AtomicU64,Ordering}};
use mnu_abi::status::Error;
mod syscall {pub(crate) use crate::mochi_user_syscall::{EAGAIN,EIO};}
struct Memory {pages:Mutex<()>,generation:AtomicU64}
impl Memory {
    fn generation(&self)->u64{self.generation.load(Ordering::Relaxed)}
"#,
    );
    program.push_str(probe::between(
        include_str!("../../../core/src/mem/shared_memory.rs"),
        "    pub(crate) fn with_generation<T>(",
        "    /// The VM coordinator",
    ));
    program.push_str(
        r#"
}
struct Gate {generation:u64,reserved:bool,unavailable:bool}
impl Gate {
    fn generation(&self)->u64{self.generation}
    fn is_reserved(&self)->bool{self.reserved}
    fn is_unavailable(&self)->bool{self.unavailable}
}
static PAGE_CACHE:Mutex<()>=Mutex::new(());
enum VmObjectSource {Memory(Arc<Memory>),Provider{_io_lock:Gate}}
struct VmObject {source:VmObjectSource}
impl VmObject {
"#,
    );
    program.push_str(probe::between(
        include_str!("../../../core/src/mem/vm_object.rs"),
        "    pub(crate) fn with_memory_generation_native<T>(",
        "    /// Removing an existing mapping",
    ));
    program.push_str(probe::between(
        include_str!("../../../core/src/mem/vm_object.rs"),
        "    pub(crate) fn check_mapping_removal(",
        "    pub fn provider(",
    ));
    program.push_str("}\n");
    program.push_str(
        &probe::between(
            include_str!("../../../core/src/mem/vm_object.rs"),
            "fn with_cache_generation<T>(",
            "fn bump_cache_mutation_epoch(",
        )
        .replace("super::object_io::IoLock", "Gate"),
    );
    program.push_str(r#"
fn main() {
    let called=Cell::new(0);
    let memory=Arc::new(Memory{pages:Mutex::new(()),generation:AtomicU64::new(7)});
    assert_eq!(memory.with_generation_native(6,||{called.set(called.get()+1);Ok(1)}),Err(Error::NotReady));
    assert_eq!(called.get(),0);
    assert!(memory.pages.try_lock().is_ok());
    for error in [Error::AccessDenied,Error::ResourceUnavailable,Error::BackingFailure] {
        assert_eq!(memory.with_generation_native(7,||{
            assert!(memory.pages.try_lock().is_err());Err::<(),_>(error)
        }),Err(error));
    }
    assert_eq!(memory.with_generation(6,||Ok(1)),Err(EAGAIN));
    assert_eq!(memory.with_generation(7,||{assert!(memory.pages.try_lock().is_err());Err::<(),_>(EACCES)}),Err(EACCES));
    let object=VmObject{source:VmObjectSource::Memory(memory.clone())};
    assert_eq!(object.check_mapping_removal(),Ok(()));
    assert_eq!(object.with_memory_generation_native(None,||Ok(1)),Err(Error::InvalidArgument));
    assert_eq!(object.with_memory_generation_native(Some(7),||{
        assert!(memory.pages.try_lock().is_err());Ok(42)
    }),Ok(42));
    for (reserved,unavailable,generation,expected) in [
        (true,false,7,Error::NotReady),(false,false,6,Error::NotReady),
        (false,true,7,Error::BackingFailure),(true,true,7,Error::BackingFailure),
    ] {
        let gate=Gate{generation:7,reserved,unavailable};
        assert_eq!(with_cache_generation_native(&gate,generation,||{called.set(called.get()+1);Ok(1)}),Err(expected));
        assert_eq!(called.get(),0);
        assert!(PAGE_CACHE.try_lock().is_ok());
        let legacy=if expected==Error::NotReady{EAGAIN}else{EIO};
        assert_eq!(with_cache_generation(&gate,generation,||Ok(1)),Err(legacy));
    }
    let gate=Gate{generation:7,reserved:false,unavailable:false};
    assert_eq!(with_cache_generation(&gate,7,||{assert!(PAGE_CACHE.try_lock().is_err());Err::<(),_>(EACCES)}),Err(EACCES));
    let object=VmObject{source:VmObjectSource::Provider{_io_lock:gate}};
    assert_eq!(object.with_memory_generation_native(Some(7),||{assert!(PAGE_CACHE.try_lock().is_err());Err::<(),_>(Error::InvalidAddress)}),Err(Error::InvalidAddress));
    assert_eq!(object.with_memory_generation_native(Some(7),||{assert!(PAGE_CACHE.try_lock().is_err());Ok(99)}),Ok(99));
    assert!(PAGE_CACHE.try_lock().is_ok());
    for reserved in [false,true] {
        for unavailable in [false,true] {
            let object=VmObject{source:VmObjectSource::Provider{_io_lock:Gate{generation:7,reserved,unavailable}}};
            assert_eq!(object.check_mapping_removal(),if reserved{Err(Error::NotReady)}else{Ok(())});
            assert!(PAGE_CACHE.try_lock().is_ok());
        }
    }
}
"#);
    probe::run(&program);
}
