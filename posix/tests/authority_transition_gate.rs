//! Execute the production process authority gate with retained mock owners.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn final_commit_excludes_authority_updates_without_allocating_or_holding_the_table() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../core/src/task/authority_transition.rs")
        .canonicalize()
        .unwrap();
    let status = path
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("crates/abi/src/status.rs");
    let mut program = format!(
        r#"
#![allow(dead_code)]
extern crate alloc;
extern crate self as mnu_abi;
#[path={status:?}]pub mod status;
use std::cell::Cell;
thread_local! {{
    static TABLE:Cell<bool>=const{{Cell::new(false)}};
    static ALLOCATIONS:Cell<usize>=const{{Cell::new(0)}};
}}
struct Allocator;
unsafe impl std::alloc::GlobalAlloc for Allocator {{
    unsafe fn alloc(&self, layout:std::alloc::Layout)->*mut u8 {{
        ALLOCATIONS.set(ALLOCATIONS.get()+1);
        unsafe {{std::alloc::System.alloc(layout)}}
    }}
    unsafe fn dealloc(&self, pointer:*mut u8, layout:std::alloc::Layout) {{
        unsafe {{std::alloc::System.dealloc(pointer,layout)}}
    }}
}}
#[global_allocator] static ALLOCATOR:Allocator=Allocator;
mod task {{
    use std::sync::{{Arc,OnceLock}};
    pub type ProcessId=u64;
    pub mod process {{
        pub struct ProcessObject(super::authority_transition::Activity);
        impl ProcessObject {{
            pub fn new()->Self {{Self(super::authority_transition::Activity::new())}}
            pub fn authority_activity(&self)->&super::authority_transition::Activity {{
                assert!(!crate::TABLE.get(),"gate acquisition/drop must be outside the table");
                &self.0
            }}
        }}
    }}
    struct Process(Arc<process::ProcessObject>);
    impl Process {{fn process_object(&self)->Arc<process::ProcessObject>{{
        assert!(crate::TABLE.get());Arc::clone(&self.0)
    }}}}
    static FIRST:OnceLock<Arc<process::ProcessObject>>=OnceLock::new();
    static SECOND:OnceLock<Arc<process::ProcessObject>>=OnceLock::new();
    pub fn with_process<T>(pid:u64,operation:impl FnOnce(&Process)->T)->Option<T>{{
        let owner=match pid {{7=>&FIRST,9=>&SECOND,_=>return None}};
        let process=Process(Arc::clone(owner.get_or_init(||Arc::new(process::ProcessObject::new()))));
        assert!(!crate::TABLE.replace(true));
        let result=operation(&process);crate::TABLE.set(false);Some(result)
    }}
    #[path={path:?}] pub mod authority_transition;
}}
use task::authority_transition::*;
"#,
    );
    program.push_str(
        r#"
fn main() {
    drop(begin_mutation(7).unwrap());drop(begin_mutation(9).unwrap());
    assert!(matches!(begin_mutation(0),Err(status::Error::NotReady)));
    assert!(matches!(begin_commit(0),Err(status::Error::NotReady)));
    let before=ALLOCATIONS.get();
    let first=begin_mutation(7).unwrap();let second=begin_mutation(7).unwrap();
    assert!(matches!(begin_commit(7),Err(status::Error::ResourceUnavailable)));
    drop(first);assert!(begin_commit(7).is_err());drop(second);
    let commit=begin_commit(7).unwrap();
    assert!(matches!(begin_mutation(7),Err(status::Error::ResourceUnavailable)));
    for _ in 0..20 {
        assert!(begin_commit(7).is_err());assert!(begin_mutation(7).is_err());
    }
    drop(begin_mutation(9).unwrap());
    drop(commit);drop(begin_mutation(7).unwrap());
    assert_eq!(ALLOCATIONS.get(),before,"authority admission must never allocate");
    let result:Result<(),()>=(||{let _commit=begin_commit(7).unwrap();Err(())})();
    assert_eq!(result,Err(()));drop(begin_mutation(7).unwrap());
    for _ in 0..100 {
        let barrier=std::sync::Arc::new(std::sync::Barrier::new(2));
        let other=barrier.clone();
        let worker=std::thread::spawn(move || {
            let mutation=begin_mutation(7).unwrap();
            other.wait();other.wait();drop(mutation);
        });
        barrier.wait();assert!(begin_commit(7).is_err());
        barrier.wait();worker.join().unwrap();
        let commit=begin_commit(7).unwrap();
        std::thread::spawn(|| {
            for _ in 0..20 {
                assert!(begin_mutation(7).is_err());assert!(begin_commit(7).is_err());
            }
            drop(begin_mutation(9).unwrap());
        }).join().unwrap();
        drop(commit);drop(begin_mutation(7).unwrap());
    }
}
"#,
    );
    probe::run(&program);
}
