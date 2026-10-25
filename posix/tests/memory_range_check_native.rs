//! Execute the native observer with process storage and page tables replaced.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn observer_checks_the_callers_complete_range_without_changing_mappings() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let mut program = format!(
        r#"
#![allow(dead_code)]
extern crate self as mnu_abi;
#[path={status:?}]pub mod status;
#[path={ranges:?}]mod ranges;
use std::cell::{{Cell, RefCell}};
use std::collections::BTreeSet;
thread_local! {{
    static THREAD: Cell<bool> = const {{ Cell::new(true) }};
    static ROOT: Cell<bool> = const {{ Cell::new(true) }};
    static PROCESS: RefCell<Option<task::Process>> = const {{ RefCell::new(None) }};
    static LEAVES: RefCell<BTreeSet<u64>> = RefCell::new(BTreeSet::new());
    static LOOKUPS: Cell<usize> = const {{ Cell::new(0) }};
}}
mod task {{
    pub mod ids {{pub type ProcessId = u64;}}
    #[derive(Clone, Debug, PartialEq, Eq)]pub struct Region {{pub start:u64,pub limit:u64}}
    impl Region {{pub fn end(&self)->Option<u64>{{Some(self.limit)}}}}
    #[derive(Clone, Debug, PartialEq, Eq)]pub struct Process {{pub regions:Vec<Region>}}
    impl Process {{
        pub fn page_table(&self)->Option<u64>{{crate::ROOT.get().then_some(17)}}
        pub fn find_memory_region(&self,page:u64)->Option<&Region>{{
            self.regions.iter().find(|region| region.start<=page && page<region.limit)
        }}
    }}
    pub struct Thread;
    impl Thread {{pub fn process_id(&self)->u64{{7}}}}
    pub fn current_thread_id()->Option<u64>{{crate::THREAD.get().then_some(9)}}
    pub fn with_thread<T>(id:u64,callback:impl FnOnce(&Thread)->T)->Option<T>{{
        assert_eq!(id,9);Some(callback(&Thread))
    }}
    pub fn with_process<T>(id:u64,callback:impl FnOnce(&Process)->T)->Option<T>{{
        assert_eq!(id,7);crate::LOOKUPS.set(crate::LOOKUPS.get()+1);
        crate::PROCESS.with_borrow(|process|process.as_ref().map(callback))
    }}
    pub mod memory_range {{pub(crate) use crate::ranges::covers_pages;}}
}}
mod mem {{pub mod paging {{
    pub fn has_user_page_entry_in_table(table:u64,page:u64)->bool{{
        assert_eq!(table,17);crate::LEAVES.with_borrow(|leaves|leaves.contains(&page))
    }}
}}}}
"#,
        status = root.join("core/crates/abi/src/status.rs"),
        ranges = root.join("core/src/task/memory_range.rs")
    );
    let syscall = include_str!("../../../core/src/syscall/mod.rs");
    program.push_str(probe::between(
        syscall,
        "fn is_canonical_user_range(",
        "fn current_process_name_for_log(",
    ));
    program.push_str("mod implementation { use mnu_abi::status::Error; const SUCCESS:u64=0;\n");
    let memory = include_str!("../../../core/src/syscall/memory.rs");
    program.push_str(probe::between(
        memory,
        "fn current_pid()",
        "#[inline(never)]",
    ));
    program.push_str(probe::between(
        memory,
        "fn memory_range_is_mapped(",
        "/// Observe only",
    ));
    program.push_str(probe::between(
        memory,
        "pub fn check_range(",
        "#[inline(never)]\nfn protect_memory_pages(",
    ));
    program.push_str(r#"
}
fn main() {
    use implementation::check_range as check;
    use status::Error;
    assert_eq!(check(u64::MAX,0),0);
    for (address,length) in [(0,1),(u64::MAX,1),(4096,u64::MAX),(0x800000000000,1)] {
        assert_eq!(check(address,length),Error::InvalidAddress.into_raw());
    }
    assert_eq!(LOOKUPS.get(),0);
    assert_eq!(check(4096,1),Error::NotReady.into_raw());
    PROCESS.set(Some(task::Process{regions:vec![task::Region{start:4096,limit:8192},task::Region{start:12288,limit:16384}]}));
    assert_eq!(check(4096,1),0);
    assert_eq!(check(8191,2),Error::InvalidAddress.into_raw());
    assert_eq!(check(4096,12288),Error::InvalidAddress.into_raw());
    LEAVES.with_borrow_mut(|leaves|{leaves.insert(8192);});
    let original_process=PROCESS.with_borrow(Clone::clone);
    let original_leaves=LEAVES.with_borrow(Clone::clone);
    assert_eq!(check(4097,12287),0);
    assert_eq!(check(4096,12289),Error::InvalidAddress.into_raw());
    assert_eq!(PROCESS.with_borrow(Clone::clone),original_process);
    assert_eq!(LEAVES.with_borrow(Clone::clone),original_leaves);
    ROOT.set(false);
    assert_eq!(check(4096,1),Error::NotReady.into_raw());
    THREAD.set(false);
    assert_eq!(check(4096,1),Error::NotReady.into_raw());
    assert_eq!(check(u64::MAX,0),0);
}
"#);
    probe::run(&program);
}
