#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn optional_tls_instruction_requires_both_the_leaf_and_feature_bit() {
    let source = include_str!("../../../user/crates/newlib-runtime/src/thread_lookup.rs");
    let start = source.find("fn cpu_supports_local_base()").unwrap();
    let end = start + source[start..].find("\n}\n").unwrap() + 3;
    let mut program = String::from(
        r#"
use std::cell::Cell;
thread_local!{
    static MAXIMUM:Cell<u32>=const{Cell::new(0)};
    static FEATURES:Cell<u32>=const{Cell::new(0)};
    static QUERIES:Cell<usize>=const{Cell::new(0)};
}
mod core { pub mod arch { pub mod x86_64 {
    pub struct Result{pub eax:u32,pub ebx:u32}
    pub fn __cpuid(leaf:u32)->Result{
        assert_eq!(leaf,0);Result{eax:crate::MAXIMUM.get(),ebx:0}
    }
    pub fn __cpuid_count(leaf:u32,subleaf:u32)->Result{
        assert_eq!((leaf,subleaf),(7,0));
        assert!(crate::MAXIMUM.get()>=7,"undefined leaves may alias unrelated data");
        crate::QUERIES.set(crate::QUERIES.get()+1);
        Result{eax:0,ebx:crate::FEATURES.get()}
    }
}}}
"#,
    );
    program.push_str(&source[start..end]);
    program.push_str(
        r#"
fn main(){
    for maximum in [0,1,6,7,8,u32::MAX]{
        for bits in [0,1,2,3,u32::MAX]{
            MAXIMUM.set(maximum);FEATURES.set(bits);QUERIES.set(0);
            assert_eq!(cpu_supports_local_base(),maximum>=7 && bits&1!=0);
            assert_eq!(QUERIES.get(),usize::from(maximum>=7));
        }
    }
}
"#,
    );
    probe::run(&program);
}
