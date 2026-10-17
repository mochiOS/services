//! Execute the complete production dispatcher with recording handler stubs.
//! This verifies routing, rejected entries and exit cleanup, not the handlers'
//! own mechanisms or the hardware syscall trampoline.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[path = "../../../core/crates/abi/src/status.rs"]
#[allow(dead_code)]
mod native_status;

#[test]
fn retirement_probes_use_the_current_native_status_not_a_posix_errno() {
    assert!(include_str!("support/native_status.h").contains(&format!(
        "MNU_NATIVE_UNSUPPORTED INT64_C({})",
        native_status::Error::Unsupported.into_raw() as i64
    )));
    for source in [
        include_str!("native_manifest_launch_retirement.c"),
        include_str!("native_physical_translation_retirement.c"),
        include_str!("native_shared_memory.c"),
        include_str!("native_positioned_io.c"),
        include_str!("native_endpoint_identity.c"),
        include_str!("native_permission_prompt.c"),
        include_str!("native_clone_cow.c"),
    ] {
        assert!(source.contains("#include \"support/native_status.h\""));
        assert!(source.contains("MNU_NATIVE_UNSUPPORTED"));
        assert!(!source.contains("== -38") && !source.contains("!= -38"));
    }
}

#[test]
fn dispatcher_rejects_unknown_numbers_without_posix_fallback_or_handler_calls() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let dispatch = probe::between(
        include_str!("../../../core/src/syscall/mod.rs"),
        "pub fn dispatch(",
        "/// Public processor discovery;",
    );
    // Discover simple handler calls from the actual function so every route is
    // typechecked. Unrecognized/new complex signatures fail compilation rather
    // than being silently replaced in the production routing expression.
    let mut stubs = std::collections::BTreeMap::<Vec<String>, usize>::new();
    let bytes = dispatch.as_bytes();
    let mut cursor = 0;
    while cursor < bytes.len() {
        if !(bytes[cursor].is_ascii_alphabetic() || bytes[cursor] == b'_') {
            cursor += 1;
            continue;
        }
        let start = cursor;
        while cursor < bytes.len()
            && (bytes[cursor].is_ascii_alphanumeric() || matches!(bytes[cursor], b'_' | b':'))
        {
            cursor += 1;
        }
        let path = &dispatch[start..cursor];
        if bytes.get(cursor) != Some(&b'(')
            || start > 0 && bytes[start - 1] == b'.'
            || path == "dispatch"
            || path.starts_with(char::is_uppercase)
        {
            continue;
        }
        let Some(end) = dispatch[cursor + 1..].find(')') else {
            continue;
        };
        let args = &dispatch[cursor + 1..cursor + 1 + end];
        let args: Vec<_> = args
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        if !args.iter().all(|arg| {
            matches!(
                *arg,
                "num" | "arg0" | "arg1" | "arg2" | "arg3" | "arg4" | "arg5" | "0"
            )
        }) {
            continue;
        }
        let path: Vec<_> = path
            .trim_start_matches("crate::")
            .split("::")
            .map(str::to_string)
            .collect();
        if let Some(old) = stubs.insert(path, args.len()) {
            assert_eq!(old, args.len());
        }
    }
    fn emit(
        program: &mut String,
        prefix: &[String],
        stubs: &std::collections::BTreeMap<Vec<String>, usize>,
    ) {
        let mut children = std::collections::BTreeSet::new();
        for (path, arity) in stubs {
            if !path.starts_with(prefix) {
                continue;
            }
            if path.len() == prefix.len() + 1 {
                let name = path.last().unwrap();
                let args = (0..*arity)
                    .map(|i| format!("a{i}:u64"))
                    .collect::<Vec<_>>()
                    .join(",");
                let values = (0..*arity)
                    .map(|i| format!("a{i}"))
                    .collect::<Vec<_>>()
                    .join(",");
                program.push_str(&format!(
                    "pub fn {name}({args})->u64{{crate::record({:?},&[{values}])}}\n",
                    path.join("::")
                ));
            } else {
                children.insert(path[prefix.len()].clone());
            }
        }
        for child in children {
            program.push_str(&format!("pub mod {child}{{\n"));
            let mut next = prefix.to_vec();
            next.push(child);
            emit(program, &next, stubs);
            program.push_str("}\n");
        }
    }
    let mut program = format!(
        "#![allow(dead_code,unused_attributes)]\nextern crate self as mnu_abi;\n#[path={:?}]mod abi;\npub use abi::*;\nuse status::Error;\n",
        root.join("core/crates/abi/src/lib.rs")
    );
    program.push_str(r#"
use std::cell::{Cell,RefCell};
thread_local!{static CALLS:RefCell<Vec<(&'static str,Vec<u64>)>>=const{RefCell::new(Vec::new())};static RESULT:Cell<u64>=const{Cell::new(41)};}
fn record(name:&'static str,args:&[u64])->u64{CALLS.with_borrow_mut(|calls|calls.push((name,args.to_vec())));RESULT.get()}
"#);
    emit(&mut program, &[], &stubs);
    program.push_str(dispatch);
    let abi = include_str!("../../../core/crates/abi/src/lib.rs");
    let enumeration = probe::between(abi, "pub enum SyscallNumber {", "\n}");
    let declared: Vec<_> = enumeration
        .lines()
        .filter_map(|line| line.split_once('='))
        .filter_map(|(_, value)| value.trim().trim_end_matches(',').parse::<u64>().ok())
        .collect();
    assert!(declared.len() > 80);
    program.push_str(&format!("const DECLARED:&[u64]=&{declared:?};\n"));
    program.push_str(r#"
fn check(num:u64,expected:u64,handler:Option<(&str,&[u64])>){
    CALLS.with_borrow_mut(Vec::clear);assert_eq!(dispatch(num,11,22,33,44,55,66),expected);
    CALLS.with_borrow(|calls|{
        let names:Vec<_>=calls.iter().map(|(name,_)|*name).collect();
        let mut expected_names=vec!["mem::extent_transaction::flush","handle::flush_provider_releases","task::flush_deferred_process_reclaims","record_syscall"];
        if let Some((name,_))=handler{expected_names.push(name)}
        expected_names.extend(["task::flush_deferred_process_reclaims","mem::extent_transaction::flush"]);assert_eq!(names,expected_names);
        assert_eq!(calls[3].1,[num,11,22,33,44,55]);if let Some((_,args))=handler{assert_eq!(calls[4].1,args)}
    });
}
fn main(){
    // Includes all removed Linux/POSIX numbers, holes and extreme selectors.
    for num in (0..=DECLARED.iter().copied().max().unwrap()+1).chain([u64::MAX,1<<63]) {
        if !DECLARED.contains(&num){check(num,Error::Unsupported.into_raw(),None)}
    }
    for result in [0,41,1<<63,Error::NotReady.into_raw(),Error::Unsupported.into_raw(),(-5i64)as u64] {
        RESULT.set(result);check(SyscallNumber::HandleRead as u64,result,Some(("handle::read",&[11,22,33])));
        check(SyscallNumber::HandleWaitMany as u64,result,Some(("handle::wait_many",&[11,22,33,0])));
        check(SyscallNumber::HandleWaitManyGuarded as u64,result,Some(("handle::wait_many",&[11,22,33,44])));
    }
    CALLS.with_borrow_mut(Vec::clear);
    assert_eq!(dispatch(SyscallNumber::HandleWaitManyGuarded as u64,11,22,33,0,55,66),Error::InvalidArgument.into_raw());
    CALLS.with_borrow(|calls|assert_eq!(calls.iter().map(|(name,_)|*name).collect::<Vec<_>>(),[
        "mem::extent_transaction::flush","handle::flush_provider_releases","task::flush_deferred_process_reclaims","record_syscall",
        "task::flush_deferred_process_reclaims","mem::extent_transaction::flush"]));
}
"#);
    probe::run(&program);
}
