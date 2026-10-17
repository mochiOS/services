#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn early_log_mirroring_is_opt_in_exact_and_cannot_recurse_or_abort_logging() {
    let mut program = String::from(
        r#"
#![allow(dead_code)]
extern crate self as mochi_user_platform;
use std::cell::{Cell,RefCell};
thread_local!{
    static FAIL:Cell<bool>=const{Cell::new(false)};
    static WRITES:RefCell<Vec<Vec<u8>>>=const{RefCell::new(Vec::new())};
}
pub mod io{
    pub fn stderr(line:&[u8])->Result<(),()>{
        crate::WRITES.with_borrow_mut(|writes|writes.push(line.to_vec()));
        if crate::FAIL.get(){Err(())}else{Ok(())}
    }
}
mod implementation{
"#,
    );
    program.push_str(include_str!("../../logger/src/early_diagnostics.rs"));
    program.push_str(
        r#"
}
fn main(){
    implementation::mirror_boot_line(b"service: pending\n");
    FAIL.set(true);
    implementation::mirror_boot_line(b"service: write failed\n");
    let expected=if cfg!(feature="early-serial-diagnostics"){
        vec![b"service: pending\n".to_vec(),b"service: write failed\n".to_vec()]
    }else{vec![]};
    WRITES.with_borrow(|writes|assert_eq!(*writes,expected));
}
"#,
    );
    probe::run(&program);
    probe::run_with_cfg(&program, "feature=\"early-serial-diagnostics\"");
    let main = include_str!("../../logger/src/main.rs");
    let validation = main
        .find("if core::str::from_utf8(&buf[..len]).is_err()")
        .unwrap();
    let mirror = main
        .find("early_diagnostics::mirror_boot_line(&buf[..len])")
        .unwrap();
    assert!(validation < mirror);
    assert!(main[validation..mirror].contains("if !persistence_enabled"));
}
