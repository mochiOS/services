//! Production readiness publication checks, independent of POSIX errno.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn signals_validate_masks_and_exact_endpoint_before_publishing() {
    let mut program = String::from(
        r#"
#![allow(dead_code)]
use std::{cell::Cell,sync::Arc};
use mnu_abi::status::Error;
thread_local! {
    static CURRENT:Cell<Option<u64>>=const {Cell::new(Some(31))};
    static ENDPOINT:Cell<Option<(u16,u64)>>=const {Cell::new(Some((4,8)))};
    static PRESENT:Cell<bool>=const {Cell::new(true)};
    static LOOKUPS:Cell<usize>=const {Cell::new(0)};
    static PROVIDER:Arc<Provider>=Arc::new(Provider{signals:Cell::new(0),updates:Cell::new(0)});
}
struct Provider {signals:Cell<u64>,updates:Cell<usize>}
impl Provider {fn update_signals(&self,set:u64,clear:u64) {
    self.updates.set(self.updates.get()+1);
    self.signals.set((self.signals.get()|set)&!clear);
}}
mod mnu_abi {pub mod status {
"#,
    );
    program.push_str(include_str!("../../../core/crates/abi/src/status.rs"));
    program.push_str("}\n");
    probe::constants(
        &mut program,
        include_str!("../../../core/crates/abi/src/lib.rs"),
        &[
            "HANDLE_SIGNAL_READABLE",
            "HANDLE_SIGNAL_WRITABLE",
            "HANDLE_SIGNAL_PEER_CLOSED",
            "HANDLE_SIGNAL_IDLE",
        ],
    );
    program.push_str(
        r#"
}
mod task {
    pub struct Thread(u64);impl Thread {pub fn as_u64(&self)->u64 {self.0}}
    pub fn current_thread_id()->Option<Thread> {crate::CURRENT.get().map(Thread)}
    pub mod handle_table {
        pub fn provider_object(thread:u64,slot:u16,generation:u64,id:u64)->Option<std::sync::Arc<crate::Provider>> {
            crate::LOOKUPS.set(crate::LOOKUPS.get()+1);
            if !crate::PRESENT.get() || (thread,slot,generation,id)!=(31,4,8,42) {return None;}
            Some(crate::PROVIDER.with(std::sync::Arc::clone))
        }
    }
}
mod syscall {pub mod ipc {
    pub struct Endpoint {pub thread_id:u64,pub slot:u16,pub generation:u64}
    pub fn endpoint_for_thread(thread:u64)->Option<Endpoint> {
        crate::ENDPOINT.get().map(|(slot,generation)|Endpoint{thread_id:thread,slot,generation})
    }
}}
mod production {use crate::mnu_abi;const SUCCESS:u64=0;
"#,
    );
    program.push_str(probe::between(
        include_str!("../../../core/src/syscall/handle.rs"),
        "pub fn provider_object_signal(",
        "pub fn close(",
    ));
    program.push_str(
        r#"
}
fn main() {
    use mnu_abi::*;
    let supported=HANDLE_SIGNAL_READABLE|HANDLE_SIGNAL_WRITABLE|HANDLE_SIGNAL_PEER_CLOSED|HANDLE_SIGNAL_IDLE;
    for (id,set,clear) in [
        (u64::MAX,0,0),(42,1,0),(42,0,1),(42,1<<63,0),(42,0,1<<63),
        (42,HANDLE_SIGNAL_READABLE,HANDLE_SIGNAL_READABLE),(42,supported,supported),
    ] {
        LOOKUPS.set(0);
        assert_eq!(production::provider_object_signal(id,set,clear),Error::InvalidArgument.into_raw());
        assert_eq!(LOOKUPS.get(),0);
    }
    CURRENT.set(None);
    assert_eq!(production::provider_object_signal(42,0,0),Error::NotReady.into_raw());
    CURRENT.set(Some(31));ENDPOINT.set(None);
    assert_eq!(production::provider_object_signal(42,0,0),Error::NotReady.into_raw());
    assert_eq!(LOOKUPS.get(),0);
    for (thread,slot,generation) in [(32,4,8),(31,5,8),(31,4,9)] {
        CURRENT.set(Some(thread));ENDPOINT.set(Some((slot,generation)));
        assert_eq!(production::provider_object_signal(42,supported,0),Error::InvalidArgument.into_raw());
    }
    CURRENT.set(Some(31));ENDPOINT.set(Some((4,8)));
    assert_eq!(production::provider_object_signal(43,0,0),Error::InvalidArgument.into_raw());
    PRESENT.set(false);
    assert_eq!(production::provider_object_signal(42,0,0),Error::InvalidArgument.into_raw());
    PRESENT.set(true);
    PROVIDER.with(|p|{assert_eq!(p.updates.get(),0);assert_eq!(p.signals.get(),0);});
    assert_eq!(production::provider_object_signal(42,supported,0),0);
    PROVIDER.with(|p|assert_eq!(p.signals.get(),supported));
    assert_eq!(production::provider_object_signal(42,0,HANDLE_SIGNAL_READABLE),0);
    PROVIDER.with(|p|assert_eq!(p.signals.get(),supported & !HANDLE_SIGNAL_READABLE));
    assert_eq!(production::provider_object_signal(42,0,supported),0);
    assert_eq!(production::provider_object_signal(42,0,0),0);
    PROVIDER.with(|p|{assert_eq!(p.signals.get(),0);assert_eq!(p.updates.get(),4);assert_eq!(Arc::strong_count(p),1);});
}
"#,
    );
    probe::run(&program);
}

#[test]
fn notification_race_classification_does_not_swallow_other_native_failures() {
    let mut program = probe::program();
    program.push_str("mod production {use crate::mnu_abi;\n");
    program.push_str(probe::between(
        include_str!("../src/socket_native.rs"),
        "pub(super) fn notification_is_retired(",
        "fn run(",
    ));
    program.push_str("}\nuse production::notification_is_retired;\n");
    program.push_str(
        r#"
fn main() {
    use mnu_abi::status::Error;
    assert!(notification_is_retired(Error::InvalidArgument.into_raw() as i64));
    for error in [Error::NotReady,Error::AccessDenied,Error::ResourceUnavailable,
        Error::BackingFailure,Error::LimitExceeded,Error::InvalidAddress,Error::AlreadyExists,
        Error::NotFound] {
        assert!(!notification_is_retired(error.into_raw() as i64));
    }
    for raw in [0,-9,-22,i64::MIN,i64::MAX,(Error::InvalidArgument.into_raw()|0xffff) as i64] {
        assert!(!notification_is_retired(raw));
    }
}
"#,
    );
    probe::run(&program);
}
