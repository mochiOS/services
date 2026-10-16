//! Execute production target validation/readiness and IPC readiness lookup.
//! Handle lookup, resource state and thread lifetime are controlled boundaries.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn target_queries_preserve_native_authority_identity_and_backend_failures() {
    let handle = include_str!("../../../core/src/syscall/handle.rs");
    let mut program = String::from(
        "#![allow(dead_code)]\nextern crate self as mnu_abi;\nextern crate alloc;\npub mod status {\n",
    );
    program.push_str(include_str!("../../../core/crates/abi/src/status.rs"));
    program.push_str("}\n");
    program.push_str(probe::between(
        include_str!("../../../core/crates/abi/src/lib.rs"),
        "#[repr(C)]\n#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]\npub struct HandleWaitItem",
        "/// Native result returned by `WaitOnAddress`.",
    ));
    program.push_str(probe::between(
        include_str!("../../../core/src/task/handle_table.rs"),
        "#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]\npub struct HandleRights",
        "/// Kernel object identity stored behind a process-local handle.",
    ));
    program.push_str(r#"
use std::{cell::{Cell,RefCell},sync::{Arc,Weak}};
use status::Error;
#[derive(Clone)]enum KernelObject {
    Process(Arc<Process>),IpcEndpoint{thread_id:u64,slot:u16,generation:u64},
    MemoryAdmission(Arc<mem::vm_object::ProviderAdmission>),File(Arc<task::FileHandle>),
    Provider(Arc<ProviderObject>),Event(u64),Thread(u64),VmObject(Arc<()>),
    MemoryUpdate(Arc<()>),AddressSpace(Arc<()>),HandleSnapshot(Arc<()>),Other,
}
struct Process{exit:bool}impl Process{fn id(&self)->u64{7}fn is_exited(&self)->bool{self.exit}}
struct ProviderObject{signals:u64}impl ProviderObject{fn signals(&self)->u64{self.signals}}
thread_local!{
    static OBJECT:RefCell<KernelObject>=const{RefCell::new(KernelObject::Other)};
    static ERROR:Cell<Option<Error>>=const{Cell::new(None)};
    static VALID:Cell<bool>=const{Cell::new(true)};
    static STREAM_ERROR:Cell<Option<Error>>=const{Cell::new(None)};
    static STREAM_CALLS:Cell<usize>=const{Cell::new(0)};
    static THRESHOLD:Cell<u32>=const{Cell::new(0)};
}
fn object_native(raw:u64,rights:HandleRights)->Result<KernelObject,Error>{
    assert_eq!(raw,41);assert_eq!(rights,HandleRights::WAIT);
    if let Some(error)=ERROR.get(){return Err(error);}
    Ok(OBJECT.with_borrow(Clone::clone))
}
fn provider_endpoint(_: &ProviderObject)->syscall::ipc::IpcEndpoint{endpoint()}
fn endpoint()->syscall::ipc::IpcEndpoint{syscall::ipc::IpcEndpoint{thread_id:7,slot:0,generation:9}}
mod task{
    pub type ProcessId=u64;pub struct FileHandle;
    #[derive(Clone,Copy)]pub struct ThreadId(pub u64);
    impl ThreadId{pub fn as_u64(self)->u64{self.0}}
}
mod mem{pub mod vm_object{
    pub struct ProviderAdmission(pub u64);
    impl ProviderAdmission{pub fn signals(&self)->u64{self.0}}
}}
mod memory_update{
    pub fn admission_endpoint(_: &crate::mem::vm_object::ProviderAdmission)->crate::syscall::ipc::IpcEndpoint{crate::endpoint()}
}
mod syscall{
    pub mod fs{
        pub fn stream_signals_for_capacity(_: &crate::task::FileHandle,minimum:u32)->Result<u64,u64>{
            crate::STREAM_CALLS.set(crate::STREAM_CALLS.get()+1);crate::THRESHOLD.set(minimum);
            if let Some(error)=crate::STREAM_ERROR.get(){return Err(error.into_raw());}
            Ok(crate::HANDLE_SIGNAL_READABLE|crate::HANDLE_SIGNAL_WRITABLE|crate::HANDLE_SIGNAL_PEER_CLOSED)
        }
    }
    pub mod ipc{
        use std::sync::{Mutex,MutexGuard};
        #[derive(Clone,Copy)]pub struct IpcEndpoint{pub thread_id:u64,pub slot:u16,pub generation:u64}
        pub fn endpoint_is_valid(_:IpcEndpoint)->bool{crate::VALID.get()}
        struct Mailbox{count:usize,waiter:u64}
        static MAILBOXES:Mutex<[Mailbox;2]>=Mutex::new([Mailbox{count:0,waiter:0},Mailbox{count:1,waiter:0}]);
        fn lock_mailboxes()->MutexGuard<'static,[Mailbox;2]>{MAILBOXES.lock().unwrap()}
        pub fn force_waiter(waiter:u64){MAILBOXES.lock().unwrap()[0].waiter=waiter;}
        pub fn waiter()->u64{MAILBOXES.lock().unwrap()[0].waiter}
"#);
    program.push_str(probe::between(
        include_str!("../../../core/src/syscall/ipc.rs"),
        "pub(crate) fn endpoint_wait_ready(",
        "fn process_local_endpoint(",
    ));
    program.push_str("}}\n");
    program.push_str(probe::between(
        include_str!("../../../core/src/task/handle_table.rs"),
        "impl KernelObject {",
        "impl core::fmt::Debug for KernelObject",
    ));
    program.push_str(
        &probe::between(
            handle,
            "#[derive(Clone)]\nenum WaitTarget",
            "fn remove_endpoint_waiters(",
        )
        .replace("fn wait_item_signal(", "fn production_wait_item_signal("),
    );
    program.push_str(r#"
fn set(object:KernelObject){OBJECT.with_borrow_mut(|slot|*slot=object)}
fn item(interests:u64)->HandleWaitItem{HandleWaitItem{handle:41,interests,..Default::default()}}
fn wait_item_signal(item:&mut HandleWaitItem,source:Option<&Weak<mem::vm_object::ProviderAdmission>>)->Result<(WaitTarget,bool),u64>{
    let source=match source {
        Some(weak)=>WaitSource::MemoryAdmission(weak.clone()),
        None=>WaitSource::capture(OBJECT.with_borrow(Clone::clone)),
    };
    production_wait_item_signal(item,&source)
}
fn failure(mut item:HandleWaitItem,source:Option<&Weak<mem::vm_object::ProviderAdmission>>,error:Error){
    assert!(matches!(wait_item_signal(&mut item,source),Err(raw) if raw==error.into_raw()));
}
fn main(){
    // Close/reuse must not retarget any supported kind, including identical
    // metadata in a distinct allocation and a new IPC generation in one slot.
    let originals=[
        KernelObject::Process(Arc::new(Process{exit:false})),
        KernelObject::IpcEndpoint{thread_id:7,slot:0,generation:9},
        KernelObject::File(Arc::new(task::FileHandle)),
        KernelObject::Provider(Arc::new(ProviderObject{signals:2})),
        KernelObject::MemoryAdmission(Arc::new(mem::vm_object::ProviderAdmission(2))),
    ];
    let replacements=[
        KernelObject::Process(Arc::new(Process{exit:false})),
        KernelObject::IpcEndpoint{thread_id:7,slot:0,generation:10},
        KernelObject::File(Arc::new(task::FileHandle)),
        KernelObject::Provider(Arc::new(ProviderObject{signals:2})),
        KernelObject::MemoryAdmission(Arc::new(mem::vm_object::ProviderAdmission(2))),
    ];
    for (original,replacement) in originals.into_iter().zip(replacements) {
        let source=WaitSource::capture(original.clone());
        assert!(source.matches(&original));assert!(!source.matches(&replacement));
        set(replacement);let mut query=item(HANDLE_SIGNAL_READABLE);
        assert!(matches!(production_wait_item_signal(&mut query,&source),Err(raw) if raw==Error::InvalidArgument.into_raw()));
    }
    let file=Arc::new(task::FileHandle);
    let source=WaitSource::capture(KernelObject::File(file.clone()));
    assert_eq!(Arc::strong_count(&file),2);drop(source);assert_eq!(Arc::strong_count(&file),1);
    let admission=Arc::new(mem::vm_object::ProviderAdmission(0));
    let source=WaitSource::capture(KernelObject::MemoryAdmission(admission.clone()));
    assert_eq!(Arc::strong_count(&admission),1,"waiting must not prevent admission cancellation");
    drop(admission);
    assert!(matches!(source,WaitSource::MemoryAdmission(weak) if weak.upgrade().is_none()));
    set(KernelObject::Other);
    let owner=task::ThreadId(7);
    assert_eq!(syscall::ipc::register_endpoint_waiter(endpoint(),owner),Ok(()));
    assert_eq!(syscall::ipc::register_endpoint_waiter(endpoint(),owner),Ok(()));
    assert_eq!(syscall::ipc::waiter(),7);
    assert_eq!(syscall::ipc::register_endpoint_waiter(endpoint(),task::ThreadId(8)),Err(Error::AccessDenied.into_raw()));
    syscall::ipc::remove_endpoint_waiter(endpoint(),task::ThreadId(8));
    assert_eq!(syscall::ipc::waiter(),7,"foreign removal must not clear the owner");
    VALID.set(false);
    assert_eq!(syscall::ipc::register_endpoint_waiter(endpoint(),owner),Err(Error::NotFound.into_raw()));
    assert_eq!(syscall::ipc::waiter(),7);VALID.set(true);
    syscall::ipc::remove_endpoint_waiter(endpoint(),owner);
    syscall::ipc::remove_endpoint_waiter(endpoint(),owner);
    assert_eq!(syscall::ipc::waiter(),0);
    syscall::ipc::force_waiter(22);
    assert_eq!(syscall::ipc::register_endpoint_waiter(endpoint(),owner),Err(Error::ResourceUnavailable.into_raw()));
    assert_eq!(syscall::ipc::waiter(),22);syscall::ipc::force_waiter(0);
    let mut invalid=endpoint();invalid.slot=u16::MAX;
    assert_eq!(syscall::ipc::register_endpoint_waiter(invalid,owner),Err(Error::InvalidArgument.into_raw()));
    syscall::ipc::remove_endpoint_waiter(invalid,owner);
    assert_eq!(syscall::ipc::waiter(),0);
    let all=HANDLE_SIGNAL_READABLE|HANDLE_SIGNAL_WRITABLE|HANDLE_SIGNAL_PEER_CLOSED|HANDLE_SIGNAL_IDLE;
    let admission=Arc::new(mem::vm_object::ProviderAdmission(HANDLE_SIGNAL_READABLE|HANDLE_SIGNAL_PEER_CLOSED));
    let weak=Arc::downgrade(&admission);
    for error in [Error::InvalidArgument,Error::AccessDenied,Error::NotReady]{
        ERROR.set(Some(error));failure(item(HANDLE_SIGNAL_READABLE),None,error);
        failure(item(HANDLE_SIGNAL_READABLE),Some(&weak),error);
    }
    ERROR.set(None);assert_eq!(STREAM_CALLS.get(),0);
    failure(item(0),None,Error::InvalidArgument);
    failure(item(HANDLE_SIGNAL_READABLE),None,Error::InvalidArgument); // Unsupported kind.
    for exited in [false,true]{
        set(KernelObject::Process(Arc::new(Process{exit:exited})));
        let mut query=item(HANDLE_SIGNAL_TERMINATED);
        assert!(matches!(wait_item_signal(&mut query,None),Ok((WaitTarget::Process(7),ready)) if ready==exited));
        assert_eq!(query.observed,if exited{HANDLE_SIGNAL_TERMINATED}else{0});
        failure(item(HANDLE_SIGNAL_READABLE),None,Error::InvalidArgument);
        query.minimum_write_bytes=1;failure(query,None,Error::InvalidArgument);
    }
    for slot in 0..2{
        set(KernelObject::IpcEndpoint{thread_id:7,slot,generation:9});
        let mut query=item(HANDLE_SIGNAL_READABLE);
        assert!(matches!(wait_item_signal(&mut query,None),Ok((WaitTarget::IpcEndpoint(_),ready)) if ready==(slot==1)));
        assert_eq!(query.observed,if slot==1{HANDLE_SIGNAL_READABLE}else{0});
        failure(item(HANDLE_SIGNAL_WRITABLE),None,Error::InvalidArgument);
        VALID.set(false);failure(query,None,Error::NotFound);VALID.set(true);
    }
    assert_eq!(syscall::ipc::endpoint_wait_ready(invalid),Err(Error::InvalidArgument.into_raw()));
    set(KernelObject::MemoryAdmission(admission.clone()));
    let mut query=item(HANDLE_SIGNAL_READABLE);
    assert!(matches!(wait_item_signal(&mut query,Some(&weak)),Ok((WaitTarget::MemoryAdmission(_),true))));
    assert_eq!(query.observed,HANDLE_SIGNAL_READABLE);
    failure(item(HANDLE_SIGNAL_WRITABLE),Some(&weak),Error::InvalidArgument);
    let other=Arc::new(mem::vm_object::ProviderAdmission(0));
    set(KernelObject::MemoryAdmission(other));failure(query,Some(&weak),Error::InvalidArgument);
    set(KernelObject::MemoryAdmission(admission));VALID.set(false);failure(query,Some(&weak),Error::NotFound);VALID.set(true);
    set(KernelObject::File(Arc::new(task::FileHandle)));
    let mut query=item(HANDLE_SIGNAL_WRITABLE);query.minimum_write_bytes=4096;
    assert!(matches!(wait_item_signal(&mut query,None),Ok((WaitTarget::Stream(_),true))));
    assert_eq!(query.observed,HANDLE_SIGNAL_WRITABLE);assert_eq!(THRESHOLD.get(),4096);
    for error in [Error::InvalidArgument,Error::ResourceUnavailable,Error::BackingFailure]{
        STREAM_ERROR.set(Some(error));failure(query,None,error);
    }
    STREAM_ERROR.set(None);
    query.interests=HANDLE_SIGNAL_READABLE;failure(query,None,Error::InvalidArgument);
    failure(item(HANDLE_SIGNAL_IDLE),None,Error::InvalidArgument);
    set(KernelObject::Provider(Arc::new(ProviderObject{signals:all})));
    let mut query=item(HANDLE_SIGNAL_IDLE|HANDLE_SIGNAL_PEER_CLOSED);
    assert!(matches!(wait_item_signal(&mut query,None),Ok((WaitTarget::Provider(_),true))));
    assert_eq!(query.observed,HANDLE_SIGNAL_IDLE|HANDLE_SIGNAL_PEER_CLOSED);
    failure(item(HANDLE_SIGNAL_TERMINATED),None,Error::InvalidArgument);
    VALID.set(false);failure(query,None,Error::NotFound);
}
"#);
    probe::run(&program);
}
