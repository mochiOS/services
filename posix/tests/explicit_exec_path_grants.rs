//! Execution authority is an explicit, thread-bound authorization, not a
//! kernel pathname grant. Run the real process authorization methods.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn execution_authorization_is_exact_thread_bound_and_consumed_once() {
    let filesystem = include_str!("../../../core/src/syscall/fs.rs");
    for retired in [
        "ensure_fs_capability_access_for_process",
        "identity_storage_path_allows",
        "path_is_in_identity_storage",
        "path::scoped_path_allows",
        "path::lookup_path",
    ] {
        assert!(!filesystem.contains(retired), "kernel retains {retired}");
    }

    let mut program = String::from(
        r#"
mod task {pub type ThreadId=u64;}
// Only the fields accessed by these methods are modeled. Image contents and
// digest enforcement have separate read_all/image-admission runtime tests.
#[derive(Debug)]
struct PendingExecSecurity {path:String,authorized_thread:u64,digest:[u8;32]}
struct Process {pending_exec_security:Option<PendingExecSecurity>}
impl Process {
"#,
    );
    program.push_str(probe::between(
        include_str!("../../../core/src/task/process.rs"),
        "    pub(crate) fn authorize_next_exec(",
        "    /// サービスIDを取得",
    ));
    program.push_str(
        r#"
}
fn main() {
    let mut process=Process{pending_exec_security:None};
    assert!(process.take_exec_authorization("/bin/app",7).is_none());
    process.authorize_next_exec(PendingExecSecurity{
        path:"/bin/app".into(),authorized_thread:7,digest:[1;32],
    });
    for wrong in ["/bin/other","/bin/./app","/bin/../bin/app","/bin/app/","app",""] {
        assert!(process.take_exec_authorization(wrong,7).is_none());
        assert!(process.pending_exec_security.is_some());
    }
    for wrong_thread in [0,6,8,u64::MAX] {
        assert!(process.take_exec_authorization("/bin/app",wrong_thread).is_none());
        assert!(process.pending_exec_security.is_some());
    }
    assert_eq!(process.take_exec_authorization("/bin/app",7).unwrap().digest,[1;32]);
    assert!(process.take_exec_authorization("/bin/app",7).is_none());

    process.authorize_next_exec(PendingExecSecurity{
        path:"/bin/old".into(),authorized_thread:7,digest:[2;32],
    });
    process.authorize_next_exec(PendingExecSecurity{
        path:"opaque-image-identity".into(),authorized_thread:8,digest:[3;32],
    });
    assert!(process.take_exec_authorization("/bin/old",7).is_none());
    assert!(process.take_exec_authorization("opaque-image-identity",7).is_none());
    assert_eq!(process.take_exec_authorization("opaque-image-identity",8).unwrap().digest,[3;32]);
    assert!(process.pending_exec_security.is_none());
}
"#,
    );
    probe::run(&program);
}
