extern crate self as mochi_user_platform;

use std::sync::Mutex;

pub mod syscall {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct SysError;
    impl SysError {
        pub fn from_raw(_: i64) -> Self {
            Self
        }
    }
}

pub mod process_watch {
    #[derive(Debug, PartialEq, Eq)]
    pub enum ProcessWatchTarget {
        RetainedHandle(u32),
    }
}

struct State {
    events: Vec<&'static str>,
    fail_create: bool,
    fail_resume: bool,
    fail_status: bool,
    status_calls: usize,
    fail_terminate: bool,
    termination_pending: bool,
    exited: bool,
}
static STATE: Mutex<State> = Mutex::new(State {
    events: Vec::new(),
    fail_create: false,
    fail_resume: false,
    fail_status: false,
    status_calls: 0,
    fail_terminate: false,
    termination_pending: false,
    exited: false,
});

pub mod handle {
    pub use mnu_abi::{HANDLE_RIGHT_SIGNAL, HANDLE_RIGHT_WAIT};
    pub type Handle = u32;
    pub fn close(handle: Handle) -> Result<(), crate::syscall::SysError> {
        assert_eq!(handle, 7);
        crate::STATE.lock().unwrap().events.push("close");
        Ok(())
    }
}

pub mod process {
    pub struct Status {
        pub process_id: u64,
        pub state: u32,
    }
    pub fn handle_status(handle: u32) -> Result<Status, crate::syscall::SysError> {
        assert_eq!(handle, 7);
        let mut state = crate::STATE.lock().unwrap();
        state.status_calls += 1;
        if state.fail_status {
            Err(crate::syscall::SysError)
        } else {
            Ok(Status {
                process_id: 70,
                state: if state.exited {
                    mnu_abi::PROCESS_STATE_EXITED
                } else {
                    mnu_abi::PROCESS_STATE_RUNNING
                },
            })
        }
    }
    pub fn create_stopped(image: u32, metadata: &[u8]) -> Result<u32, crate::syscall::SysError> {
        assert_eq!(image, 9);
        assert_eq!(metadata, b"metadata");
        let mut state = crate::STATE.lock().unwrap();
        state.events.push("create-stopped");
        if state.fail_create {
            Err(crate::syscall::SysError)
        } else {
            Ok(7)
        }
    }
    pub fn resume_handle(handle: u32) -> Result<(), crate::syscall::SysError> {
        assert_eq!(handle, 7);
        let mut state = crate::STATE.lock().unwrap();
        state.events.push("resume");
        if state.fail_resume {
            Err(crate::syscall::SysError)
        } else {
            Ok(())
        }
    }
    pub fn terminate_handle(handle: u32, code: u64) -> Result<(), crate::syscall::SysError> {
        assert_eq!((handle, code), (7, 127));
        let mut state = crate::STATE.lock().unwrap();
        state.events.push("terminate");
        if state.fail_terminate {
            return Err(crate::syscall::SysError);
        }
        if !state.termination_pending {
            state.exited = true;
        }
        Ok(())
    }
}

#[path = "../../service-manager/src/native_process.rs"]
mod production;

#[test]
fn display_launch_and_readiness_use_retained_handles_without_legacy_fallback() {
    let launcher = include_str!("../../service-manager/src/service_launcher.rs");
    let bootstrap = include_str!("../../service-manager/src/bootstrap.rs");
    let orchestration = include_str!("../../service-manager/src/orchestration.rs");
    let fixed_spawn = &launcher[launcher.find("pub(crate) fn spawn_fixed_service(").unwrap()
        ..launcher.find("pub(crate) fn spawn_input_service(").unwrap()];
    for native_only in [
        "Input",
        "Display",
        "Compositor",
        "Network",
        "User",
        "Update",
        "SecureUi",
    ] {
        assert!(fixed_spawn.contains(&format!("FixedService::{native_only}")));
    }
    assert!(launcher.contains("FixedService::Display,\n        \"display.driver\""));
    assert!(bootstrap.contains("type DisplayProcess = NativeProcess;"));
    assert!(bootstrap.contains("self.wait_ready(ReadyService::Display, process.watch_target())"));
    assert!(orchestration.contains("operations.spawn_display()"));
    assert!(!orchestration.contains("operations.spawn_fixed(FixedService::Display)"));
    assert!(orchestration.contains("children.display.as_ref().unwrap()"));
}

#[test]
fn fixed_services_register_userspace_posix_state_before_resume_with_rollback() {
    let launcher = include_str!("../../service-manager/src/service_launcher.rs");
    let native = launcher
        .split("fn spawn_native(")
        .nth(1)
        .unwrap()
        .split("pub(crate) fn spawn_mboot_agent(")
        .next()
        .unwrap();
    assert!(native.contains("resolve_execution_security(spec.path, spec.execution_class)?"));
    assert!(native.contains("NativeProcess::create_with_rollback"));
    assert!(!native.contains("create_and_resume"));
    assert!(!native.contains("thread_security_context"));
    let compact: String = native
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    assert!(compact.contains("client.register_spawned_child(ObjectHandleAttachment{handle,rights:mnu_abi::HANDLE_RIGHT_WAIT|mnu_abi::HANDLE_RIGHT_SIGNAL,},0,0,&[],)"));
    assert!(native.contains("retain_failed_launch(process, posix_endpoint)"));
    let rollback = include_str!("../../service-manager/src/launch_rollback.rs");
    assert!(rollback.contains("pending.process.retry_rollback"));
    let launcher_compact: String = rollback
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    assert!(launcher_compact.contains("pending.client.abort_launched_child"));
    assert!(native.contains("if has_failed_launch_cleanup()"));
    assert!(rollback.contains("FAILED_LAUNCHES.lock().unwrap().push_back(pending)"));
    assert!(
        include_str!("../../service-manager/src/bootstrap.rs")
            .contains("service_launcher::retry_failed_launch_cleanup();")
    );
    assert!(native.contains("close(image.handle)"));
}

#[test]
fn compositor_creation_keeps_a_native_owner_and_has_no_path_launch_fallback() {
    let launcher = include_str!("../../service-manager/src/service_launcher.rs");
    let start = launcher
        .find("pub(crate) fn spawn_compositor_service(")
        .unwrap();
    let end = start + launcher[start..].find("fn spawn_native_fixed(").unwrap();
    let compositor = &launcher[start..end];
    assert!(compositor.contains("Result<NativeProcess,"));
    assert!(compositor.contains("append_posix_handle(&mut arguments, Some(posix_endpoint))"));
    assert!(compositor.contains("spawn_native("));
    assert!(!compositor.contains("spawn("));
    let bootstrap = include_str!("../../service-manager/src/bootstrap.rs");
    assert!(bootstrap.contains("type CompositorProcess = NativeProcess;"));
    let orchestration = include_str!("../../service-manager/src/orchestration.rs");
    assert!(orchestration.contains("compositor: Option<Compositor>"));
    assert!(orchestration.contains("children.compositor = operations.spawn_compositor();"));
    assert!(!orchestration.contains("children.compositor = operations.spawn_fixed("));
}

#[test]
fn network_creation_and_readiness_use_native_owned_process_handles() {
    let launcher = include_str!("../../service-manager/src/service_launcher.rs");
    let start = launcher
        .find("pub(crate) fn spawn_network_service(")
        .unwrap();
    let end = start + launcher[start..].find("fn spawn_native_fixed(").unwrap();
    assert!(launcher[start..end].contains("FixedService::Network,\n        \"network.service\""));
    assert!(launcher[start..end].contains("Result<NativeProcess,"));
    let bootstrap = include_str!("../../service-manager/src/bootstrap.rs");
    assert!(bootstrap.contains("type NetworkProcess = NativeProcess;"));
    assert!(bootstrap.contains("self.wait_ready(ReadyService::Network, process.watch_target())"));
    let orchestration = include_str!("../../service-manager/src/orchestration.rs");
    assert!(orchestration.contains("network: Option<Network>"));
    assert!(orchestration.contains("children.network = operations.spawn_network();"));
    assert!(orchestration.contains("children.network.as_ref()"));
    assert!(!orchestration.contains("children.network = operations.spawn_fixed("));
}

#[test]
fn user_creation_and_readiness_use_native_owned_process_handles() {
    let launcher = include_str!("../../service-manager/src/service_launcher.rs");
    let start = launcher.find("pub(crate) fn spawn_user_service(").unwrap();
    let end = start + launcher[start..].find("fn spawn_native_fixed(").unwrap();
    assert!(launcher[start..end].contains("FixedService::User,\n        \"user.service\""));
    assert!(launcher[start..end].contains("Result<NativeProcess,"));
    let bootstrap = include_str!("../../service-manager/src/bootstrap.rs");
    assert!(bootstrap.contains("type UserProcess = NativeProcess;"));
    assert!(bootstrap.contains("self.wait_ready(ReadyService::User, process.watch_target())"));
    let orchestration = include_str!("../../service-manager/src/orchestration.rs");
    assert!(orchestration.contains("user: Option<User>"));
    assert!(orchestration.contains("operations.spawn_user()"));
    assert!(orchestration.contains("operations.wait_user_ready(children.user.as_ref().unwrap())"));
    assert!(!orchestration.contains("operations.spawn_fixed(FixedService::User)"));
}

#[test]
fn update_creation_keeps_a_native_owner_without_legacy_fallback() {
    let launcher = include_str!("../../service-manager/src/service_launcher.rs");
    let start = launcher
        .find("pub(crate) fn spawn_update_service(")
        .unwrap();
    let end = start + launcher[start..].find("fn spawn_native_fixed(").unwrap();
    let update = &launcher[start..end];
    assert!(update.contains("Result<NativeProcess,"));
    assert!(update.contains("append_posix_handle(&mut arguments, Some(posix_endpoint))"));
    assert!(update.contains("spawn_native("));
    assert!(!update.contains("spawn("));
    let bootstrap = include_str!("../../service-manager/src/bootstrap.rs");
    assert!(bootstrap.contains("type UpdateProcess = NativeProcess;"));
    let orchestration = include_str!("../../service-manager/src/orchestration.rs");
    assert!(orchestration.contains("update: Option<Update>"));
    assert!(orchestration.contains("children.update = operations.spawn_update();"));
    assert!(!orchestration.contains("children.update = operations.spawn_fixed("));
}

#[test]
fn secure_login_launches_and_watches_retained_native_process_handles() {
    let launcher = include_str!("../../service-manager/src/service_launcher.rs");
    let start = launcher.find("pub(crate) fn spawn_secure_ui(").unwrap();
    let end = start
        + launcher[start..]
            .find("pub(crate) fn spawn_iommu_warning(")
            .unwrap();
    let login = &launcher[start..end];
    assert!(login.contains("Result<NativeProcess,"));
    assert!(login.contains("append_posix_handle(&mut arguments, Some(posix_endpoint))"));
    assert!(login.contains("spawn_native("));
    assert!(!login.contains("spawn("));
    let bootstrap = include_str!("../../service-manager/src/bootstrap.rs");
    assert!(bootstrap.contains("type SecureUiProcess = NativeProcess;"));
    assert_eq!(
        bootstrap
            .matches("handshake.wait_for_login_complete(process.watch_target())")
            .count(),
        2
    );
    let orchestration = include_str!("../../service-manager/src/orchestration.rs");
    assert!(orchestration.contains("secure_ui: Option<SecureUi>"));
    assert!(orchestration.contains("operations.spawn_secure_ui()"));
    assert!(!orchestration.contains("operations.spawn_fixed(FixedService::SecureUi)"));
}

#[test]
fn remaining_secure_ui_warning_launch_is_native_and_keeps_its_owner() {
    let launcher = include_str!("../../service-manager/src/service_launcher.rs");
    assert!(!launcher.contains("spawn_portal_prompt("));
    assert!(!launcher.contains("spawn_network_prompt("));
    let start = launcher.find("pub(crate) fn spawn_iommu_warning(").unwrap();
    let end = start
        + launcher[start..]
            .find("pub(crate) fn spawn_permission_prompt_server(")
            .unwrap();
    let warning = &launcher[start..end];
    assert!(warning.contains("Result<NativeProcess,"));
    assert!(warning.contains("append_posix_handle(&mut arguments, Some(posix_endpoint))"));
    assert!(warning.contains("spawn_native("));
    assert!(!warning.contains("spawn("));
    let bootstrap = include_str!("../../service-manager/src/bootstrap.rs");
    assert!(bootstrap.contains("iommu_warning: Option<NativeProcess>"));
    assert!(bootstrap.contains("runtime.iommu_warning = Some(process)"));
    assert!(bootstrap.contains("!running_under_hypervisor()"));
}

#[test]
fn permission_server_uses_native_creation_and_an_explicit_send_handle() {
    let launcher = include_str!("../../service-manager/src/service_launcher.rs");
    let start = launcher
        .find("pub(crate) fn spawn_permission_prompt_server(")
        .unwrap();
    let end = start + launcher[start..].find("fn session_user(").unwrap();
    let server = &launcher[start..end];
    assert!(server.contains("Result<NativeProcess,"));
    assert!(server.contains("platform::handle::inherited("));
    assert!(server.contains("spawn_native("));
    assert!(!server.contains("spawn("));
    let portal = include_str!("../../service-manager/src/portal.rs");
    assert!(portal.contains("process.watch_target()"));
    assert!(portal.contains("platform::ipc::call_object_handles("));
    assert!(!portal.contains("call_with_wait("));
    let child = include_str!("../../secure-ui/src/permission_server.rs");
    assert!(child.contains("platform::service_ready::notify_handle("));
    assert!(child.contains("platform::ipc::wait_object_handles("));
    assert!(!child.contains("platform::ipc::try_wait("));
    assert!(child.contains("mochi_user_syscall::EIO as i32"));
    assert!(child.find("platform::ipc::reply(").unwrap() < child.find("ui_error.map_or(").unwrap());
}

#[test]
fn native_launch_transfers_failed_creation_owners_until_cleanup_is_confirmed() {
    let mut state = STATE.lock().unwrap();
    state.events.clear();
    state.fail_create = false;
    state.fail_resume = false;
    state.fail_status = false;
    state.fail_terminate = false;
    state.termination_pending = false;
    state.exited = false;
    state.status_calls = 0;
    drop(state);

    let mut process = production::NativeProcess::create_with_rollback(
        9,
        b"metadata",
        |_| Ok(()),
        |_| panic!("successful launch"),
    )
    .unwrap();
    assert_eq!(process.process_id(), 70);
    assert_eq!(
        process.watch_target(),
        process_watch::ProcessWatchTarget::RetainedHandle(7)
    );
    assert_eq!(process.termination_attachment().handle, 7);
    assert!(!process.tree_exit_confirmed());
    process.confirm_tree_exit();
    assert!(process.tree_exit_confirmed());
    assert_eq!(STATE.lock().unwrap().events, ["create-stopped", "resume"]);
    drop(process);
    assert_eq!(
        STATE.lock().unwrap().events,
        ["create-stopped", "resume", "close"]
    );

    for failure in 0..3 {
        {
            let mut state = STATE.lock().unwrap();
            state.events.clear();
            state.fail_resume = failure == 2;
            state.fail_status = failure == 1;
            state.fail_terminate = true;
            state.exited = false;
        }
        let mut retained = None;
        assert!(
            production::NativeProcess::create_with_rollback(
                9,
                b"metadata",
                |_| {
                    STATE.lock().unwrap().events.push("register-posix-state");
                    if failure == 0 {
                        Err(syscall::SysError)
                    } else {
                        Ok(())
                    }
                },
                |owner| retained = Some(owner),
            )
            .is_err()
        );
        let process = retained.unwrap();
        assert!(!STATE.lock().unwrap().events.contains(&"close"));
        // Native failure must not even attempt userspace reclaim.
        assert!(
            process
                .retry_rollback(|_| panic!("exit not confirmed"))
                .is_err()
        );
        assert!(!STATE.lock().unwrap().events.contains(&"close"));
        {
            let mut state = STATE.lock().unwrap();
            state.fail_status = false;
            state.fail_terminate = false;
            state.termination_pending = true;
        }
        assert!(
            process
                .retry_rollback(|_| panic!("termination is asynchronous"))
                .is_err()
        );
        assert!(!STATE.lock().unwrap().events.contains(&"close"));
        {
            let mut state = STATE.lock().unwrap();
            state.exited = true;
            state.events.clear();
        }
        assert!(
            process
                .retry_rollback(|handle| {
                    assert_eq!(handle, 7);
                    STATE.lock().unwrap().events.push("reclaim-failed");
                    Err(syscall::SysError)
                })
                .is_err()
        );
        assert_eq!(STATE.lock().unwrap().events, ["reclaim-failed"]);
        process
            .retry_rollback(|handle| {
                assert_eq!(handle, 7);
                STATE.lock().unwrap().events.push("reclaim-posix-state");
                Ok(())
            })
            .unwrap();
        // No repeat termination after confirmed exit, no early close.
        assert_eq!(
            STATE.lock().unwrap().events,
            ["reclaim-failed", "reclaim-posix-state"]
        );
        drop(process);
        assert_eq!(
            STATE.lock().unwrap().events,
            ["reclaim-failed", "reclaim-posix-state", "close"]
        );
    }
    {
        let mut state = STATE.lock().unwrap();
        state.events.clear();
        state.fail_create = true;
    }
    assert!(
        production::NativeProcess::create_with_rollback(
            9,
            b"metadata",
            |_| panic!("no created process"),
            |_| panic!("no owner to retain"),
        )
        .is_err()
    );
    assert_eq!(STATE.lock().unwrap().events, ["create-stopped"]);
    let mut state = STATE.lock().unwrap();
    state.fail_create = false;
    state.fail_resume = false;
    state.fail_status = false;
    state.fail_terminate = false;
    state.termination_pending = false;
    state.exited = false;
}
