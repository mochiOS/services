extern crate self as mochi_user_platform;

use std::sync::Mutex;

pub mod syscall {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct SysError;
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
}
static STATE: Mutex<State> = Mutex::new(State {
    events: Vec::new(),
    fail_create: false,
    fail_resume: false,
});

pub mod handle {
    pub type Handle = u32;
    pub fn close(handle: Handle) -> Result<(), crate::syscall::SysError> {
        assert_eq!(handle, 7);
        crate::STATE.lock().unwrap().events.push("close");
        Ok(())
    }
}

pub mod process {
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
        crate::STATE.lock().unwrap().events.push("terminate");
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
    for native_only in ["Input", "Display", "Compositor", "Network", "User"] {
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
fn native_launch_owns_the_creation_reference_and_cleans_failed_resume() {
    let process = production::NativeProcess::create_and_resume(9, b"metadata").unwrap();
    assert_eq!(
        process.watch_target(),
        process_watch::ProcessWatchTarget::RetainedHandle(7)
    );
    assert_eq!(STATE.lock().unwrap().events, ["create-stopped", "resume"]);
    drop(process);
    assert_eq!(
        STATE.lock().unwrap().events,
        ["create-stopped", "resume", "close"]
    );
    {
        let mut state = STATE.lock().unwrap();
        state.events.clear();
        state.fail_create = true;
    }
    assert!(production::NativeProcess::create_and_resume(9, b"metadata").is_err());
    assert_eq!(STATE.lock().unwrap().events, ["create-stopped"]);
    {
        let mut state = STATE.lock().unwrap();
        state.events.clear();
        state.fail_create = false;
        state.fail_resume = true;
    }
    assert!(production::NativeProcess::create_and_resume(9, b"metadata").is_err());
    assert_eq!(
        STATE.lock().unwrap().events,
        ["create-stopped", "resume", "terminate", "close"]
    );
}
