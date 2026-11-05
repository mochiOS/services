//! Keep one measured secure-ui presenter available, with bounded restart
//! frequency. The capability broker owns its waiting call and every decision.
use crate::{
    native_process::NativeProcess, process_watch::ProcessWatch, readiness::DeferredMessage,
};
use alloc::collections::VecDeque;
use mochi_user_platform as p;
struct Worker {
    process: Option<NativeProcess>,
    watch: Option<ProcessWatch>,
    endpoint: Option<u32>,
    posix: u32,
}
impl Drop for Worker {
    fn drop(&mut self) {
        if let Some(process) = self.process.take() {
            process.terminate();
            crate::launch_rollback::retain_failed_launch(process, self.posix);
        }
        if let Some(endpoint) = self.endpoint {
            let _ = p::handle::close(endpoint);
        }
    }
}
#[derive(Default)]
pub(crate) struct Presenter {
    worker: Option<Worker>,
    next_check: u64,
    cleanup_blocked: bool,
}
impl Presenter {
    pub(crate) fn maintain(&mut self, logger: u64, deferred: &mut VecDeque<DeferredMessage>) {
        let Ok(now) = p::time::monotonic_nanoseconds() else {
            return;
        };
        if now < self.next_check {
            return;
        }
        self.next_check = now.saturating_add(1_000_000_000);
        if crate::service_launcher::has_failed_launch_cleanup() {
            if !self.cleanup_blocked {
                let _ = p::logger::write_status_fmt(format_args!(
                    "service-manager.service: execution presenter waiting for failed launch cleanup\n"
                ));
                self.cleanup_blocked = true;
            }
            return;
        }
        self.cleanup_blocked = false;
        if let Some(worker) = self.worker.as_ref() {
            match worker.watch.as_ref().unwrap().exit_status() {
                Ok(None) => return,
                Ok(Some(status)) => {
                    let _ = p::logger::write_status_fmt(format_args!(
                        "service-manager.service: execution presenter exited status={status}\n"
                    ));
                    self.worker = None;
                    return;
                }
                Err(reason) => {
                    let _ = p::logger::write_status_fmt(format_args!(
                        "service-manager.service: execution prompt status failed: {:?}\n",
                        reason
                    ));
                    return;
                }
            }
        }
        let result = (|| {
            let token = p::service_ready::generate_token()?;
            let target = p::service_ready::Target {
                endpoint: p::ipc::create()?,
                token,
            };
            let posix = p::handle::inherited(mochios_posix_protocol::CONTROL_HANDLE_KEY)?;
            let process = crate::service_launcher::spawn_execution_prompt_server(logger, target)?;
            let mut worker = Worker {
                process: Some(process),
                watch: None,
                endpoint: None,
                posix,
            };
            let process = worker.process.as_ref().unwrap();
            worker.watch = Some(
                ProcessWatch::open(process.watch_target())
                    .map_err(|_| p::syscall::SysError::from_raw(-5))?,
            );
            worker.endpoint = Some(
                match crate::readiness::wait_for_published_endpoint(
                    token,
                    process.watch_target(),
                    deferred,
                ) {
                    Ok(endpoint) => endpoint,
                    Err(reason) => {
                        let _ = p::logger::write_status_fmt(format_args!(
                            "service-manager.service: execution prompt readiness failed: {:?}\n",
                            reason
                        ));
                        return Err(p::syscall::SysError::from_raw(-5));
                    }
                },
            );
            Ok(worker)
        })();
        match result {
            Ok(worker) => {
                let _ = p::logger::write_status_fmt(format_args!(
                    "service-manager.service: execution presenter ready pid={}\n",
                    worker.process.as_ref().unwrap().process_id()
                ));
                self.worker = Some(worker);
            }
            Err(reason) => {
                let _ = p::logger::write_status_fmt(format_args!(
                    "service-manager.service: execution prompt launch failed: {:?}\n",
                    reason
                ));
            }
        }
    }
}
