//! Reusable protected renderer. The broker owns every execution decision.
use crate::execution_prompt::Presentation;
use mochi_user_platform as p;
use p::capability::consent::{Choice, Correlation, frontend as wire, prompt};
use std::{
    cell::RefCell,
    rc::Rc,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    time::{Duration, Instant},
};
use viewkit::{
    prelude::*,
    view::{Constraints, MeasureContext, PaintContext},
};

const ARGUMENT: &str = "--execution-consent-server";
thread_local! {
    // ViewKit callbacks run on this UI thread. Every view owns its question;
    // no old callback can obtain a later request through this publication slot.
    static QUESTION: RefCell<Option<Rc<Question>>> = const { RefCell::new(None) };
}
pub(crate) fn requested() -> bool {
    std::env::args().any(|argument| argument == ARGUMENT)
}
fn denied() -> p::syscall::SysError {
    p::syscall::SysError::from(p::syscall::NativeError::AccessDenied.into_raw())
}
struct Broker {
    peer: p::execution_peer::MeasuredPeer,
}
impl Broker {
    fn connect() -> Result<Self, p::syscall::SysError> {
        // A service name selects a candidate, never authenticates it. Require
        // its kernel-bound system identity and broker authority separately.
        let peer = p::execution_peer::capture(p::process::find_by_name("capability.service")?)?;
        let context = &peer.context;
        if context.package_id.get(..context.package_id_len as usize)
            != Some(b"org.mochios.capability")
            || context
                .developer_id
                .get(..context.developer_id_len as usize)
                != Some(b"org.mochios.system")
            || context.subject_key_id != [0; 32]
            || p::capability::check_thread(peer.endpoint, "capabilities.manage") != Ok(1)
        {
            return Err(denied());
        }
        Ok(Self { peer })
    }
    fn current(&self) -> Result<(), p::syscall::SysError> {
        let current = p::execution_peer::capture(self.peer.endpoint)?;
        if current.image != self.peer.image
            || !p::handle::same_object(current.process.0, self.peer.process.0)?
        {
            return Err(denied());
        }
        Ok(())
    }
    fn call(&self, request: &[u8], reply: &mut [u8]) -> Result<usize, p::syscall::SysError> {
        self.current()?;
        let mut handles = p::ipc::IpcObjectHandles::default();
        let message = p::ipc::call_object_handles(
            u32::try_from(self.peer.endpoint).map_err(|_| denied())?,
            request,
            reply,
            &mut handles,
        )?;
        let unexpected = handles.count != 0 || handles.delivery_flags != 0;
        for attached in handles
            .handles
            .iter()
            .take((handles.count as usize).min(handles.handles.len()))
        {
            if attached.handle != 0 {
                let _ = p::handle::close(attached.handle);
            }
        }
        self.current()?;
        if unexpected || message >> 32 != self.peer.endpoint {
            return Err(denied());
        }
        let length = message as u32 as usize;
        if length > reply.len() {
            return Err(denied());
        }
        Ok(length)
    }
    fn command(
        &self,
        correlation: Correlation,
        action: wire::Action,
    ) -> Result<(), p::syscall::SysError> {
        let request = wire::encode(correlation, action).map_err(|_| denied())?;
        let mut reply = [0; 8];
        if self.call(&request, &mut reply)? != reply.len() {
            return Err(denied());
        }
        let status = u64::from_le_bytes(reply);
        if status == 0 {
            Ok(())
        } else if status <= 4095 {
            Err(p::syscall::SysError::from_raw(-(status as i64)))
        } else {
            Err(denied())
        }
    }
}
struct Question {
    broker: Rc<Broker>,
    presentation: Presentation,
    correlation: Correlation,
    first_frame: AtomicBool,
    armed: AtomicBool,
    next_poll: AtomicU64,
}
fn retryable(error: p::syscall::SysError) -> bool {
    error.errno() == Some(mochios_posix_client::newlib_errno::EAGAIN as u64)
}
fn startup<T>(stage: &str, result: Result<T, p::syscall::SysError>) -> T {
    result.unwrap_or_else(|reason| {
        p::logln!(
            "secure-ui.service: execution consent {stage} failed raw={}",
            reason.raw()
        );
        std::process::exit(1)
    })
}
pub(crate) fn run() -> Result<(), ViewKitError> {
    let target = p::service_ready::take_bootstrap_target().unwrap_or_else(|| std::process::exit(1));
    let endpoint = p::ipc::create_handle().unwrap_or_else(|_| std::process::exit(1));
    if p::service_ready::notify_handle(
        target,
        0,
        endpoint,
        p::handle::HANDLE_RIGHT_SEND | p::handle::HANDLE_RIGHT_TRANSFER,
    )
    .is_err()
    {
        std::process::exit(1);
    }
    let broker = Rc::new(startup("broker", Broker::connect()));
    loop {
        let mut bytes = [0; prompt::MAX_MESSAGE_BYTES];
        let length = startup(
            "wait",
            broker.call(&wire::encode_wait(wire::Kind::Graphical), &mut bytes),
        );
        let offer = prompt::decode(&bytes[..length]).unwrap_or_else(|_| std::process::exit(1));
        let correlation = offer.correlation;
        let presentation =
            Presentation::decode(&bytes[..length]).unwrap_or_else(|_| std::process::exit(1));
        let question = Rc::new(Question {
            broker: Rc::clone(&broker),
            presentation,
            correlation,
            first_frame: AtomicBool::new(false),
            armed: AtomicBool::new(false),
            next_poll: AtomicU64::new(0),
        });
        QUESTION.with(|slot| {
            assert!(slot.borrow_mut().replace(Rc::clone(&question)).is_none());
        });
        let result = viewkit::run::<ExecutionPromptApp>();
        // Complete ViewKit teardown and retire this correlation before waiting
        // for the next question. Display receipts/input arms are never reused.
        let _ = question
            .broker
            .command(question.correlation, wire::Action::Dismissed);
        QUESTION.with(|slot| {
            slot.borrow_mut().take();
        });
        if let Err(reason) = result {
            p::logln!("secure-ui.service: execution consent window failed: {reason:?}");
            let _ = p::handle::close(endpoint);
            return Err(reason);
        }
    }
}
struct ExecutionPromptApp {
    question: Rc<Question>,
}
impl App for ExecutionPromptApp {
    type Body = Box<dyn View>;
    fn new() -> Self {
        Self {
            question: QUESTION.with(|slot| Rc::clone(slot.borrow().as_ref().unwrap())),
        }
    }
    fn window(&self) -> WindowOptions {
        WindowOptions::new("Application Permissions")
            .compact()
            .resizable(false)
            .secure_overlay(true)
            .fullscreen(false)
    }
    fn protected_presentation_for_window(
        &self,
        _: viewkit::app::WindowId,
    ) -> Option<viewkit::platform::ProtectedPresentation> {
        Some(self.question.presentation.binding())
    }
    fn first_frame_presented(&mut self) {
        self.question.first_frame.store(true, Ordering::Release);
    }
    fn close_requested(&mut self) -> bool {
        let _ = self
            .question
            .broker
            .command(self.question.correlation, wire::Action::Dismissed);
        true
    }
    fn body(&self, _: &ViewContext) -> Self::Body {
        let question = Rc::clone(&self.question);
        let proposal = Rc::clone(&question);
        Box::new(ProtectedContent {
            question,
            inner: Box::new(
                ZStack::new()
                    .alignment(ZStackAlignment::Center)
                    .child(
                        Rectangle::new()
                            .color(RectangleColor::Custom(Theme::current().shell.scrim)),
                    )
                    .child(
                        self.question
                            .presentation
                            .content(move |correlation, choice| {
                                if choice != Choice::Deny && !proposal.armed.load(Ordering::Acquire)
                                {
                                    return;
                                }
                                match proposal
                                    .broker
                                    .command(correlation, wire::Action::Decide(choice))
                                {
                                    Ok(()) => viewkit::request_exit(),
                                    Err(reason) if retryable(reason) => {}
                                    Err(_) => viewkit::request_exit(),
                                }
                            }),
                    ),
            ),
        })
    }
}
struct ProtectedContent {
    inner: Box<dyn View>,
    question: Rc<Question>,
}
impl View for ProtectedContent {
    fn measure(&self, constraints: Constraints, context: &mut MeasureContext<'_>) -> Size {
        self.inner.measure(constraints, context)
    }
    fn paint(&self, bounds: Rect, context: &mut PaintContext<'_>) {
        self.inner.paint(bounds, context);
        let now = p::time::monotonic_nanoseconds().unwrap_or(u64::MAX);
        let question = &self.question;
        if question.first_frame.load(Ordering::Acquire)
            && now >= question.next_poll.load(Ordering::Acquire)
        {
            question
                .next_poll
                .store(now.saturating_add(100_000_000), Ordering::Release);
            match question
                .broker
                .command(question.correlation, wire::Action::Presented)
            {
                Ok(()) => question.armed.store(true, Ordering::Release),
                Err(reason) if retryable(reason) => {}
                Err(reason) => {
                    p::logln!(
                        "secure-ui.service: execution consent presentation failed raw={}",
                        reason.raw()
                    );
                    viewkit::request_exit();
                }
            }
        }
        context.request_redraw_in_at(bounds, Instant::now() + Duration::from_millis(100));
    }
    fn handle_event(
        &self,
        bounds: Rect,
        event: &viewkit::event::ViewEvent,
        context: &mut viewkit::event::EventContext<'_>,
    ) -> viewkit::event::EventResult {
        self.inner.handle_event(bounds, event, context)
    }
}
