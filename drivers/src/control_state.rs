use mochios_driver_control_protocol::{
    DiscoveryComplete, DiscoveryResult, DriverHello, Message, StartDiscovery,
};

const EBUSY_ERRNO: i32 = 16;
const BUSY_STATUS: i32 = -EBUSY_ERRNO;

pub(crate) const fn driver_hello(
    request_id: u64,
    token: u64,
    control_endpoint: u64,
) -> DriverHello {
    DriverHello {
        request_id,
        token,
        control_endpoint,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DiscoveryState {
    Waiting,
    Running,
    Complete(DiscoveryResult),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PendingDiscovery {
    pub(crate) request_id: u64,
    pub(crate) response_endpoint: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ControlAction {
    Ignore,
    Run(PendingDiscovery),
    Reply {
        response_endpoint: u64,
        message: DiscoveryComplete,
    },
}

pub(crate) struct DiscoveryController {
    token: u64,
    state: DiscoveryState,
}

impl DiscoveryController {
    pub(crate) const fn new(token: u64) -> Self {
        Self {
            token,
            state: DiscoveryState::Waiting,
        }
    }

    #[cfg(test)]
    pub(crate) const fn state(&self) -> DiscoveryState {
        self.state
    }

    pub(crate) fn handle_message(&mut self, bytes: &[u8]) -> ControlAction {
        let Ok(Message::StartDiscovery(request)) = Message::decode(bytes) else {
            return ControlAction::Ignore;
        };
        self.handle_request(request)
    }

    pub(crate) fn complete(
        &mut self,
        pending: PendingDiscovery,
        result: DiscoveryResult,
    ) -> ControlAction {
        if self.state != DiscoveryState::Running {
            return ControlAction::Ignore;
        }
        self.state = DiscoveryState::Complete(result);
        ControlAction::Reply {
            response_endpoint: pending.response_endpoint,
            message: result.response(pending.request_id),
        }
    }

    fn handle_request(&mut self, request: StartDiscovery) -> ControlAction {
        if request.token != self.token {
            return ControlAction::Ignore;
        }
        match self.state {
            DiscoveryState::Waiting => {
                self.state = DiscoveryState::Running;
                ControlAction::Run(PendingDiscovery {
                    request_id: request.request_id,
                    response_endpoint: request.response_endpoint,
                })
            }
            DiscoveryState::Running => ControlAction::Reply {
                response_endpoint: request.response_endpoint,
                message: DiscoveryComplete {
                    request_id: request.request_id,
                    status: BUSY_STATUS,
                },
            },
            DiscoveryState::Complete(result) => ControlAction::Reply {
                response_endpoint: request.response_endpoint,
                message: result.response(request.request_id),
            },
        }
    }
}
