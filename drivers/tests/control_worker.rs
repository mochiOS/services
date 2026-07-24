#[path = "../src/control_state.rs"]
mod control_state;
#[path = "../src/startup_args.rs"]
mod startup_args;

use control_state::{ControlAction, DiscoveryController, DiscoveryState, driver_hello};
use mochios_driver_control_protocol::{
    DISCOVERY_COMPLETE_LEN, DRIVER_HELLO_LEN, DiscoveryResult, Message, StartDiscovery,
};
use startup_args::{
    DriverManagerArgError, DriverManagerArgParser, DriverManagerConfig, LaunchMode,
};

fn parse(arguments: &[&[u8]]) -> Result<LaunchMode, DriverManagerArgError> {
    let mut parser = DriverManagerArgParser::new();
    for &argument in arguments {
        parser.push(argument)?;
    }
    parser.finish()
}

fn start_bytes(request_id: u64, token: u64, response_endpoint: u64) -> [u8; 32] {
    let request = StartDiscovery {
        request_id,
        token,
        response_endpoint,
    };
    let mut bytes = [0u8; 32];
    match request.encode(&mut bytes) {
        Ok(length) => assert_eq!(length, bytes.len()),
        Err(error) => panic!("START_DISCOVERY encode failed: {error:?}"),
    }
    bytes
}

#[test]
fn parses_driver_manager_argument_and_preserves_other_arguments() {
    assert_eq!(
        parse(&[
            b"drivers.service",
            b"42",
            b"--service-ready=9:10",
            b"--driver-manager=123:456",
        ]),
        Ok(LaunchMode::Controlled(DriverManagerConfig {
            endpoint: 123,
            token: 456,
        }))
    );
    assert_eq!(
        parse(&[b"drivers.service", b"42"]),
        Ok(LaunchMode::Compatibility)
    );
}

#[test]
fn rejects_missing_driver_manager_fields() {
    assert_eq!(
        parse(&[b"--driver-manager=:2"]),
        Err(DriverManagerArgError::MissingEndpoint)
    );
    assert_eq!(
        parse(&[b"--driver-manager=1:"]),
        Err(DriverManagerArgError::MissingToken)
    );
    assert_eq!(
        parse(&[b"--driver-manager=1"]),
        Err(DriverManagerArgError::MissingToken)
    );
    assert_eq!(
        parse(&[b"--driver-manager"]),
        Err(DriverManagerArgError::InvalidFormat)
    );
}

#[test]
fn rejects_duplicate_and_invalid_driver_manager_arguments() {
    assert_eq!(
        parse(&[b"--driver-manager=1:2", b"--driver-manager=3:4"]),
        Err(DriverManagerArgError::Duplicate)
    );
    assert_eq!(
        parse(&[b"--driver-manager=abc:2"]),
        Err(DriverManagerArgError::InvalidEndpoint)
    );
    assert_eq!(
        parse(&[b"--driver-manager=1:abc"]),
        Err(DriverManagerArgError::InvalidToken)
    );
    assert_eq!(
        parse(&[b"--driver-manager=18446744073709551616:1"]),
        Err(DriverManagerArgError::InvalidEndpoint)
    );
    assert_eq!(
        parse(&[b"--driver-manager=1:2:3"]),
        Err(DriverManagerArgError::InvalidFormat)
    );
}

#[test]
fn hello_uses_configured_fields_and_protocol_golden_bytes() {
    let hello = driver_hello(
        0x0807_0605_0403_0201,
        0x1817_1615_1413_1211,
        0x2827_2625_2423_2221,
    );
    assert_eq!(hello.request_id, 0x0807_0605_0403_0201);
    assert_eq!(hello.token, 0x1817_1615_1413_1211);
    assert_eq!(hello.control_endpoint, 0x2827_2625_2423_2221);
    let mut bytes = [0u8; DRIVER_HELLO_LEN];
    assert_eq!(hello.encode(&mut bytes), Ok(DRIVER_HELLO_LEN));
    assert_eq!(
        bytes,
        [
            b'D', b'R', b'V', b'C', 1, 0, 1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 17, 18, 19, 20, 21, 22, 23,
            24, 33, 34, 35, 36, 37, 38, 39, 40,
        ]
    );
}

#[test]
fn valid_request_runs_once_and_completes_with_matching_request_id() {
    let mut controller = DiscoveryController::new(55);
    let request = start_bytes(71, 55, 91);
    let pending = match controller.handle_message(&request) {
        ControlAction::Run(pending) => pending,
        action => panic!("expected discovery run, got {action:?}"),
    };
    assert_eq!(controller.state(), DiscoveryState::Running);
    let mut discovery_runs = 0;
    discovery_runs += 1;
    let result = DiscoveryResult { status: 0 };
    match controller.complete(pending, result) {
        ControlAction::Reply {
            response_endpoint,
            message,
        } => {
            assert_eq!(response_endpoint, 91);
            assert_eq!(message.request_id, 71);
            assert_eq!(message.status, 0);
            let mut response = [0u8; DISCOVERY_COMPLETE_LEN];
            assert_eq!(message.encode(&mut response), Ok(DISCOVERY_COMPLETE_LEN));
        }
        action => panic!("expected completion reply, got {action:?}"),
    }
    assert_eq!(controller.state(), DiscoveryState::Complete(result));
    assert_eq!(discovery_runs, 1);
}

#[test]
fn wrong_token_and_malformed_message_keep_waiting() {
    let mut controller = DiscoveryController::new(55);
    assert_eq!(
        controller.handle_message(&start_bytes(1, 54, 2)),
        ControlAction::Ignore
    );
    assert_eq!(controller.state(), DiscoveryState::Waiting);
    assert_eq!(
        controller.handle_message(b"not a control message"),
        ControlAction::Ignore
    );
    assert_eq!(controller.state(), DiscoveryState::Waiting);
}

#[test]
fn running_request_returns_negative_ebusy_without_another_run() {
    let mut controller = DiscoveryController::new(55);
    let first = start_bytes(1, 55, 2);
    assert!(matches!(
        controller.handle_message(&first),
        ControlAction::Run(_)
    ));
    match controller.handle_message(&start_bytes(3, 55, 4)) {
        ControlAction::Reply {
            response_endpoint,
            message,
        } => {
            assert_eq!(response_endpoint, 4);
            assert_eq!(message.request_id, 3);
            assert_eq!(message.status, -16);
        }
        action => panic!("expected busy reply, got {action:?}"),
    }
    assert_eq!(controller.state(), DiscoveryState::Running);
}

#[test]
fn complete_request_reuses_result_with_new_request_id_without_running() {
    let mut controller = DiscoveryController::new(55);
    let pending = match controller.handle_message(&start_bytes(1, 55, 2)) {
        ControlAction::Run(pending) => pending,
        action => panic!("expected discovery run, got {action:?}"),
    };
    let saved = DiscoveryResult { status: -5 };
    assert!(matches!(
        controller.complete(pending, saved),
        ControlAction::Reply { .. }
    ));
    match controller.handle_message(&start_bytes(99, 55, 100)) {
        ControlAction::Reply {
            response_endpoint,
            message,
        } => {
            assert_eq!(response_endpoint, 100);
            assert_eq!(message.request_id, 99);
            assert_eq!(message.status, -5);
        }
        action => panic!("expected saved completion reply, got {action:?}"),
    }
    assert_eq!(controller.state(), DiscoveryState::Complete(saved));
}

#[test]
fn non_start_protocol_message_does_not_begin_discovery() {
    let mut controller = DiscoveryController::new(55);
    let hello = driver_hello(1, 55, 2);
    let mut bytes = [0u8; DRIVER_HELLO_LEN];
    assert_eq!(hello.encode(&mut bytes), Ok(DRIVER_HELLO_LEN));
    assert_eq!(Message::decode(&bytes), Ok(Message::DriverHello(hello)));
    assert_eq!(controller.handle_message(&bytes), ControlAction::Ignore);
    assert_eq!(controller.state(), DiscoveryState::Waiting);
}
