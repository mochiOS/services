//! Service admission limits belong to their userspace protocols, not mnu.
#[allow(dead_code)]
#[path = "../../compositor/src/protocol.rs"]
mod compositor;

use mochios_linux_gui_protocol as linux;
use mochios_workspace_protocol as workspace;

#[test]
fn linux_instance_limit_survives_both_launch_reply_formats() {
    assert_eq!(linux::STATUS_INSTANCE_LIMIT, -28);
    let mut bytes = [0; linux::LAUNCH_RESPONSE_LEN];
    let reply = linux::LaunchResponse {
        request_id: 17,
        status: linux::STATUS_INSTANCE_LIMIT,
        instance: 0,
    };
    let length = reply.encode(&mut bytes).unwrap();
    assert_eq!(linux::LaunchResponse::decode(&bytes[..length]), Ok(reply));
    let reply = linux::BundleLaunchResponse {
        request_id: 18,
        status: linux::STATUS_INSTANCE_LIMIT,
        instance: 0,
    };
    let length = reply.encode(&mut bytes).unwrap();
    assert_eq!(
        linux::BundleLaunchResponse::decode(&bytes[..length]),
        Ok(reply)
    );
    let source = include_str!("../../linux/src/runtime.rs");
    assert_eq!(
        source
            .matches("Err(mochios_linux_gui_protocol::STATUS_INSTANCE_LIMIT)")
            .count(),
        2
    );
    assert!(!source.contains("::ENOSPC"));
}

#[test]
fn workspace_capacity_reply_keeps_its_negative_wire_status() {
    assert_eq!(workspace::STATUS_CAPACITY_EXCEEDED, -28);
    let mut bytes = [0; workspace::HEADER_LEN + 24];
    let length =
        workspace::encode_status(42, workspace::STATUS_CAPACITY_EXCEEDED, 7, 0, &mut bytes)
            .unwrap();
    let reply = workspace::decode(&bytes[..length]).unwrap();
    assert_eq!(reply.request_id, 42);
    assert_eq!(workspace::decode_status(reply), Ok((-28, 7, 0)));
    let source = include_str!("../../workspace/src/main.rs");
    assert_eq!(
        source.matches("protocol::STATUS_CAPACITY_EXCEEDED").count(),
        3
    );
    assert!(!source.contains("::ENOSPC"));
    let panel = include_str!("../../../tools/devkit/crates/appcore/src/panel.rs");
    assert!(
        panel
            .contains("error.raw() == mochios_workspace_protocol::STATUS_CAPACITY_EXCEEDED as i64")
    );
    assert!(!panel.contains("::ENOSPC"));
}

#[test]
fn compositor_capacity_reply_keeps_its_positive_wire_status() {
    assert_eq!(compositor::STATUS_CAPACITY_EXCEEDED, 28);
    let mut bytes = [0; 16];
    compositor::put_u32(&mut bytes, 0, compositor::STATUS_CAPACITY_EXCEEDED);
    assert_eq!(compositor::read_u32(&bytes, 0), Some(28));
    for (source, occurrences) in [
        (include_str!("../../compositor/src/server.rs"), 2),
        (include_str!("../../compositor/src/surface.rs"), 2),
        (include_str!("../../compositor/src/decoration.rs"), 1),
    ] {
        assert_eq!(
            source
                .matches("put_u32(&mut reply, 0, STATUS_CAPACITY_EXCEEDED)")
                .count(),
            occurrences
        );
        assert!(!source.contains("::ENOSPC"));
    }
}
