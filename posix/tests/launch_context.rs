use std::collections::BTreeMap;

use mochios_posix_client::fd::{
    Entry, FD_CLOEXEC, FdTable, HandleOps, LaunchContextOps, LaunchFdDescription, LaunchFdError,
    restore_launch_context, stage_launch_context,
};
use mochios_posix_protocol as protocol;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Object {
    id: u64,
    kind: u8,
    open_flags: u32,
    has_handle: bool,
}

#[derive(Default)]
struct Context {
    values: BTreeMap<u64, u64>,
    handles: BTreeMap<u64, Object>,
    rights: BTreeMap<u64, u64>,
}

impl LaunchContextOps<Object> for Context {
    type Error = ();

    fn get_value(&mut self, key: u64) -> Result<Option<u64>, Self::Error> {
        Ok(self.values.get(&key).copied())
    }

    fn get_handle(&mut self, key: u64) -> Result<Option<Object>, Self::Error> {
        Ok(self.handles.get(&key).copied())
    }

    fn get_handle_rights(&mut self, handle: Object) -> Result<u64, Self::Error> {
        self.rights.get(&handle.id).copied().ok_or(())
    }

    fn set_value(&mut self, key: u64, value: u64) -> Result<(), Self::Error> {
        self.values.insert(key, value);
        Ok(())
    }

    fn remove_value(&mut self, key: u64) -> Result<(), Self::Error> {
        self.values.remove(&key);
        Ok(())
    }

    fn set_handle(&mut self, key: u64, handle: Object) -> Result<(), Self::Error> {
        self.handles.insert(key, handle);
        Ok(())
    }

    fn remove_handle(&mut self, key: u64) -> Result<(), Self::Error> {
        self.handles.remove(&key);
        Ok(())
    }
}

#[derive(Default)]
struct Objects(Vec<u64>);

impl HandleOps<Object> for Objects {
    type Error = ();

    fn clone_handle(&mut self, handle: Object, _rights: u64) -> Result<Object, Self::Error> {
        Ok(handle)
    }

    fn close_handle(&mut self, handle: Object) {
        self.0.push(handle.id);
    }
}

fn object(id: u64, kind: u8, open_flags: u32, has_handle: bool) -> Object {
    Object {
        id,
        kind,
        open_flags,
        has_handle,
    }
}

fn describe(object: Object) -> Option<LaunchFdDescription> {
    Some(LaunchFdDescription {
        kind: object.kind,
        open_flags: object.open_flags,
        has_handle: object.has_handle,
    })
}

#[test]
fn launch_context_round_trip_preserves_fd_numbers_rights_and_open_state() {
    let stdin = object(0, protocol::INHERITED_FD_KIND_STDIN, 0, false);
    let file = object(41, protocol::INHERITED_FD_KIND_FILE, 0x1234, true);
    let cloexec = object(42, protocol::INHERITED_FD_KIND_FILE, 0x5678, true);
    let mut source = FdTable::new();
    let mut objects = Objects::default();
    source
        .install_at(
            0,
            Entry {
                handle: stdin,
                rights: 0,
                descriptor_flags: 0,
            },
            &mut objects,
        )
        .unwrap();
    source
        .install_at(
            7,
            Entry {
                handle: file,
                rights: 0x25,
                descriptor_flags: 0,
            },
            &mut objects,
        )
        .unwrap();
    source
        .install_at(
            8,
            Entry {
                handle: cloexec,
                rights: 0x77,
                descriptor_flags: FD_CLOEXEC,
            },
            &mut objects,
        )
        .unwrap();

    let mut context = Context::default();
    context.rights.insert(file.id, 0x25);
    context.values.insert(
        protocol::fd_metadata_key(8).unwrap(),
        protocol::encode_inherited_fd_metadata(protocol::InheritedFdMetadata {
            kind: protocol::INHERITED_FD_KIND_FILE,
            open_flags: 1,
            descriptor_flags: 0,
        })
        .unwrap(),
    );
    context
        .handles
        .insert(protocol::fd_handle_key(8).unwrap(), cloexec);

    stage_launch_context(&source, 16, &mut context, describe).unwrap();
    assert!(
        !context
            .values
            .contains_key(&protocol::fd_metadata_key(8).unwrap())
    );
    assert!(
        !context
            .handles
            .contains_key(&protocol::fd_handle_key(8).unwrap())
    );
    assert!(
        !context
            .handles
            .contains_key(&protocol::fd_handle_key(0).unwrap())
    );

    let mut restored = FdTable::new();
    assert_eq!(
        restore_launch_context(
            &mut restored,
            16,
            &mut context,
            &mut objects,
            |metadata, attachment| {
                Some(attachment.map_or_else(
                    || object(0, metadata.kind, metadata.open_flags, false),
                    |(handle, _)| object(handle.id, metadata.kind, metadata.open_flags, true),
                ))
            },
        ),
        Ok(true)
    );
    assert_eq!(restored.get(0).unwrap().handle, stdin);
    assert_eq!(restored.get(7).unwrap().handle, file);
    assert_eq!(restored.get(7).unwrap().rights, 0x25);
    assert_eq!(restored.get(7).unwrap().descriptor_flags, 0);
    assert_eq!(restored.get(8), None);
}

#[test]
fn restore_rejects_object_metadata_without_an_attached_handle() {
    let mut context = Context::default();
    context.values.insert(
        protocol::fd_metadata_key(3).unwrap(),
        protocol::encode_inherited_fd_metadata(protocol::InheritedFdMetadata {
            kind: protocol::INHERITED_FD_KIND_FILE,
            open_flags: 0,
            descriptor_flags: 0,
        })
        .unwrap(),
    );
    let mut restored = FdTable::new();
    let mut objects = Objects::default();
    assert_eq!(
        restore_launch_context(
            &mut restored,
            8,
            &mut context,
            &mut objects,
            |_, attachment| attachment.map(|(handle, _)| handle),
        ),
        Err(LaunchFdError::MissingHandle)
    );
}

#[test]
fn restore_rejects_hidden_handle_on_a_pseudo_descriptor() {
    let stdin = object(9, protocol::INHERITED_FD_KIND_STDIN, 0, true);
    let mut context = Context::default();
    context.values.insert(
        protocol::fd_metadata_key(0).unwrap(),
        protocol::encode_inherited_fd_metadata(protocol::InheritedFdMetadata {
            kind: protocol::INHERITED_FD_KIND_STDIN,
            open_flags: 0,
            descriptor_flags: 0,
        })
        .unwrap(),
    );
    context
        .handles
        .insert(protocol::fd_handle_key(0).unwrap(), stdin);
    let mut restored = FdTable::new();
    let mut objects = Objects::default();
    assert_eq!(
        restore_launch_context(
            &mut restored,
            1,
            &mut context,
            &mut objects,
            |_, attachment| attachment.map(|(handle, _)| handle),
        ),
        Err(LaunchFdError::UnexpectedHandle)
    );
}

#[test]
fn pty_descriptor_round_trip_preserves_bidirectional_object_handle() {
    let pty = object(73, protocol::INHERITED_FD_KIND_PTY, 2, true);
    let mut source = FdTable::new();
    let mut objects = Objects::default();
    source
        .install_at(
            5,
            Entry {
                handle: pty,
                rights: 0x3f,
                descriptor_flags: 0,
            },
            &mut objects,
        )
        .unwrap();

    let mut context = Context::default();
    context.rights.insert(pty.id, 0x3f);
    stage_launch_context(&source, 8, &mut context, describe).unwrap();

    let mut restored = FdTable::new();
    assert_eq!(
        restore_launch_context(
            &mut restored,
            8,
            &mut context,
            &mut objects,
            |metadata, attachment| {
                attachment
                    .map(|(handle, _)| object(handle.id, metadata.kind, metadata.open_flags, true))
            },
        ),
        Ok(true)
    );
    assert_eq!(restored.get(5).unwrap().handle, pty);
    assert_eq!(restored.get(5).unwrap().rights, 0x3f);
}
