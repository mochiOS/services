//! Inode-based path traversal shared by filesystem namespace backends.

use ext4plus::path::{Component, Path};
use mochios_filesystem_protocol::MAX_PATH_LEN;
use std::collections::VecDeque;

const EIO: i32 = 5;
const ENOENT: i32 = 2;
const ENOTDIR: i32 = 20;
const EINVAL: i32 = 22;
const ELOOP: i32 = 40;

pub enum Resolution<N> {
    Found {
        inode: N,
        parent: Option<(N, Vec<u8>)>,
    },
    Missing {
        parent: N,
        name: Vec<u8>,
    },
}

#[derive(Clone, Copy)]
pub struct Credentials<'a> {
    pub uid: u32,
    pub gid: u32,
    pub groups: &'a [u32],
}

/// Nodes identify both filesystem and inode for multi-volume namespaces.
/// Implementations resolve mount crossings in `child` and return the virtual
/// namespace ancestry in `ancestry`, never the mounted volume's raw `..`.
pub trait Backend {
    type Node: Clone;
    fn is_directory(&self, node: &Self::Node) -> bool;
    fn is_symlink(&self, node: &Self::Node) -> bool;
    fn search(&self, node: &Self::Node, credentials: Credentials<'_>) -> Result<(), i32>;
    fn child(&self, node: &Self::Node, name: &[u8]) -> Result<Self::Node, i32>;
    fn symlink(&self, node: &Self::Node) -> Result<Vec<u8>, i32>;
    /// Returns root..base inclusive, or rejects a base outside root.
    fn ancestry(&self, root: &Self::Node, base: Self::Node) -> Result<Vec<Self::Node>, i32>;
}

pub fn resolve<B: Backend>(
    backend: &B,
    root: B::Node,
    base: B::Node,
    path: &[u8],
    follow_final: bool,
    credentials: Credentials<'_>,
) -> Result<Resolution<B::Node>, i32> {
    resolve_visible(
        backend,
        root,
        base,
        path,
        follow_final,
        credentials,
        |_, _, _| true,
    )
}

/// Reject private entries before following symlinks or returning a create target.
pub fn resolve_visible<B: Backend>(
    backend: &B,
    root: B::Node,
    base: B::Node,
    path: &[u8],
    follow_final: bool,
    credentials: Credentials<'_>,
    mut visible: impl FnMut(&B::Node, &[u8], &B::Node) -> bool,
) -> Result<Resolution<B::Node>, i32> {
    if path.is_empty() || path.len() > MAX_PATH_LEN || path.contains(&0) {
        return Err(EINVAL);
    }
    let parsed = Path::try_from(path).map_err(|_| EINVAL)?;
    let mut ancestors = if parsed.is_absolute() {
        vec![root]
    } else {
        backend.ancestry(&root, base)?
    };
    let mut pending = components(parsed);
    let require_directory = path.last() == Some(&b'/');
    let mut symlinks = 0usize;
    let mut iterations = 0usize;
    let mut last_name = None;
    while let Some(component) = pending.pop_front() {
        if component == OwnedComponent::DirectoryEnd {
            // This is a type requirement, not another pathname lookup. Keep
            // its parent identity and do not require final-directory search.
            if !backend.is_directory(ancestors.last().ok_or(EIO)?) {
                return Err(ENOTDIR);
            }
            continue;
        }
        iterations = iterations.checked_add(1).ok_or(ELOOP)?;
        if iterations > 1024 {
            return Err(ELOOP);
        }
        if component == OwnedComponent::Root {
            ancestors.truncate(1);
            last_name = None;
            continue;
        }
        let current = ancestors.last().ok_or(EIO)?;
        if !backend.is_directory(current) {
            return Err(ENOTDIR);
        }
        backend.search(current, credentials)?;
        match component {
            OwnedComponent::DirectoryEnd => unreachable!("handled before search"),
            OwnedComponent::Root | OwnedComponent::Current => {
                last_name = None;
            }
            OwnedComponent::Parent => {
                if ancestors.len() > 1 {
                    ancestors.pop();
                }
                last_name = None;
            }
            OwnedComponent::Normal(name) => {
                let child = match backend.child(current, &name) {
                    Ok(child) => child,
                    Err(ENOENT) if pending.is_empty() => {
                        return Ok(Resolution::Missing {
                            parent: current.clone(),
                            name,
                        });
                    }
                    Err(error) => return Err(error),
                };
                if !visible(current, &name, &child) {
                    return Err(ENOENT);
                }
                if backend.is_symlink(&child) && (follow_final || !pending.is_empty()) {
                    last_name = None;
                    symlinks += 1;
                    if symlinks > 40 {
                        return Err(ELOOP);
                    }
                    let target = backend.symlink(&child)?;
                    if target.len().saturating_add(path.len()) > MAX_PATH_LEN {
                        return Err(EINVAL);
                    }
                    let target = Path::try_from(target.as_slice()).map_err(|_| EINVAL)?;
                    if target.is_absolute() {
                        ancestors.truncate(1);
                    }
                    let mut target_components = components(target);
                    // Parsing drops trailing separators. Keep the target's
                    // directory requirement inside the unresolved sequence:
                    // it applies before an original suffix, not to its leaf.
                    if target.as_ref().last() == Some(&b'/') {
                        target_components.push_back(OwnedComponent::DirectoryEnd);
                    }
                    while let Some(component) = target_components.pop_back() {
                        pending.push_front(component);
                    }
                } else {
                    last_name = Some(name);
                    ancestors.push(child);
                }
            }
        }
    }
    let inode = ancestors.pop().ok_or(EIO)?;
    let parent = last_name.and_then(|name| ancestors.last().cloned().map(|parent| (parent, name)));
    if require_directory && !backend.is_directory(&inode) {
        return Err(ENOTDIR);
    }
    Ok(Resolution::Found { inode, parent })
}

#[derive(PartialEq, Eq)]
enum OwnedComponent {
    DirectoryEnd,
    Root,
    Current,
    Parent,
    Normal(Vec<u8>),
}
fn components(path: Path<'_>) -> VecDeque<OwnedComponent> {
    path.components()
        .map(|component| match component {
            Component::RootDir => OwnedComponent::Root,
            Component::CurDir => OwnedComponent::Current,
            Component::ParentDir => OwnedComponent::Parent,
            Component::Normal(name) => OwnedComponent::Normal(name.as_ref().to_vec()),
        })
        .collect()
}
