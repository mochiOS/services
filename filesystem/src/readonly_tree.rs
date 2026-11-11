//! Immutable, capability-relative file trees. Publishing bytes never authorizes
//! an ambient pathname. A delegated subdirectory cannot escape to its parent.
use mochios_filesystem_protocol::{self as wire, readonly_tree as protocol};
use std::{
    collections::BTreeMap,
    ops::Range,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

/// Aggregate serialized data limit, independent of publisher or caller identity.
pub const LIVE_BYTES: usize = 512 * 1024 * 1024;
#[derive(Clone, Default)]
pub struct Budget(Arc<AtomicUsize>);
impl Budget {
    /// Account retained immutable bytes across every open reference.
    pub fn used(&self) -> usize {
        self.0.load(Ordering::Relaxed)
    }
}
struct Reservation {
    budget: Budget,
    size: usize,
}
impl Drop for Reservation {
    fn drop(&mut self) {
        self.budget.0.fetch_sub(self.size, Ordering::Relaxed);
    }
}
struct Node {
    name: String,
    parent: usize,
    data: Option<Range<usize>>,
    children: BTreeMap<String, usize>,
}
/// Frozen snapshot; its owning reservation is released only after the last open.
pub struct Tree {
    bytes: Vec<u8>,
    nodes: Vec<Node>,
    _reservation: Reservation,
}
impl Tree {
    /// Own already captured caller bytes. No alias to mutable input survives.
    pub fn capture(bytes: Vec<u8>, budget: &Budget) -> Result<Arc<Self>, i32> {
        let mut entries = protocol::Entries::new(&bytes).map_err(|_| 22)?;
        let mut nodes = vec![Node {
            name: String::new(),
            parent: 0,
            data: None,
            children: BTreeMap::new(),
        }];
        while let Some((name, data)) = entries.next_entry().map_err(|_| 22)? {
            let parts: Vec<_> = name.split('/').collect();
            let mut parent = 0;
            for (i, part) in parts.iter().enumerate() {
                let last = i + 1 == parts.len();
                if let Some(&index) = nodes[parent].children.get(*part) {
                    if last || nodes[index].data.is_some() {
                        return Err(17);
                    }
                    parent = index;
                } else {
                    if nodes.len() >= protocol::MAX_NODES {
                        return Err(7);
                    }
                    let index = nodes.len();
                    nodes.push(Node {
                        name: (*part).into(),
                        parent,
                        data: last.then_some(data.clone()),
                        children: BTreeMap::new(),
                    });
                    nodes[parent].children.insert((*part).into(), index);
                    parent = index;
                }
            }
        }
        // Conservatively charge 1 KiB per node plus both name copies, covering
        // node-vector capacity, sparse B-tree allocations and path components.
        let metadata = nodes
            .iter()
            .try_fold(0usize, |n, node| n.checked_add(1024 + node.name.len() * 2))
            .ok_or(12)?;
        let charged = bytes.len().checked_add(metadata).ok_or(12)?;
        budget
            .0
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
                old.checked_add(charged).filter(|n| *n <= LIVE_BYTES)
            })
            .map_err(|_| 12)?;
        Ok(Arc::new(Self {
            bytes,
            nodes,
            _reservation: Reservation {
                budget: budget.clone(),
                size: charged,
            },
        }))
    }
    /// Number of stable identities needed by the owning provider.
    pub fn nodes(&self) -> usize {
        self.nodes.len()
    }
    /// Resolve beneath an explicitly delegated directory, never a global root.
    pub fn resolve(&self, base: usize, path: &[u8]) -> Result<usize, i32> {
        if !self.directory(base)? {
            return Err(20);
        }
        let path = core::str::from_utf8(path).map_err(|_| 22)?;
        if path.is_empty()
            || path.starts_with('/')
            || path.len() >= wire::MAX_PATH_LEN
            || path.bytes().any(|b| b == b'\\' || b.is_ascii_control())
        {
            return Err(13);
        }
        let trailing = path.ends_with('/');
        let mut current = base;
        for part in path.split('/') {
            if !self.directory(current)? {
                return Err(20);
            }
            match part {
                "" | "." => (),
                ".." => {
                    if current == base {
                        return Err(13);
                    }
                    current = self.nodes[current].parent;
                }
                _ => current = *self.nodes[current].children.get(part).ok_or(2)?,
            }
        }
        if trailing && !self.directory(current)? {
            return Err(20);
        }
        Ok(current)
    }
    /// True only for synthesized directories; symlinks cannot be represented.
    pub fn directory(&self, node: usize) -> Result<bool, i32> {
        Ok(self.nodes.get(node).ok_or(9)?.data.is_none())
    }
    /// Exact regular-file size; directory byte lengths are intentionally absent.
    pub fn length(&self, node: usize) -> Result<u64, i32> {
        Ok(self
            .nodes
            .get(node)
            .ok_or(9)?
            .data
            .as_ref()
            .ok_or(21)?
            .len() as u64)
    }
    /// Copy a file range without exposing bytes belonging to neighboring files.
    pub fn read(&self, node: usize, offset: u64, output: &mut [u8]) -> Result<usize, i32> {
        let range = self.nodes.get(node).ok_or(9)?.data.as_ref().ok_or(21)?;
        let start = usize::try_from(offset)
            .unwrap_or(usize::MAX)
            .min(range.len());
        let done = output.len().min(range.len() - start);
        output[..done]
            .copy_from_slice(&self.bytes[range.start + start..range.start + start + done]);
        Ok(done)
    }
}
/// One native open description, shared by duplicated references.
pub struct Open {
    pub tree: Arc<Tree>,
    pub node: usize,
    pub identity_base: u64,
    /// Filesystem namespace volume identity, distinct from pager identity.
    pub volume: u32,
    pub offset: u64,
    pub flags: u32,
    pub cursor_records: bool,
}
impl Open {
    /// Read ordinary filesystem directory records, with a stable per-open cursor.
    pub fn read_directory(&mut self, length: usize) -> Result<Vec<u8>, i32> {
        if !self.tree.directory(self.node)? {
            return Err(20);
        }
        let mut out = vec![0; length.min(mnu_abi::provider::MAX_DATA_LEN)];
        let mut written = 0;
        let children = &self.tree.nodes[self.node].children;
        for (ordinal, (name, &index)) in children
            .iter()
            .enumerate()
            .skip(usize::try_from(self.offset).unwrap_or(usize::MAX))
        {
            let kind = if self.tree.directory(index)? {
                wire::NODE_TYPE_DIRECTORY
            } else {
                wire::NODE_TYPE_REGULAR
            };
            let result = if self.cursor_records {
                wire::encode_cursor_dir_entry(
                    (u64::from(self.volume) << 32) | (index as u64 + 1),
                    kind,
                    name.as_bytes(),
                    ordinal as u64 + 1,
                    &mut out[written..],
                )
            } else {
                wire::encode_dir_entry(
                    (u64::from(self.volume) << 32) | (index as u64 + 1),
                    kind,
                    name.as_bytes(),
                    &mut out[written..],
                )
            };
            match result {
                Ok(n) => {
                    written += n;
                    self.offset = ordinal as u64 + 1;
                }
                Err(_) if written != 0 => break,
                Err(_) => return Err(22),
            }
        }
        out.truncate(written);
        Ok(out)
    }
    /// File range, cursor and seek stay local to this native open description.
    pub fn read(&mut self, output: &mut [u8]) -> Result<(usize, u64), i32> {
        let start = self.offset;
        let done = self.tree.read(self.node, start, output)?;
        self.offset = self.offset.checked_add(done as u64).ok_or(27)?;
        Ok((done, start))
    }
    /// Preserve POSIX seek behavior while refusing directory SEEK_END.
    pub fn seek(&mut self, offset: i64, basis: u64) -> Result<u64, i32> {
        let base = match basis {
            mnu_abi::HANDLE_SEEK_START => 0,
            mnu_abi::HANDLE_SEEK_CURRENT => self.offset,
            mnu_abi::HANDLE_SEEK_END => self.tree.length(self.node)?,
            _ => return Err(22),
        };
        self.offset = u64::try_from(i128::from(base) + i128::from(offset)).map_err(|_| 22)?;
        Ok(self.offset)
    }
}
