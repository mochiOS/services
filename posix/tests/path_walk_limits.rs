use std::cell::Cell;

use filesystem_service::path_walk::{Backend, Credentials, Resolution, resolve};
use mochios_filesystem_protocol::MAX_PATH_LEN;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Node {
    Directory(usize),
    File,
    Link,
}

struct Namespace {
    target: Vec<u8>,
    searches: Cell<usize>,
}

impl Backend for Namespace {
    type Node = Node;

    fn is_directory(&self, node: &Node) -> bool {
        matches!(node, Node::Directory(_))
    }

    fn is_symlink(&self, node: &Node) -> bool {
        *node == Node::Link
    }

    fn search(&self, _: &Node, _: Credentials<'_>) -> Result<(), i32> {
        self.searches.set(self.searches.get() + 1);
        Ok(())
    }

    fn child(&self, node: &Node, name: &[u8]) -> Result<Node, i32> {
        match (node, name) {
            (Node::Directory(depth), b"d") => Ok(Node::Directory(depth + 1)),
            (Node::Directory(_), b"leaf") => Ok(Node::File),
            (Node::Directory(_), b"alias") => Ok(Node::Link),
            (Node::Directory(_), name) if name.len() == 255 => Ok(Node::File),
            _ => Err(2),
        }
    }

    fn symlink(&self, _: &Node) -> Result<Vec<u8>, i32> {
        Ok(self.target.clone())
    }

    fn ancestry(&self, root: &Node, base: Node) -> Result<Vec<Node>, i32> {
        assert_eq!(*root, Node::Directory(0));
        assert_eq!(base, Node::Directory(0));
        Ok(vec![base])
    }
}

fn namespace(target: Vec<u8>) -> Namespace {
    Namespace {
        target,
        searches: Cell::new(0),
    }
}

fn walk(ns: &Namespace, path: &[u8], follow: bool) -> Result<Resolution<Node>, i32> {
    resolve(
        ns,
        Node::Directory(0),
        Node::Directory(0),
        path,
        follow,
        Credentials {
            uid: 501,
            gid: 20,
            groups: &[],
        },
    )
}

fn found(result: Result<Resolution<Node>, i32>) -> Node {
    match result.unwrap() {
        Resolution::Found { inode, .. } => inode,
        Resolution::Missing { .. } => panic!("expected existing inode"),
    }
}

#[test]
fn valid_paths_are_not_limited_to_1024_components() {
    let ns = namespace(Vec::new());
    let mut path = b"d/".repeat(1500);
    path.extend_from_slice(b"leaf");
    assert!(path.len() <= MAX_PATH_LEN);
    assert_eq!(found(walk(&ns, &path, true)), Node::File);
    assert_eq!(ns.searches.get(), 1501);

    let dots = b"./".repeat(MAX_PATH_LEN / 2);
    assert_eq!(found(walk(&ns, &dots, true)), Node::Directory(0));
    let parents = b"../".repeat(MAX_PATH_LEN / 3);
    assert_eq!(found(walk(&ns, &parents, true)), Node::Directory(0));
}

#[test]
fn expanded_link_targets_can_contain_more_than_1024_components() {
    let mut target = b"./".repeat(1500);
    target.extend_from_slice(b"leaf");
    let ns = namespace(target);
    assert_eq!(found(walk(&ns, b"alias", true)), Node::File);
}

#[test]
fn component_length_errors_are_distinct_from_invalid_wire_paths() {
    let ns = namespace(Vec::new());
    assert_eq!(found(walk(&ns, &vec![b'x'; 255], true)), Node::File);
    for prefix in [b"".as_slice(), b"/", b"d/"] {
        let mut path = prefix.to_vec();
        path.extend_from_slice(&[b'x'; 256]);
        assert!(matches!(walk(&ns, &path, true), Err(36)));
    }
    assert!(matches!(walk(&ns, b"leaf\0suffix", true), Err(22)));
}

#[test]
fn overlong_link_components_are_rejected_only_when_followed() {
    let ns = namespace(vec![b'x'; 256]);
    assert_eq!(found(walk(&ns, b"alias", false)), Node::Link);
    assert!(matches!(walk(&ns, b"alias", true), Err(36)));
    assert!(matches!(walk(&ns, b"alias/leaf", false), Err(36)));
}

#[test]
fn overlong_input_path_is_rejected_before_any_lookup() {
    let ns = namespace(Vec::new());
    let path = vec![b'/'; MAX_PATH_LEN + 1];
    assert!(matches!(walk(&ns, &path, true), Err(36)));
    assert_eq!(ns.searches.get(), 0);
}

#[test]
fn removing_the_component_limit_does_not_remove_the_symlink_limit() {
    let ns = namespace(b"alias".to_vec());
    assert!(matches!(walk(&ns, b"alias", true), Err(40)));
    assert_eq!(ns.searches.get(), 41);
}

#[test]
fn symlink_expansion_does_not_count_the_already_resolved_prefix() {
    let ns = namespace(b"leaf".to_vec());
    let mut path = b"./".repeat(2045);
    path.extend_from_slice(b"alias");
    assert_eq!(path.len(), MAX_PATH_LEN - 1);
    assert_eq!(found(walk(&ns, &path, true)), Node::File);
}

#[test]
fn final_symlink_target_can_use_the_full_path_budget() {
    let mut target = b"./".repeat((MAX_PATH_LEN - 4) / 2);
    target.extend_from_slice(b"leaf");
    assert_eq!(target.len(), MAX_PATH_LEN);
    let ns = namespace(target);
    assert_eq!(found(walk(&ns, b"alias", true)), Node::File);
}

#[test]
fn expanded_length_includes_the_exact_unresolved_separators_and_suffix() {
    let mut target = b"./".repeat(2045);
    target.extend_from_slice(b"d");
    let ns = namespace(target);
    assert_eq!(ns.target.len() + b"/leaf".len(), MAX_PATH_LEN);
    assert_eq!(found(walk(&ns, b"alias/leaf", true)), Node::File);
    for path in [b"alias//leaf".as_slice(), b"alias/leaf/", b"alias///leaf"] {
        assert!(matches!(walk(&ns, path, true), Err(36)));
    }
}

#[test]
fn repeated_expansion_accounts_for_suffixes_left_by_prior_links() {
    let mut target = b"alias/".to_vec();
    target.extend_from_slice(&b"d/".repeat(1000));
    let ns = namespace(target);
    // Each expansion leaves another suffix behind. Reject the expanded length
    // before reaching the independent 40-link limit.
    assert!(matches!(walk(&ns, b"alias/leaf", true), Err(36)));
    assert!(ns.searches.get() < 40);
}

#[test]
fn oversized_targets_do_not_affect_nofollow_and_fail_with_name_too_long() {
    let ns = namespace(vec![b'/'; MAX_PATH_LEN + 1]);
    assert_eq!(found(walk(&ns, b"alias", false)), Node::Link);
    assert!(matches!(walk(&ns, b"alias", true), Err(36)));
}

#[test]
fn empty_link_target_never_resolves_to_its_parent_or_suffix() {
    let ns = namespace(Vec::new());
    assert_eq!(found(walk(&ns, b"alias", false)), Node::Link);
    for path in [b"alias".as_slice(), b"alias/leaf"] {
        assert!(matches!(walk(&ns, path, true), Err(2)));
    }
}
