use filesystem_service::path_walk::{Backend, Credentials, Resolution, resolve};

// Different volumes intentionally reuse the same inode numbers.
type Node = (u64, u64);
const ROOT: Node = (0, 2);
const MOUNT: Node = (1, 2);
const OUTSIDE: Node = (0, 3);
const INSIDE: Node = (1, 3);
const ABS_LINK: Node = (1, 4);
const REL_LINK: Node = (1, 5);
const LOOP: Node = (1, 6);
struct Namespace {
    deny_mounted_search: bool,
}

impl Backend for Namespace {
    type Node = Node;
    fn is_directory(&self, node: &Node) -> bool {
        matches!(*node, ROOT | MOUNT)
    }
    fn is_symlink(&self, node: &Node) -> bool {
        matches!(*node, ABS_LINK | REL_LINK | LOOP)
    }
    fn search(&self, node: &Node, _: Credentials<'_>) -> Result<(), i32> {
        if self.deny_mounted_search && *node == MOUNT {
            Err(13)
        } else {
            Ok(())
        }
    }
    fn child(&self, node: &Node, name: &[u8]) -> Result<Node, i32> {
        match (*node, name) {
            (ROOT, b"system") => Ok(MOUNT),
            (ROOT, b"outside") => Ok(OUTSIDE),
            (MOUNT, b"inside") => Ok(INSIDE),
            (MOUNT, b"absolute") => Ok(ABS_LINK),
            (MOUNT, b"relative") => Ok(REL_LINK),
            (MOUNT, b"loop") => Ok(LOOP),
            _ => Err(2),
        }
    }
    fn symlink(&self, node: &Node) -> Result<Vec<u8>, i32> {
        Ok(match *node {
            ABS_LINK => b"/outside".to_vec(),
            REL_LINK => b"../outside".to_vec(),
            LOOP => b"loop".to_vec(),
            _ => return Err(22),
        })
    }
    fn ancestry(&self, root: &Node, base: Node) -> Result<Vec<Node>, i32> {
        match (*root, base) {
            (ROOT, ROOT) => Ok(vec![ROOT]),
            (ROOT, MOUNT) => Ok(vec![ROOT, MOUNT]),
            (MOUNT, MOUNT) => Ok(vec![MOUNT]),
            _ => Err(13),
        }
    }
}
fn walk(root: Node, base: Node, path: &[u8], follow: bool) -> Result<Resolution<Node>, i32> {
    resolve(
        &Namespace {
            deny_mounted_search: false,
        },
        root,
        base,
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
fn mount_crossings_keep_volume_identity_and_virtual_parent() {
    assert_eq!(found(walk(ROOT, ROOT, b"/system/inside", true)), INSIDE);
    assert_eq!(
        found(walk(ROOT, ROOT, b"/system/../outside", true)),
        OUTSIDE
    );
    assert_eq!(found(walk(ROOT, MOUNT, b"../outside", true)), OUTSIDE);
    match walk(ROOT, ROOT, b"/system/new", true).unwrap() {
        Resolution::Missing { parent, name } => {
            assert_eq!(parent, MOUNT);
            assert_eq!(name, b"new");
        }
        _ => panic!("missing leaf must retain the mounted parent inode"),
    }
}

#[test]
fn absolute_and_relative_symlinks_follow_namespace_not_volume_roots() {
    assert_eq!(found(walk(ROOT, ROOT, b"/system/absolute", true)), OUTSIDE);
    assert_eq!(found(walk(ROOT, ROOT, b"/system/relative", true)), OUTSIDE);
    assert_eq!(
        found(walk(ROOT, ROOT, b"/system/absolute", false)),
        ABS_LINK
    );
}

#[test]
fn confined_mount_root_cannot_escape_through_parent_or_absolute_link() {
    assert_eq!(found(walk(MOUNT, MOUNT, b"../../inside", true)), INSIDE);
    for path in [b"/absolute".as_slice(), b"relative"] {
        match walk(MOUNT, MOUNT, path, true).unwrap() {
            Resolution::Missing { parent, name } => {
                assert_eq!(parent, MOUNT);
                assert_eq!(name, b"outside");
            }
            _ => panic!("link escaped confined root"),
        }
    }
    assert!(matches!(walk(MOUNT, ROOT, b"inside", true), Err(13)));
}

#[test]
fn mounted_directory_search_and_symlink_loop_limits_are_enforced() {
    let backend = Namespace {
        deny_mounted_search: true,
    };
    assert!(matches!(
        resolve(
            &backend,
            ROOT,
            ROOT,
            b"/system/inside",
            true,
            Credentials {
                uid: 501,
                gid: 20,
                groups: &[]
            }
        ),
        Err(13)
    ));
    assert!(matches!(walk(ROOT, ROOT, b"/system/loop", true), Err(40)));
    assert!(matches!(
        walk(ROOT, ROOT, b"/system/inside/", true),
        Err(20)
    ));
}
