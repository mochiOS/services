use posix_service::socket_gc::{Node, unreachable};
fn nodes(counts: &[u64]) -> Vec<Node> {
    counts
        .iter()
        .enumerate()
        .map(|(index, references)| Node {
            id: index as u64 + 1,
            references: *references,
        })
        .collect()
}

#[test]
fn self_cycles_and_duplicate_edges_are_collected_without_an_external_root() {
    assert_eq!(unreachable(&nodes(&[1]), &[(1, 1)]), Ok(vec![1]));
    assert_eq!(unreachable(&nodes(&[2]), &[(1, 1), (1, 1)]), Ok(vec![1]));
    assert_eq!(unreachable(&nodes(&[3]), &[(1, 1), (1, 1)]), Ok(vec![]));
    assert_eq!(
        unreachable(&nodes(&[1, 1]), &[(1, 2), (2, 1)]),
        Ok(vec![1, 2])
    );
}
#[test]
fn roots_keep_their_entire_reachable_closure_but_not_unrelated_cycles() {
    let edges = [(1, 2), (2, 3), (3, 2), (4, 5), (5, 4), (6, 6)];
    // External/native temporary reference to node 1 retains 2 and 3 too.
    assert_eq!(
        unreachable(&nodes(&[1, 2, 1, 1, 1, 1]), &edges),
        Ok(vec![4, 5, 6])
    );
    // An extra queued IPC reference to node 5 conservatively retains 4 and 5.
    assert_eq!(
        unreachable(&nodes(&[1, 2, 1, 1, 2, 1]), &edges),
        Ok(vec![6])
    );
    assert_eq!(
        unreachable(&nodes(&[0, 2, 1, 1, 1, 1]), &edges),
        Ok(vec![1, 2, 3, 4, 5, 6])
    );
}
#[test]
fn inconsistent_snapshots_unknown_nodes_and_duplicate_ids_never_authorize_discard() {
    assert_eq!(unreachable(&nodes(&[0]), &[(1, 1)]), Err(-11));
    assert_eq!(unreachable(&nodes(&[1]), &[(1, 2)]), Err(-22));
    assert_eq!(unreachable(&nodes(&[1]), &[(2, 1)]), Err(-22));
    assert_eq!(
        unreachable(
            &[Node {
                id: 1,
                references: 1
            }; 2],
            &[]
        ),
        Err(-22)
    );
    assert_eq!(
        unreachable(
            &[Node {
                id: 0,
                references: 0
            }],
            &[]
        ),
        Err(-22)
    );
    assert_eq!(unreachable(&[], &[]), Ok(vec![]));
}
#[test]
fn maximum_depth_is_iterative_not_recursive() {
    let count = posix_service::socket::MAX_ENDPOINTS;
    let mut info = nodes(&vec![1; count]);
    let mut edges: Vec<_> = (1..count as u64).map(|id| (id, id + 1)).collect();
    assert_eq!(unreachable(&info, &edges), Ok(vec![]));
    info[0].references = 0;
    assert_eq!(unreachable(&info, &edges), Ok((1..=count as u64).collect()));
    edges.push((count as u64, 1));
    info[0].references = 1;
    assert_eq!(unreachable(&info, &edges), Ok((1..=count as u64).collect()));
}
