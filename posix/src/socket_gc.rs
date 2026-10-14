//! Conservative collection of queue-only socket reference cycles. Node IDs are
//! worker-private descriptions, not client authority. The caller serializes all
//! graph mutation and does not issue Handle transfers while taking samples.
//! A zero external count then remains zero: clients cannot create authority
//! from nothing, and queued IPC/kernel references are included in the sample.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Node {
    pub id: u64,
    pub references: u64,
}

/// Every edge denotes ONE strong queued reference, including duplicate leases.
/// Other references (FDs, IPC in flight, staging, routes, waits, VM aliases and
/// temporary kernel operations) are conservative roots. Missing/inconsistent
/// observations abort collection; an error must never mean "no external refs".
pub fn unreachable(nodes: &[Node], edges: &[(u64, u64)]) -> Result<Vec<u64>, i32> {
    if nodes.len() > crate::socket::MAX_ENDPOINTS {
        return Err(-22);
    }
    for (index, node) in nodes.iter().enumerate() {
        if node.id == 0 || nodes[..index].iter().any(|old| old.id == node.id) {
            return Err(-22);
        }
    }
    let mut incoming = Vec::new();
    incoming.try_reserve_exact(nodes.len()).map_err(|_| -12)?;
    incoming.resize(nodes.len(), 0u64);
    for (source, target) in edges {
        if !nodes.iter().any(|node| node.id == *source) {
            return Err(-22);
        }
        let index = nodes
            .iter()
            .position(|node| node.id == *target)
            .ok_or(-22)?;
        incoming[index] = incoming[index].checked_add(1).ok_or(-75)?;
    }
    let mut reachable = Vec::new();
    reachable.try_reserve_exact(nodes.len()).map_err(|_| -12)?;
    reachable.resize(nodes.len(), false);
    let mut work = Vec::new();
    work.try_reserve_exact(nodes.len()).map_err(|_| -12)?;
    for (index, node) in nodes.iter().enumerate() {
        if node.references < incoming[index] {
            return Err(-11);
        }
        if node.references > incoming[index] {
            reachable[index] = true;
            work.push(index);
        }
    }
    while let Some(index) = work.pop() {
        for (_, target) in edges
            .iter()
            .filter(|(source, _)| *source == nodes[index].id)
        {
            // All endpoints were validated before traversal.
            let target = nodes
                .iter()
                .position(|node| node.id == *target)
                .ok_or(-22)?;
            if !reachable[target] {
                reachable[target] = true;
                work.push(target);
            }
        }
    }
    let mut garbage = Vec::new();
    garbage.try_reserve_exact(nodes.len()).map_err(|_| -12)?;
    for (node, reachable) in nodes.iter().zip(reachable) {
        if !reachable {
            garbage.push(node.id);
        }
    }
    Ok(garbage)
}
