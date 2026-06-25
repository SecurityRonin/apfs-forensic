//! Structural integrity audits: Fletcher-64 checksum mismatches, object-map
//! inconsistencies, checkpoint-ring malformation, and (oid, xid) reuse.
//!
//! `APFS-OBJECT-CKSUM-MISMATCH` (High), `APFS-OMAP-INCONSISTENT` (High),
//! `APFS-OMAP-ORPHAN-MAPPING` (Info), `APFS-CHECKPOINT-RING-MALFORMED` (High),
//! `APFS-XID-REUSE` (High). A plain xid *gap* is NOT flagged — xids are
//! monotonic and the spec permits non-contiguous visible checkpoints.

use crate::AnomalyKind;

/// Verify structural integrity of an open container.
///
/// Checks the live checkpoint map for a reused object id (the same `cpm_oid`
/// mapped to two different blocks within one checkpoint is impossible under
/// copy-on-write → `APFS-XID-REUSE`). Note that a structurally malformed
/// checkpoint ring is already rejected loudly by `ApfsContainer::open`, so a
/// successfully-opened container has a valid ring. Full object-graph Fletcher-64
/// re-verification and omap target-type/xid agreement require a reader-bearing
/// pass over every object (the live superblock's checksum is verified at open);
/// they are layered in [`crate::audit_container`].
#[must_use]
pub fn audit<R: std::io::Read + std::io::Seek>(
    container: &apfs_core::ApfsContainer<R>,
) -> Vec<AnomalyKind> {
    let live_xid = container.superblock().xid;
    let mappings: Vec<(u64, u64)> = container
        .checkpoint_mappings()
        .iter()
        .map(|m| (m.oid, m.paddr))
        .collect();
    duplicate_oid_anomalies(&mappings, live_xid)
}

/// Pure logic (Humble Object): flag any object id that the live checkpoint map
/// resolves to two distinct blocks — two live objects claiming the same
/// `(oid, xid)`, impossible under copy-on-write.
fn duplicate_oid_anomalies(mappings: &[(u64, u64)], live_xid: u64) -> Vec<AnomalyKind> {
    let mut out = Vec::new();
    for i in 0..mappings.len() {
        let (oid, paddr) = mappings[i];
        // Reported once, on the first sighting of a colliding oid.
        let already = mappings[..i].iter().any(|&(o, _)| o == oid);
        let collides = mappings[i + 1..]
            .iter()
            .any(|&(o, p)| o == oid && p != paddr);
        if !already && collides {
            out.push(AnomalyKind::XidReuse { oid, xid: live_xid });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unique_oids_are_clean() {
        let maps = [(1u64, 10u64), (2, 11), (3, 12)];
        assert!(duplicate_oid_anomalies(&maps, 5).is_empty());
    }

    #[test]
    fn same_oid_two_blocks_is_xid_reuse() {
        // oid 1 mapped to both block 10 and block 99 within one checkpoint.
        let maps = [(1u64, 10u64), (2, 11), (1, 99)];
        let v = duplicate_oid_anomalies(&maps, 7);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].code(), "APFS-XID-REUSE");
    }

    #[test]
    fn same_oid_same_block_is_not_flagged() {
        // A duplicate identical mapping is not a contradiction.
        let maps = [(1u64, 10u64), (1, 10)];
        assert!(duplicate_oid_anomalies(&maps, 7).is_empty());
    }
}
