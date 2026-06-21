//! Structural integrity audits: Fletcher-64 checksum mismatches, object-map
//! inconsistencies, checkpoint-ring malformation, and (oid, xid) reuse.
//!
//! `APFS-OBJECT-CKSUM-MISMATCH` (High), `APFS-OMAP-INCONSISTENT` (High),
//! `APFS-OMAP-ORPHAN-MAPPING` (Info), `APFS-CHECKPOINT-RING-MALFORMED` (High),
//! `APFS-XID-REUSE` (High). A plain xid *gap* is NOT flagged — xids are
//! monotonic and the spec permits non-contiguous visible checkpoints.

use crate::AnomalyKind;

/// Verify object checksums and map consistency across a container.
#[must_use]
pub fn audit<R: std::io::Read + std::io::Seek>(
    _container: &apfs_core::ApfsContainer<R>,
) -> Vec<AnomalyKind> {
    todo!("P9: cksum verify, omap target type/xid agreement, ring structure, xid reuse")
}
