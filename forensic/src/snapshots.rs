//! Snapshot audits: xid/create-time disorder, missing metadata vs name records,
//! and snapshot-vs-live divergence.
//!
//! `APFS-SNAPSHOT-XID-DISORDER` (Info), `APFS-SNAPSHOT-MISSING-METADATA`
//! (Medium), `APFS-SNAPSHOT-DIVERGENCE` (Info). These are observation leads, not
//! proofs — legitimate operations (Time Machine thinning) produce similar
//! signatures, so the framing stays at Info/Medium and "consistent with".

use crate::AnomalyKind;

/// Audit a volume's snapshots.
#[must_use]
pub fn audit(_volume: &apfs_core::volume::ApfsVolume) -> Vec<AnomalyKind> {
    todo!("P9: cross-check snap-metadata vs snap-name trees, xid ordering, live divergence")
}
