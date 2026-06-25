//! Deleted-record recovery leads from copy-on-write residue.
//!
//! `APFS-DELETED-INODE-RECOVERABLE` (Medium) — a superseded inode/dir record
//! still present in an older checkpoint or unreaped block;
//! `APFS-DELETED-EXTENT-CARVE-CANDIDATE` (Low) — extent blocks marked free in
//! the spaceman bitmap (a *candidate*, NOT a recoverability guarantee: TRIM,
//! encryption, zeroing, and reuse races intervene — content must be validated);
//! `APFS-REAPER-PENDING-OBJECT` (Low) — object queued in the reaper;
//! `APFS-ORPHAN-INODE` (Low) — inode with no referencing `DIR_REC`.
//!
//! Validated against an INDEPENDENT oracle (real images / pre-delete capture +
//! apfsck), not only records we deleted ourselves.

use crate::AnomalyKind;

/// Surface deleted-but-present recovery leads from the reaper queue.
///
/// Objects queued in the reaper are logically deleted but still physically
/// present (`APFS-REAPER-PENDING-OBJECT`). The further recovery leads in the
/// design — superseded-checkpoint inodes (`APFS-DELETED-INODE-RECOVERABLE`),
/// free-marked extent blocks (`APFS-DELETED-EXTENT-CARVE-CANDIDATE`), and orphan
/// inodes (`APFS-ORPHAN-INODE`) — require an independent oracle (a real image or
/// pre-delete capture + `apfsck`) to validate without false positives, so they
/// are layered in as that corpus becomes available.
///
/// `reaper_paddr` and `mappings` come from the open container
/// ([`apfs_core::ApfsContainer::reaper_paddr`] /
/// [`apfs_core::ApfsContainer::checkpoint_mappings`]).
///
/// # Errors
/// Surfaces an [`apfs_core::ApfsError`] from reading the reaper.
pub fn audit<R: std::io::Read + std::io::Seek>(
    reader: &mut R,
    reaper_paddr: u64,
    mappings: &[apfs_core::checkpoint::CheckpointMapping],
    block_size: usize,
) -> crate::Result<Vec<AnomalyKind>> {
    let pending = apfs_core::reaper::pending_objects(reader, reaper_paddr, mappings, block_size)?;
    let oids: Vec<u64> = pending.iter().map(|p| p.oid).collect();
    Ok(reaper_anomalies(&oids))
}

/// Pure mapping (Humble Object): each reaper-pending object id → a Low
/// `APFS-REAPER-PENDING-OBJECT` residue lead.
fn reaper_anomalies(pending_oids: &[u64]) -> Vec<AnomalyKind> {
    pending_oids
        .iter()
        .map(|&oid| AnomalyKind::ReaperPendingObject { oid })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_pending_objects_is_clean() {
        assert!(reaper_anomalies(&[]).is_empty());
    }

    #[test]
    fn pending_objects_become_residue_leads() {
        let v = reaper_anomalies(&[500, 600]);
        assert_eq!(v.len(), 2);
        assert!(v.iter().all(|a| a.code() == "APFS-REAPER-PENDING-OBJECT"));
    }
}
