//! Deleted-record recovery leads from copy-on-write residue.
//!
//! `APFS-DELETED-INODE-RECOVERABLE` (Medium) — a superseded inode/dir record
//! still present in an older checkpoint or unreaped block;
//! `APFS-DELETED-EXTENT-CARVE-CANDIDATE` (Low) — extent blocks marked free in
//! the spaceman bitmap (a *candidate*, NOT a recoverability guarantee: TRIM,
//! encryption, zeroing, and reuse races intervene — content must be validated);
//! `APFS-REAPER-PENDING-OBJECT` (Low) — object queued in the reaper;
//! `APFS-ORPHAN-INODE` (Low) — inode with no referencing DIR_REC.
//!
//! Validated against an INDEPENDENT oracle (real images / pre-delete capture +
//! apfsck), not only records we deleted ourselves.

use crate::AnomalyKind;

/// Surface deleted-record recovery leads.
#[must_use]
pub fn audit<R: std::io::Read + std::io::Seek>(
    _container: &apfs_core::ApfsContainer<R>,
) -> Vec<AnomalyKind> {
    todo!("P9: scan superseded checkpoints, reaper queue, free-extent candidates, orphans")
}
