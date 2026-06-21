//! Clone / dedup analysis.
//!
//! `APFS-CLONE-SHARED-EXTENT` (Info) — two inodes share physical extents
//! (clonefile/dedup); a provenance link, not an anomaly.
//! `APFS-CLONE-FLAG-WITHOUT-SHARING` (Low) — `INODE_WAS_CLONED` internal flag is
//! set but no shared extent is found (an inconsistency).
//!
//! Shared-extent detection uses the extent-reference tree (a block referenced by
//! more than one file).

use crate::AnomalyKind;

/// Audit clone/dedup relationships in a volume.
#[must_use]
pub fn audit<R: std::io::Read + std::io::Seek>(
    _reader: &mut R,
    _volume: &apfs_core::volume::ApfsVolume,
) -> Vec<AnomalyKind> {
    todo!("P9: extentref-tree shared-block detection; cross-check INODE_WAS_CLONED")
}
