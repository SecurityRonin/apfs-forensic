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
///
/// Shared-extent detection reads the volume's extent-reference tree
/// (`extentref_tree_oid`, a physical extent → owner/refcount map): a block with
/// refcount > 1 is shared by more than one file (`APFS-CLONE-SHARED-EXTENT`), and
/// an inode with `INODE_WAS_CLONED` set but no shared extent is an inconsistency
/// (`APFS-CLONE-FLAG-WITHOUT-SHARING`). The grading/emission logic lives in
/// [`clone_anomalies`] and is unit-tested; the extent-reference-tree reader that
/// would feed it real refcounts is a core capability not yet built (and no
/// committed corpus contains clones to validate it), so this currently surfaces
/// no clone findings rather than guess. It is wired through once that reader and
/// a clone-bearing fixture land.
#[must_use]
pub fn audit<R: std::io::Read + std::io::Seek>(
    _reader: &mut R,
    _volume: &apfs_core::volume::ApfsVolume,
) -> Vec<AnomalyKind> {
    // No extent-reference reader yet → no shared blocks observed → no clone
    // findings (an honest empty, not a guess).
    clone_anomalies(&[], &[])
}

/// Pure clone-finding logic (Humble Object). `shared` is `(inode_a, inode_b)`
/// pairs that share a physical extent; `flagged_unshared` is inodes whose
/// `INODE_WAS_CLONED` flag is set with no shared extent found.
fn clone_anomalies(_shared: &[(u64, u64)], _flagged_unshared: &[u64]) -> Vec<AnomalyKind> {
    Vec::new() // RED stub
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_sharing_no_flags_is_clean() {
        assert!(clone_anomalies(&[], &[]).is_empty());
    }

    #[test]
    fn shared_extent_is_a_provenance_link() {
        let v = clone_anomalies(&[(10, 20)], &[]);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].code(), "APFS-CLONE-SHARED-EXTENT");
    }

    #[test]
    fn clone_flag_without_sharing_is_inconsistency() {
        let v = clone_anomalies(&[], &[7]);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].code(), "APFS-CLONE-FLAG-WITHOUT-SHARING");
    }
}
