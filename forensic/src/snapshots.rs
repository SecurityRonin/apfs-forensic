//! Snapshot audits: xid/create-time disorder, missing metadata vs name records,
//! and snapshot-vs-live divergence.
//!
//! `APFS-SNAPSHOT-XID-DISORDER` (Info), `APFS-SNAPSHOT-MISSING-METADATA`
//! (Medium), `APFS-SNAPSHOT-DIVERGENCE` (Info). These are observation leads, not
//! proofs — legitimate operations (Time Machine thinning) produce similar
//! signatures, so the framing stays at Info/Medium and "consistent with".

use crate::AnomalyKind;

/// Audit a volume's snapshots: each snapshot's name must resolve back to its xid
/// (snap-metadata ↔ snap-name agreement), and xids must be ordered consistently
/// with creation time. All are observation leads — Time Machine thinning and
/// other legitimate operations produce similar signatures.
///
/// # Errors
/// Returns `Ok(findings)`; an unreadable snap tree surfaces as an
/// [`apfs_core::ApfsError`].
pub fn audit<R: std::io::Read + std::io::Seek>(
    reader: &mut R,
    volume: &apfs_core::volume::ApfsVolume,
    block_size: usize,
) -> crate::Result<Vec<AnomalyKind>> {
    let snaps = apfs_core::snapshot::list_snapshots(reader, volume, block_size)?;
    let mut out = Vec::new();
    // Each snapshot's name must resolve back to its own xid in the name tree.
    for s in &snaps {
        match apfs_core::snapshot::resolve_snapshot_xid(reader, volume, &s.name, block_size)? {
            Some(x) if x == s.xid => {}
            _ => out.push(AnomalyKind::SnapshotMissingMetadata {
                name: s.name.clone(),
            }),
        }
    }
    let by_xid: Vec<(u64, u64)> = snaps.iter().map(|s| (s.xid, s.create_time)).collect();
    out.extend(snapshot_xid_disorder(&by_xid));
    Ok(out)
}

/// Pure ordering check (Humble Object): with snapshots in ascending-xid order,
/// `create_time` must be non-decreasing. A later xid that predates an earlier
/// one's creation is an `APFS-SNAPSHOT-XID-DISORDER` lead.
fn snapshot_xid_disorder(_snaps: &[(u64, u64)]) -> Vec<AnomalyKind> {
    Vec::new() // RED stub
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascending_xid_and_time_is_clean() {
        assert!(snapshot_xid_disorder(&[(1, 100), (2, 200), (3, 300)]).is_empty());
    }

    #[test]
    fn later_xid_older_time_is_disorder() {
        // xid 3 was created before xid 2 — an ordering lead on xid 3.
        let v = snapshot_xid_disorder(&[(1, 100), (2, 300), (3, 200)]);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].code(), "APFS-SNAPSHOT-XID-DISORDER");
    }

    #[test]
    fn zero_create_times_are_not_disorder() {
        // Missing (zero) creation times are not ordering evidence.
        assert!(snapshot_xid_disorder(&[(1, 0), (2, 0)]).is_empty());
    }
}
