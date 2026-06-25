//! Sealed / signed-system-volume validation (the analyzer side).
//!
//! Recomputes file-info content hashes and compares them to the seal, and flags
//! a set `im_broken_xid`. `APFS-SEALED-VOLUME-HASH-MISMATCH` (High — reported as
//! a hash-metadata mismatch, NOT "the system volume was modified", which is a
//! trust-chain conclusion for the examiner), `APFS-SEALED-VOLUME-BROKEN` (High).
//!
//! The exact canonicalization Apple hashes is the least-documented, highest-FP
//! area; this is validated ONLY against a real SSV image + apfsck, never a
//! synthetic seal we compute ourselves (Tier-3 trap). Implemented last (P8/P9).

use crate::AnomalyKind;

/// Validate a sealed volume's integrity metadata.
///
/// Flags a recorded broken seal (`im_broken_xid != 0`). Per-file hash
/// recomputation vs the seal (`APFS-SEALED-VOLUME-HASH-MISMATCH`) is **not**
/// performed here: Apple's exact content-canonicalization is the least-documented
/// and highest-false-positive area, and the design requires validating it only
/// against a real Signed System Volume image + `apfsck` (never a synthetic seal
/// we compute ourselves — the Tier-3 trap). It is gated on such a fixture.
#[must_use]
pub fn audit<R: std::io::Read + std::io::Seek>(
    _reader: &mut R,
    _volume: &apfs_core::volume::ApfsVolume,
    meta: &apfs_core::sealed::IntegrityMeta,
) -> Vec<AnomalyKind> {
    sealed_anomalies(meta.broken_xid)
}

/// Pure sealed-volume audit logic (Humble Object: testable without an
/// `IntegrityMeta`). A non-zero `im_broken_xid` records that the seal was broken
/// at a known transaction — reported as an observation, not a "system volume was
/// modified" verdict (that trust-chain conclusion is for the examiner).
fn sealed_anomalies(broken_xid: u64) -> Vec<AnomalyKind> {
    if broken_xid != 0 {
        vec![AnomalyKind::SealedVolumeBroken { broken_xid }]
    } else {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intact_seal_has_no_findings() {
        assert!(sealed_anomalies(0).is_empty());
    }

    #[test]
    fn broken_xid_is_flagged_with_value() {
        let v = sealed_anomalies(42);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].code(), "APFS-SEALED-VOLUME-BROKEN");
        let note = forensicnomicon::report::Observation::note(&v[0]);
        assert!(note.contains("42"), "{note}");
    }
}
