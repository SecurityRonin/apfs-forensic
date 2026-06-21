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
#[must_use]
pub fn audit<R: std::io::Read + std::io::Seek>(
    _reader: &mut R,
    _volume: &apfs_core::volume::ApfsVolume,
    _meta: &apfs_core::sealed::IntegrityMeta,
) -> Vec<AnomalyKind> {
    todo!("P9: recompute file-info hashes vs seal; check im_broken_xid")
}
