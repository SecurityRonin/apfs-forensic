//! `apfs-forensic` — a graded anomaly auditor over [`apfs_core`].
//!
//! Mirrors `ntfs-forensic`: a typed [`AnomalyKind`] domain enum that keeps APFS
//! knowledge, plus `audit_*` entry points that convert each anomaly into a
//! [`forensicnomicon::report::Finding`] via [`forensicnomicon::report::Observation`]
//! (static codes) so an APFS volume's anomalies aggregate uniformly with the
//! partition and container layers. Every finding is an **observation**
//! ("consistent with …"), never a verdict — the examiner/tribunal concludes.
//!
//! Anomaly findings that report something *unrecognized* (an unexpected keybag
//! tag, a bad magic, an oid/xid) MUST carry the raw offending value + location
//! in their evidence (fleet "show the unrecognized value" rule).
//!
//! # Scaffold notice
//!
//! Design skeleton; `audit_*` bodies are `todo!()` stubs reflecting
//! `docs/plans/2026-06-21-apfs-forensic-design.md`.
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod clones;
pub mod crypto;
pub mod integrity;
pub mod recovery;
pub mod sealed;
pub mod snapshots;
pub mod timestamps;

use forensicnomicon::report::Observation;
pub use forensicnomicon::report::{Category, Finding, Severity, Source};

/// The APFS-specific anomalies this analyzer can surface. Each variant maps to a
/// published, scheme-prefixed SCREAMING-KEBAB `code` (never changed once
/// shipped; new variants get new codes).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum AnomalyKind {
    /// `APFS-OBJECT-CKSUM-MISMATCH` — Fletcher-64 over an object body ≠ stored
    /// `o_cksum`. Carries the block, stored, and computed values.
    ObjectChecksumMismatch {
        block: u64,
        stored: u64,
        computed: u64,
    },
    /// `APFS-OMAP-INCONSISTENT` — omap maps a virtual oid to a paddr whose
    /// object oid/xid/type disagrees.
    OmapInconsistent { oid: u64, xid: u64 },
    /// `APFS-OMAP-ORPHAN-MAPPING` (Info) — omap entry for a block not referable
    /// from any live tree (FP-prone without a full reachability model).
    OmapOrphanMapping { oid: u64 },
    /// `APFS-CHECKPOINT-RING-MALFORMED` — structurally invalid checkpoint ring
    /// (no cksum-valid NXSB, bad magic, wrap/index inconsistency).
    CheckpointRingMalformed { detail: &'static str },
    /// `APFS-CHECKPOINT-SUPERSEDED-STATE` (Info) — recoverable prior state in a
    /// non-latest checkpoint (normal copy-on-write residue).
    CheckpointSupersededState { xid: u64 },
    /// `APFS-SNAPSHOT-XID-DISORDER` (Info) — snapshot xids inconsistent with
    /// `create_time` ordering.
    SnapshotXidDisorder { xid: u64 },
    /// `APFS-SNAPSHOT-MISSING-METADATA` — snap-name without snap-metadata (or
    /// vice-versa).
    SnapshotMissingMetadata { name: String },
    /// `APFS-SNAPSHOT-DIVERGENCE` (Info) — a snapshot's inode view differs from
    /// the live volume.
    SnapshotDivergence { inode: u64 },
    /// `APFS-SEALED-VOLUME-HASH-MISMATCH` — sealed-volume file-info hash ≠
    /// recomputed content hash (a hash-metadata mismatch, not a trust verdict).
    SealedVolumeHashMismatch { inode: u64 },
    /// `APFS-SEALED-VOLUME-BROKEN` — `integrity_meta_phys.im_broken_xid` set.
    SealedVolumeBroken { broken_xid: u64 },
    /// `APFS-DELETED-INODE-RECOVERABLE` — superseded inode/dir record still in an
    /// older checkpoint / unreaped block.
    DeletedInodeRecoverable { oid: u64 },
    /// `APFS-DELETED-EXTENT-CARVE-CANDIDATE` (Low) — extent blocks marked free
    /// (carve candidate, NOT a recoverability guarantee).
    DeletedExtentCarveCandidate { block: u64 },
    /// `APFS-REAPER-PENDING-OBJECT` (Low) — object queued in the reaper.
    ReaperPendingObject { oid: u64 },
    /// `APFS-CLONE-SHARED-EXTENT` (Info) — inode shares physical extents
    /// (clonefile/dedup provenance link).
    CloneSharedExtent { inode_a: u64, inode_b: u64 },
    /// `APFS-CLONE-FLAG-WITHOUT-SHARING` (Low) — `INODE_WAS_CLONED` set but no
    /// shared extent found.
    CloneFlagWithoutSharing { inode: u64 },
    /// `APFS-ENCRYPTION-LOCKED` (Info) — volume encrypted, no key available.
    EncryptionLocked,
    /// `APFS-ENCRYPTION-STATE` (Info) — observed keybag/crypto-state fields (raw).
    EncryptionState { detail: String },
    /// `APFS-ENCRYPTION-KEYBAG-ANOMALY` — malformed/unexpected keybag entry;
    /// carries the raw tag value + offset.
    EncryptionKeybagAnomaly { raw_tag: u8, offset: u64 },
    /// `APFS-TIMESTAMP-ZEROED` (Info) — one timestamp 0 while siblings are set.
    TimestampZeroed { inode: u64 },
    /// `APFS-TIMESTAMP-ORDER` (Info) — `change_time` < `create_time`, etc. (FP-prone).
    TimestampOrder { inode: u64 },
    /// `APFS-XID-REUSE` — two live objects claim the same (oid, xid).
    XidReuse { oid: u64, xid: u64 },
    /// `APFS-ORPHAN-INODE` (Low) — inode with no referencing `DIR_REC`.
    OrphanInode { oid: u64 },
    /// `APFS-VOLUME-ROLE-MISMATCH` (Info) — volume role flag inconsistent with
    /// content.
    VolumeRoleMismatch { detail: String },
}

impl AnomalyKind {
    /// The published anomaly code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::ObjectChecksumMismatch { .. } => "APFS-OBJECT-CKSUM-MISMATCH",
            Self::OmapInconsistent { .. } => "APFS-OMAP-INCONSISTENT",
            Self::OmapOrphanMapping { .. } => "APFS-OMAP-ORPHAN-MAPPING",
            Self::CheckpointRingMalformed { .. } => "APFS-CHECKPOINT-RING-MALFORMED",
            Self::CheckpointSupersededState { .. } => "APFS-CHECKPOINT-SUPERSEDED-STATE",
            Self::SnapshotXidDisorder { .. } => "APFS-SNAPSHOT-XID-DISORDER",
            Self::SnapshotMissingMetadata { .. } => "APFS-SNAPSHOT-MISSING-METADATA",
            Self::SnapshotDivergence { .. } => "APFS-SNAPSHOT-DIVERGENCE",
            Self::SealedVolumeHashMismatch { .. } => "APFS-SEALED-VOLUME-HASH-MISMATCH",
            Self::SealedVolumeBroken { .. } => "APFS-SEALED-VOLUME-BROKEN",
            Self::DeletedInodeRecoverable { .. } => "APFS-DELETED-INODE-RECOVERABLE",
            Self::DeletedExtentCarveCandidate { .. } => "APFS-DELETED-EXTENT-CARVE-CANDIDATE",
            Self::ReaperPendingObject { .. } => "APFS-REAPER-PENDING-OBJECT",
            Self::CloneSharedExtent { .. } => "APFS-CLONE-SHARED-EXTENT",
            Self::CloneFlagWithoutSharing { .. } => "APFS-CLONE-FLAG-WITHOUT-SHARING",
            Self::EncryptionLocked => "APFS-ENCRYPTION-LOCKED",
            Self::EncryptionState { .. } => "APFS-ENCRYPTION-STATE",
            Self::EncryptionKeybagAnomaly { .. } => "APFS-ENCRYPTION-KEYBAG-ANOMALY",
            Self::TimestampZeroed { .. } => "APFS-TIMESTAMP-ZEROED",
            Self::TimestampOrder { .. } => "APFS-TIMESTAMP-ORDER",
            Self::XidReuse { .. } => "APFS-XID-REUSE",
            Self::OrphanInode { .. } => "APFS-ORPHAN-INODE",
            Self::VolumeRoleMismatch { .. } => "APFS-VOLUME-ROLE-MISMATCH",
        }
    }
}

impl Observation for AnomalyKind {
    fn severity(&self) -> Option<Severity> {
        todo!("P9: per-variant grading (Critical/High/Medium/Low/Info per design table)")
    }

    fn code(&self) -> &'static str {
        AnomalyKind::code(self)
    }

    fn note(&self) -> String {
        todo!("P9: human note carrying the raw offending values (show-the-value rule)")
    }
}

/// Audit a whole container (checksum/omap/checkpoint integrity, volumes, snapshots).
#[must_use]
pub fn audit_container<R: std::io::Read + std::io::Seek>(
    _container: &apfs_core::ApfsContainer<R>,
) -> Vec<AnomalyKind> {
    todo!("P9: drive integrity/recovery/snapshot/crypto audits across the container")
}

/// Audit a single volume.
#[must_use]
pub fn audit_volume(_volume: &apfs_core::volume::ApfsVolume) -> Vec<AnomalyKind> {
    todo!("P9")
}
