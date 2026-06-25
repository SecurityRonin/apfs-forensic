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

/// Audit result — errors are `apfs_core` read/parse failures surfaced loudly
/// (never swallowed into an empty finding set).
pub type Result<T> = std::result::Result<T, apfs_core::ApfsError>;

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
        // Grades from the design-doc anomaly table. Codex's tempering applies:
        // copy-on-write residue and FP-prone leads are Info; only structural
        // contradictions and integrity breaks are High.
        Some(match self {
            Self::ObjectChecksumMismatch { .. }
            | Self::OmapInconsistent { .. }
            | Self::CheckpointRingMalformed { .. }
            | Self::SealedVolumeHashMismatch { .. }
            | Self::SealedVolumeBroken { .. }
            | Self::XidReuse { .. } => Severity::High,

            Self::SnapshotMissingMetadata { .. }
            | Self::DeletedInodeRecoverable { .. }
            | Self::EncryptionKeybagAnomaly { .. } => Severity::Medium,

            Self::DeletedExtentCarveCandidate { .. }
            | Self::ReaperPendingObject { .. }
            | Self::CloneFlagWithoutSharing { .. }
            | Self::OrphanInode { .. } => Severity::Low,

            Self::OmapOrphanMapping { .. }
            | Self::CheckpointSupersededState { .. }
            | Self::SnapshotXidDisorder { .. }
            | Self::SnapshotDivergence { .. }
            | Self::CloneSharedExtent { .. }
            | Self::EncryptionLocked
            | Self::EncryptionState { .. }
            | Self::TimestampZeroed { .. }
            | Self::TimestampOrder { .. }
            | Self::VolumeRoleMismatch { .. } => Severity::Info,
        })
    }

    fn code(&self) -> &'static str {
        AnomalyKind::code(self)
    }

    fn note(&self) -> String {
        // "Consistent with …", never a verdict — the examiner/tribunal concludes.
        // Every raw offending value (block, oid/xid, tag, name) is surfaced.
        match self {
            Self::ObjectChecksumMismatch {
                block,
                stored,
                computed,
            } => format!(
                "object at block {block} has stored Fletcher-64 {stored:#018x} but its body computes {computed:#018x}; consistent with structural corruption or tampering"
            ),
            Self::OmapInconsistent { oid, xid } => format!(
                "object-map entry for oid {oid} at xid {xid} resolves to a block whose object oid/xid/type disagrees; consistent with omap inconsistency"
            ),
            Self::OmapOrphanMapping { oid } => format!(
                "object-map entry for oid {oid} targets a block not reachable from any live tree examined; consistent with an orphaned mapping (reachability not exhaustively modelled)"
            ),
            Self::CheckpointRingMalformed { detail } => format!(
                "checkpoint ring is structurally invalid: {detail}; consistent with a malformed or truncated checkpoint area"
            ),
            Self::CheckpointSupersededState { xid } => format!(
                "a non-latest checkpoint at xid {xid} references objects absent from the latest; consistent with normal copy-on-write residue (a recovery lead)"
            ),
            Self::SnapshotXidDisorder { xid } => format!(
                "snapshot xid {xid} is not ordered consistently with its create_time; a lead for the examiner"
            ),
            Self::SnapshotMissingMetadata { name } => format!(
                "snapshot \"{name}\" appears in one of the snap-metadata / snap-name trees but not the other; consistent with a structural snapshot inconsistency"
            ),
            Self::SnapshotDivergence { inode } => format!(
                "a snapshot's view of inode {inode} differs from the live volume; a history lead, not an anomaly in itself"
            ),
            Self::SealedVolumeHashMismatch { inode } => format!(
                "sealed-volume file-info hash for inode {inode} does not match the recomputed content hash; consistent with a hash-metadata mismatch (not a trust-chain verdict)"
            ),
            Self::SealedVolumeBroken { broken_xid } => format!(
                "integrity_meta_phys.im_broken_xid is set to {broken_xid}; consistent with the seal having been broken at that transaction"
            ),
            Self::DeletedInodeRecoverable { oid } => format!(
                "inode/dir record for oid {oid} is superseded but still present in an older checkpoint or unreaped block; consistent with recoverable residue"
            ),
            Self::DeletedExtentCarveCandidate { block } => format!(
                "a deleted file's extent block {block} is marked free in the allocation bitmap; a carve candidate only (free does not guarantee recoverable content)"
            ),
            Self::ReaperPendingObject { oid } => format!(
                "object oid {oid} is queued in the reaper (logically deleted, still physically present); a residue lead"
            ),
            Self::CloneSharedExtent { inode_a, inode_b } => format!(
                "inodes {inode_a} and {inode_b} share one or more physical extents; consistent with a clonefile/dedup provenance link"
            ),
            Self::CloneFlagWithoutSharing { inode } => format!(
                "inode {inode} has INODE_WAS_CLONED set but no shared extent was found; consistent with a clone-flag inconsistency"
            ),
            Self::EncryptionLocked => {
                "volume is encrypted and no key is available; content is not readable (a state, not a verdict)".to_string()
            }
            Self::EncryptionState { detail } => {
                format!("observed encryption state: {detail} (raw fields; software-vs-hardware not inferred)")
            }
            Self::EncryptionKeybagAnomaly { raw_tag, offset } => format!(
                "keybag entry at offset {offset} carries an unexpected or malformed tag {raw_tag:#04x}; consistent with a keybag anomaly"
            ),
            Self::TimestampZeroed { inode } => format!(
                "inode {inode} has one timestamp zeroed while its siblings are set; an Info lead (possible wipe)"
            ),
            Self::TimestampOrder { inode } => format!(
                "inode {inode} has timestamps out of expected order (e.g. change_time before create_time); an FP-prone Info lead"
            ),
            Self::XidReuse { oid, xid } => format!(
                "two distinct live objects claim the same (oid {oid}, xid {xid}); impossible under copy-on-write, consistent with tampering"
            ),
            Self::OrphanInode { oid } => format!(
                "inode {oid} has no DIR_REC referencing it and is not in the private directory; consistent with deleted-but-linked residue"
            ),
            Self::VolumeRoleMismatch { detail } => format!(
                "volume role flag is inconsistent with content: {detail}; a structural lead"
            ),
        }
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

#[cfg(test)]
mod observation_tests {
    use super::AnomalyKind::*;
    use super::*;

    /// Every variant's severity must match the published design-doc grading.
    #[test]
    fn severity_matches_design_table() {
        use Severity::*;
        let cases: &[(AnomalyKind, Severity)] = &[
            (
                ObjectChecksumMismatch {
                    block: 1,
                    stored: 2,
                    computed: 3,
                },
                High,
            ),
            (OmapInconsistent { oid: 1, xid: 2 }, High),
            (OmapOrphanMapping { oid: 1 }, Info),
            (CheckpointRingMalformed { detail: "x" }, High),
            (CheckpointSupersededState { xid: 1 }, Info),
            (SnapshotXidDisorder { xid: 1 }, Info),
            (
                SnapshotMissingMetadata {
                    name: "s".to_string(),
                },
                Medium,
            ),
            (SnapshotDivergence { inode: 1 }, Info),
            (SealedVolumeHashMismatch { inode: 1 }, High),
            (SealedVolumeBroken { broken_xid: 1 }, High),
            (DeletedInodeRecoverable { oid: 1 }, Medium),
            (DeletedExtentCarveCandidate { block: 1 }, Low),
            (ReaperPendingObject { oid: 1 }, Low),
            (
                CloneSharedExtent {
                    inode_a: 1,
                    inode_b: 2,
                },
                Info,
            ),
            (CloneFlagWithoutSharing { inode: 1 }, Low),
            (EncryptionLocked, Info),
            (
                EncryptionState {
                    detail: "d".to_string(),
                },
                Info,
            ),
            (
                EncryptionKeybagAnomaly {
                    raw_tag: 0x99,
                    offset: 16,
                },
                Medium,
            ),
            (TimestampZeroed { inode: 1 }, Info),
            (TimestampOrder { inode: 1 }, Info),
            (XidReuse { oid: 1, xid: 2 }, High),
            (OrphanInode { oid: 1 }, Low),
            (
                VolumeRoleMismatch {
                    detail: "r".to_string(),
                },
                Info,
            ),
        ];
        for (k, want) in cases {
            assert_eq!(
                k.severity(),
                Some(*want),
                "{} should grade {want:?}",
                AnomalyKind::code(k)
            );
        }
    }

    /// Findings that carry raw offending values must surface them in the note
    /// (fleet "show the unrecognized value" rule) — never a value-less message.
    #[test]
    fn note_carries_raw_offending_values() {
        // checksum: block (decimal) + stored/computed (hex) must all appear.
        let n = ObjectChecksumMismatch {
            block: 4660,
            stored: 0xaa,
            computed: 0xbb,
        }
        .note();
        assert!(
            n.contains("4660") && n.contains("aa") && n.contains("bb"),
            "{n}"
        );

        // keybag anomaly: raw tag (hex) + offset (decimal).
        let n = EncryptionKeybagAnomaly {
            raw_tag: 0x7f,
            offset: 64,
        }
        .note();
        assert!(n.contains("0x7f") && n.contains("64"), "{n}");

        // names/details pass through.
        assert!(SnapshotMissingMetadata {
            name: "APFSP5.snap1".to_string()
        }
        .note()
        .contains("APFSP5.snap1"));
    }

    /// `note()` is an observation, never a verdict (no "proves"/"confirms").
    #[test]
    fn notes_are_observations_not_verdicts() {
        let n = SealedVolumeHashMismatch { inode: 5 }.note().to_lowercase();
        assert!(
            !n.contains("proves") && !n.contains("confirms") && !n.contains("modified by"),
            "sealed-volume note must not assert a trust verdict: {n}"
        );
    }
}
