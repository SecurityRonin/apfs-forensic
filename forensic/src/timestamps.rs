//! Timestamp anomaly leads (deliberately Info — FP-prone).
//!
//! `APFS-TIMESTAMP-ZEROED` (Info) — one of create/mod/change/access is 0 while
//! siblings are set; `APFS-TIMESTAMP-ORDER` (Info) — change_time < create_time
//! or access predating create. Like ntfs-forensic's timestomp detector, these
//! are deliberately Info: timestamps are `uint64_t` ns-since-epoch and zero is a
//! contextual lead, not a spec sentinel, so they are leads for the examiner, not
//! graded anomalies.

use crate::AnomalyKind;

/// Audit an inode's timestamps.
#[must_use]
pub fn audit(_inode: &apfs_core::inode::Inode) -> Vec<AnomalyKind> {
    todo!("P9: zeroed-among-siblings + ordering leads, all Info")
}
