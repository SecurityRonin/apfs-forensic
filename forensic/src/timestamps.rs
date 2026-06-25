//! Timestamp anomaly leads (deliberately Info — FP-prone).
//!
//! `APFS-TIMESTAMP-ZEROED` (Info) — one of create/mod/change/access is 0 while
//! siblings are set; `APFS-TIMESTAMP-ORDER` (Info) — `change_time` < `create_time`
//! or access predating create. Like ntfs-forensic's timestomp detector, these
//! are deliberately Info: timestamps are `uint64_t` ns-since-epoch and zero is a
//! contextual lead, not a spec sentinel, so they are leads for the examiner, not
//! graded anomalies.

use crate::AnomalyKind;

/// Audit an inode's timestamps for zeroed-among-siblings and ordering leads.
#[must_use]
pub fn audit(inode: &apfs_core::inode::Inode) -> Vec<AnomalyKind> {
    timestamp_anomalies(
        inode.oid,
        inode.create_time,
        inode.mod_time,
        inode.change_time,
        inode.access_time,
    )
}

/// Pure timestamp-anomaly logic (Humble Object: testable without constructing an
/// `Inode`). All leads are Info — timestamps are ns-since-epoch `u64`, and zero
/// or out-of-order values have benign explanations, so these guide an examiner
/// rather than assert tampering.
fn timestamp_anomalies(
    oid: u64,
    create: u64,
    modify: u64,
    change: u64,
    access: u64,
) -> Vec<AnomalyKind> {
    let mut out = Vec::new();
    let ts = [create, modify, change, access];
    // One timestamp zeroed while siblings are set — a possible-wipe lead.
    if ts.iter().any(|&t| t != 0) && ts.contains(&0) {
        out.push(AnomalyKind::TimestampZeroed { inode: oid });
    }
    // Out-of-order: change before create, or access before create (both set).
    let order_broken = (change != 0 && create != 0 && change < create)
        || (access != 0 && create != 0 && access < create);
    if order_broken {
        out.push(AnomalyKind::TimestampOrder { inode: oid });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn codes(v: &[AnomalyKind]) -> Vec<&'static str> {
        v.iter().map(AnomalyKind::code).collect()
    }

    #[test]
    fn all_set_and_ordered_is_clean() {
        // create <= change/access, none zero -> no leads.
        assert!(timestamp_anomalies(7, 100, 200, 300, 400).is_empty());
    }

    #[test]
    fn zeroed_among_siblings_is_flagged() {
        let v = timestamp_anomalies(7, 0, 200, 300, 400);
        assert_eq!(codes(&v), vec!["APFS-TIMESTAMP-ZEROED"]);
    }

    #[test]
    fn all_zero_is_not_flagged() {
        // A brand-new/zeroed inode with ALL timestamps zero is not a "zeroed
        // among siblings" lead (nothing stands out).
        assert!(timestamp_anomalies(7, 0, 0, 0, 0).is_empty());
    }

    #[test]
    fn change_before_create_is_order_lead() {
        let v = timestamp_anomalies(7, 300, 300, 100, 300);
        assert!(codes(&v).contains(&"APFS-TIMESTAMP-ORDER"));
    }
}
