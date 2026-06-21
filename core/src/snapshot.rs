//! Snapshots: the snapshot-metadata tree and snapshot-name tree.
//!
//! A volume's snapshots are recorded in two B-trees referenced from the APSB
//! (`apfs_snap_meta_tree_oid`): keyed by xid, the **metadata** records
//! (`APFS_TYPE_SNAP_METADATA 1`, value `j_snap_metadata_val_t`) give each
//! snapshot's extent-reference tree oid, the volume-superblock oid frozen at
//! that snapshot, `create_time`, `change_time`, and the name; keyed by name, the
//! **name** records (`APFS_TYPE_SNAP_NAME 11`) map a name back to its xid.
//!
//! `j_snap_metadata_val_t` (Apple *APFS Reference*): `extentref_tree_oid`,
//! `sblock_oid`, `create_time`, `change_time`, `inum`, `extentref_tree_type`,
//! `flags`, `name_len`, `name[]`. Mounting a snapshot's `sblock_oid` yields a
//! point-in-time view of the entire volume.

/// A parsed snapshot.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Snapshot {
    pub xid: u64,
    pub name: String,
    pub create_time: u64,
    pub change_time: u64,
    pub sblock_oid: u64,
    pub extentref_tree_oid: u64,
}

/// Enumerate a volume's snapshots (metadata-tree order = by xid).
pub fn list_snapshots<R: std::io::Read + std::io::Seek>(
    _reader: &mut R,
    _volume: &crate::volume::ApfsVolume,
) -> crate::Result<Vec<Snapshot>> {
    todo!("P5: walk snap-metadata + snap-name trees")
}
