//! Snapshots: the snapshot-metadata tree, the snapshot-name tree, and the
//! point-in-time volume view.
//!
//! A volume's snapshots live in a single B-tree located by a **physical** block
//! number in the APSB (`apfs_snap_meta_tree_oid`, offset 152 — despite the
//! `_oid` name it is a block address; libfsapfs names the field
//! `snapshot_metadata_tree_block_number` and the tree's `o_subtype` is
//! `SNAPMETATREE 0x10`, stored physically `0x40000002`).
//!
//! `j_snap_metadata_val_t` field offsets within the value (verified verbatim
//! against libfsapfs `fsapfs_snapshot_metadata_btree_value` *and* dissect.apfs's
//! `j_snap_metadata_val`, which agree exactly):
//!
//! | off | size | field                 |
//! |-----|------|-----------------------|
//! | 0   | 8    | `extentref_tree_oid`  |
//! | 8   | 8    | `sblock_oid` (volume superblock block number) |
//! | 16  | 8    | `create_time` (ns since 1970-01-01 UTC) |
//! | 24  | 8    | `change_time`         |
//! | 32  | 8    | `inum`                |
//! | 40  | 4    | `extentref_tree_type` |
//! | 44  | 4    | `flags`               |
//! | 48  | 2    | `name_len` (incl. trailing NUL) |
//! | 50  | …    | `name[name_len]`      |

use std::io::{Read, Seek};

use crate::volume::ApfsVolume;

/// `o_subtype` of the snapshot-metadata tree (`OBJECT_TYPE_SNAPMETATREE`).
const OBJECT_SUBTYPE_SNAPMETATREE: u32 = 0x10;

// `j_snap_metadata_val_t` field offsets within the value.
const OFF_SNAP_EXTENTREF_TREE_OID: usize = 0;
const OFF_SNAP_SBLOCK_OID: usize = 8;
const OFF_SNAP_CREATE_TIME: usize = 16;
const OFF_SNAP_CHANGE_TIME: usize = 24;
const OFF_SNAP_INUM: usize = 32;
const OFF_SNAP_FLAGS: usize = 44;
const OFF_SNAP_NAME_LEN: usize = 48;
const OFF_SNAP_NAME: usize = 50;

/// Hard cap on a snapshot name length (incl. NUL) — a snapshot name is bounded;
/// cap well above any legal name to reject an allocation-bomb `name_len`.
const MAX_SNAP_NAME_LEN: usize = 4096;

/// A parsed snapshot (one `APFS_TYPE_SNAP_METADATA` record).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Snapshot {
    /// The snapshot's transaction id (the snap-metadata key's low 60 bits).
    pub xid: u64,
    /// The snapshot name (`j_snap_metadata_val_t.name`, NUL-terminated).
    pub name: String,
    /// `create_time` (ns since 1970-01-01 UTC).
    pub create_time: u64,
    /// `change_time` (ns since 1970-01-01 UTC).
    pub change_time: u64,
    /// `sblock_oid` — the block address of the volume superblock (APSB) frozen at
    /// this snapshot.
    pub sblock_oid: u64,
    /// `extentref_tree_oid` — the snapshot's extent-reference tree oid.
    pub extentref_tree_oid: u64,
    /// `inum` — the snapshot's `inum` field.
    pub inum: u64,
    /// `flags` (`j_snap_metadata_val_t.flags`).
    pub flags: u32,
}

/// Decode a `j_snap_metadata_val_t` value for a snapshot at `xid`. Bounds-checked:
/// missing fields read as 0, an over-long `name_len` is clamped, and the name is
/// taken only from bytes that fit (never panics, never over-reads).
fn parse_snap_metadata(xid: u64, value: &[u8]) -> Snapshot {
    let name_len = (crate::bytes::le_u16(value, OFF_SNAP_NAME_LEN) as usize).min(MAX_SNAP_NAME_LEN);
    let name = value
        .get(OFF_SNAP_NAME..OFF_SNAP_NAME + name_len)
        .map_or_else(String::new, decode_cstr);
    Snapshot {
        xid,
        name,
        create_time: crate::bytes::le_u64(value, OFF_SNAP_CREATE_TIME),
        change_time: crate::bytes::le_u64(value, OFF_SNAP_CHANGE_TIME),
        sblock_oid: crate::bytes::le_u64(value, OFF_SNAP_SBLOCK_OID),
        extentref_tree_oid: crate::bytes::le_u64(value, OFF_SNAP_EXTENTREF_TREE_OID),
        inum: crate::bytes::le_u64(value, OFF_SNAP_INUM),
        flags: crate::bytes::le_u32(value, OFF_SNAP_FLAGS),
    }
}

/// Enumerate a volume's snapshots from the snapshot-metadata tree, sorted by xid.
///
/// # Errors
/// [`crate::ApfsError::ChecksumMismatch`] / [`crate::ApfsError::CycleGuard`] /
/// [`crate::ApfsError::OmapUnresolved`] / [`crate::ApfsError::Io`] on a
/// structurally invalid tree or a read failure.
pub fn list_snapshots<R: Read + Seek>(
    _reader: &mut R,
    _volume: &ApfsVolume,
    _block_size: usize,
) -> crate::Result<Vec<Snapshot>> {
    todo!("P5 unit 1: walk the snap-metadata tree and decode SNAP_METADATA records")
}

/// Decode a NUL-terminated UTF-8 byte string (the snapshot name form).
fn decode_cstr(data: &[u8]) -> String {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).into_owned()
}

/// The snapshot-metadata tree's `o_subtype` (`OBJECT_TYPE_SNAPMETATREE`).
#[must_use]
pub fn snap_meta_tree_subtype() -> u32 {
    OBJECT_SUBTYPE_SNAPMETATREE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_snap_metadata_value_decodes_all_fields() {
        let mut v = Vec::new();
        v.extend_from_slice(&0x11u64.to_le_bytes()); // extentref_tree_oid @0
        v.extend_from_slice(&0x22u64.to_le_bytes()); // sblock_oid @8
        v.extend_from_slice(&1000u64.to_le_bytes()); // create_time @16
        v.extend_from_slice(&2000u64.to_le_bytes()); // change_time @24
        v.extend_from_slice(&99u64.to_le_bytes()); // inum @32
        v.extend_from_slice(&0x4000_0002u32.to_le_bytes()); // extentref_tree_type @40
        v.extend_from_slice(&0x1u32.to_le_bytes()); // flags @44
        v.extend_from_slice(&6u16.to_le_bytes()); // name_len @48 ("snap1\0")
        v.extend_from_slice(b"snap1\0"); // name @50

        let s = parse_snap_metadata(42, &v);
        assert_eq!(s.xid, 42);
        assert_eq!(s.extentref_tree_oid, 0x11);
        assert_eq!(s.sblock_oid, 0x22);
        assert_eq!(s.create_time, 1000);
        assert_eq!(s.change_time, 2000);
        assert_eq!(s.inum, 99);
        assert_eq!(s.flags, 0x1);
        assert_eq!(s.name, "snap1");
    }

    #[test]
    fn parse_snap_metadata_clamps_overlong_name() {
        let mut v = vec![0u8; OFF_SNAP_NAME];
        v[OFF_SNAP_NAME_LEN..OFF_SNAP_NAME_LEN + 2].copy_from_slice(&50000u16.to_le_bytes());
        let s = parse_snap_metadata(1, &v);
        assert_eq!(s.name, "");
    }

    #[test]
    fn parse_snap_metadata_truncated_value_reads_zero() {
        let s = parse_snap_metadata(7, &[0u8; 4]);
        assert_eq!(s.sblock_oid, 0);
        assert_eq!(s.create_time, 0);
        assert_eq!(s.name, "");
    }

    #[test]
    fn snap_meta_tree_subtype_is_snapmetatree() {
        assert_eq!(snap_meta_tree_subtype(), 0x10);
    }
}
