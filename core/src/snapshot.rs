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

use crate::btree::{self, BTreeSubtype};
use crate::fsrecord::{decode_jkey, RecordType};
use crate::object::{fletcher64_checksum, fletcher64_stored, ObjPhys};
use crate::omap::ObjectMap;
use crate::volume::ApfsVolume;

/// `o_subtype` of the snapshot-metadata tree (`OBJECT_TYPE_SNAPMETATREE`).
const OBJECT_SUBTYPE_SNAPMETATREE: u32 = 0x10;

// `j_snap_name_key_t`: u16 name_len @8 (after the 8-byte j_key), name @10.
const OFF_SNAP_NAME_KEY_LEN: usize = 8;
const OFF_SNAP_NAME_KEY_NAME: usize = 10;

// `j_snap_metadata_val_t` field offsets within the value.
const OFF_SNAP_EXTENTREF_TREE_OID: usize = 0;
const OFF_SNAP_SBLOCK_OID: usize = 8;
const OFF_SNAP_CREATE_TIME: usize = 16;
const OFF_SNAP_CHANGE_TIME: usize = 24;
const OFF_SNAP_INUM: usize = 32;
const OFF_SNAP_FLAGS: usize = 44;
const OFF_SNAP_NAME_LEN: usize = 48;
const OFF_SNAP_NAME: usize = 50;

/// Depth cap on a snapshot-metadata-tree descent (cyclic-oid guard).
const MAX_SNAP_TREE_DEPTH: usize = 64;

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
    reader: &mut R,
    volume: &ApfsVolume,
    block_size: usize,
) -> crate::Result<Vec<Snapshot>> {
    let mut out = Vec::new();
    for_each_snap_record(reader, volume, block_size, &mut |key, value| {
        let (xid, ty) = decode_jkey(crate::bytes::le_u64(key, 0));
        if ty == Some(RecordType::SnapMetadata) {
            out.push(parse_snap_metadata(xid, value));
        }
    })?;
    out.sort_by_key(|s| s.xid);
    Ok(out)
}

/// Resolve a snapshot **name** to its xid via the snapshot-name tree records
/// (`APFS_TYPE_SNAP_NAME`, value `j_snap_name_val_t { xid_t snap_xid }`). `None`
/// if no snapshot of that name exists.
///
/// # Errors
/// As [`list_snapshots`].
pub fn resolve_snapshot_xid<R: Read + Seek>(
    reader: &mut R,
    volume: &ApfsVolume,
    name: &str,
    block_size: usize,
) -> crate::Result<Option<u64>> {
    let mut found = None;
    for_each_snap_record(reader, volume, block_size, &mut |key, value| {
        if found.is_some() {
            return;
        }
        let (_oid, ty) = decode_jkey(crate::bytes::le_u64(key, 0));
        if ty != Some(RecordType::SnapName) {
            return;
        }
        if decode_snap_name_key(key).as_deref() == Some(name) {
            // j_snap_name_val_t { xid_t snap_xid } — the xid is the whole value.
            found = Some(crate::bytes::le_u64(value, 0));
        }
    })?;
    Ok(found)
}

/// Walk the snapshot-metadata tree, invoking `visit(key, value)` for every leaf
/// record (both `SNAP_METADATA` and `SNAP_NAME`). The root is read by its
/// physical block address ([`ApfsVolume::snap_meta_tree_oid`]); index-node
/// children are *virtual* oids resolved through the volume omap at the volume's
/// xid (libfsapfs resolves snap-meta-tree sub-nodes via the object map),
/// mirroring [`crate::dir`]'s fs-tree walk. Each node's Fletcher-64 checksum is
/// verified before its TOC is trusted, the descent depth is capped, and a
/// visited-set guards against cyclic node oids.
fn for_each_snap_record<R, F>(
    reader: &mut R,
    volume: &ApfsVolume,
    block_size: usize,
    visit: &mut F,
) -> crate::Result<()>
where
    R: Read + Seek,
    F: FnMut(&[u8], &[u8]),
{
    // Read the volume omap header (a physical object at apfs_omap_oid) — needed
    // to resolve any virtual sub-node oids of the snap-meta tree.
    let mut buf = vec![0u8; block_size];
    let omap_off = volume.omap_oid().saturating_mul(block_size as u64);
    reader.seek(std::io::SeekFrom::Start(omap_off))?;
    reader.read_exact(&mut buf)?;
    let omap = ObjectMap::parse(&buf)?;

    let mut visited = std::collections::HashSet::new();
    descend_snap(
        reader,
        &omap,
        volume.snap_meta_tree_oid(),
        true,
        volume.xid(),
        block_size,
        0,
        &mut visited,
        visit,
    )
}

#[allow(clippy::too_many_arguments)]
fn descend_snap<R, F>(
    reader: &mut R,
    omap: &ObjectMap,
    node_oid: u64,
    is_root: bool,
    xid: u64,
    block_size: usize,
    depth: usize,
    visited: &mut std::collections::HashSet<u64>,
    visit: &mut F,
) -> crate::Result<()>
where
    R: Read + Seek,
    F: FnMut(&[u8], &[u8]),
{
    let cycle = || crate::ApfsError::CycleGuard {
        cap: MAX_SNAP_TREE_DEPTH,
    };
    // The visited-set guard below dominates any realizable cycle; this depth cap
    // is defense-in-depth against a pathological deep acyclic tree.
    if depth >= MAX_SNAP_TREE_DEPTH {
        return Err(cycle()); // cov:unreachable: visited-set guard dominates any realizable cycle
    }
    if !visited.insert(node_oid) {
        return Err(cycle());
    }

    // The root is a direct block address; a sub-node is a virtual oid resolved
    // through the volume omap.
    let paddr = if is_root {
        node_oid
    } else {
        omap.resolve(reader, node_oid, xid, block_size)?.paddr
    };

    let mut buf = vec![0u8; block_size];
    let offset = paddr.saturating_mul(block_size as u64);
    reader.seek(std::io::SeekFrom::Start(offset))?;
    reader.read_exact(&mut buf)?;

    // Checksum-before-trust.
    let stored = fletcher64_stored(&buf);
    let computed = fletcher64_checksum(&buf);
    if stored != computed {
        let block = ObjPhys::parse(&buf).map_or(paddr, |h| h.oid);
        return Err(crate::ApfsError::ChecksumMismatch {
            block,
            stored,
            computed,
        });
    }

    let Some(hdr) = btree::parse_node_header(&buf) else {
        return Ok(()); // cov:unreachable: buf is block_size >= node header length
    };

    // The snap-meta tree is a variable-KV tree (variable keys: 8-byte metadata
    // key vs name key); its layout matches the fs-tree, so BTreeSubtype::FsTree
    // supplies the right (variable-KV, 8-byte branch) entry geometry.
    if hdr.is_leaf() {
        for e in btree::node_entries(&buf, BTreeSubtype::FsTree) {
            visit(e.key, e.value);
        }
        return Ok(());
    }

    // Index node: each value is an 8-byte child *virtual* oid; descend each.
    let children: Vec<u64> = btree::node_entries(&buf, BTreeSubtype::FsTree)
        .iter()
        .map(|e| crate::bytes::le_u64(e.value, 0))
        .collect();
    for child in children {
        descend_snap(
            reader,
            omap,
            child,
            false,
            xid,
            block_size,
            depth + 1,
            visited,
            visit,
        )?;
    }
    Ok(())
}

/// Decode a `j_snap_name_key_t` name from a snap-name record key (u16 `name_len`
/// @8, name @10). `None` if the length is zero or runs past the key (never
/// over-reads).
fn decode_snap_name_key(key: &[u8]) -> Option<String> {
    let name_len =
        (crate::bytes::le_u16(key, OFF_SNAP_NAME_KEY_LEN) as usize).min(MAX_SNAP_NAME_LEN);
    if name_len == 0 {
        return None;
    }
    key.get(OFF_SNAP_NAME_KEY_NAME..OFF_SNAP_NAME_KEY_NAME + name_len)
        .map(decode_cstr)
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

    /// Build an 8-byte `j_key` header word from a 4-bit type and a 60-bit oid.
    fn jkey(ty: u64, oid: u64) -> [u8; 8] {
        ((ty << 60) | oid).to_le_bytes()
    }

    #[test]
    fn decode_snap_name_key_reads_name() {
        // j_snap_name_key_t: j_key (SNAP_NAME=11) + name_len u16 @8 + name @10.
        let mut key = Vec::new();
        key.extend_from_slice(&jkey(11, 0)); // snap-name keys carry oid 0
        key.extend_from_slice(&6u16.to_le_bytes()); // name_len = 6 ("snap1\0")
        key.extend_from_slice(b"snap1\0");
        assert_eq!(decode_snap_name_key(&key).as_deref(), Some("snap1"));
    }

    #[test]
    fn decode_snap_name_key_rejects_zero_and_overlong() {
        // name_len 0 -> None; name_len past the key -> None (no over-read).
        let mut zero = Vec::new();
        zero.extend_from_slice(&jkey(11, 0));
        zero.extend_from_slice(&0u16.to_le_bytes());
        assert_eq!(decode_snap_name_key(&zero), None);

        let mut overlong = Vec::new();
        overlong.extend_from_slice(&jkey(11, 0));
        overlong.extend_from_slice(&200u16.to_le_bytes());
        overlong.extend_from_slice(b"z");
        assert_eq!(decode_snap_name_key(&overlong), None);
    }
}
