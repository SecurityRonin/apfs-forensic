//! File-system record keys (`j_key_t`) and record-type dispatch.
//!
//! Every file-system record's key begins with `j_key_t { u64 obj_id_and_type }`
//! (Apple *APFS Reference*). The top 4 bits are the record type
//! (`OBJ_TYPE_SHIFT 60`, `OBJ_TYPE_MASK 0xf000000000000000`); the low 60 bits
//! are the object id (`OBJ_ID_MASK 0x0fffffffffffffff`).
//!
//! Record types (`j_obj_types`, verbatim numeric values from Apple):
//! `SNAP_METADATA 1`, `EXTENT 2`, `INODE 3`, `XATTR 4`, `SIBLING_LINK 5`,
//! `DSTREAM_ID 6`, `CRYPTO_STATE 7`, `FILE_EXTENT 8`, `DIR_REC 9`,
//! `DIR_STATS 10`, `SNAP_NAME 11`, `SIBLING_MAP 12`, `FILE_INFO 13`.
//!
//! Variable records carry extended fields (xfields) after the fixed value: an
//! `xf_blob { u16 xf_num_exts; u16 xf_used_data; u8 xf_data[] }` of TLV entries
//! (e.g. `INO_EXT_TYPE_NAME 4` = filename, `INO_EXT_TYPE_DSTREAM`,
//! `INO_EXT_TYPE_DOCUMENT_ID 3`).

/// APFS file-system record types (`j_obj_types`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecordType {
    SnapMetadata = 1,
    Extent = 2,
    Inode = 3,
    Xattr = 4,
    SiblingLink = 5,
    DstreamId = 6,
    CryptoState = 7,
    FileExtent = 8,
    DirRec = 9,
    DirStats = 10,
    SnapName = 11,
    SiblingMap = 12,
    FileInfo = 13,
}

/// Top-4-bit type shift in `j_key.obj_id_and_type`.
pub const OBJ_TYPE_SHIFT: u64 = 60;
/// Low-60-bit object-id mask.
pub const OBJ_ID_MASK: u64 = 0x0fff_ffff_ffff_ffff;

/// Decode a `j_key_t` into `(object_id, record_type)`.
#[must_use]
pub fn decode_jkey(_obj_id_and_type: u64) -> (u64, Option<RecordType>) {
    todo!("P3: split top-4-bit type / low-60-bit oid")
}

/// Walk an `xf_blob` TLV extended-field area (bounds-checked).
#[must_use]
pub fn parse_xfields(_data: &[u8]) -> Vec<(u8, &[u8])> {
    todo!("P3: parse xf_blob header + TLV entries")
}
