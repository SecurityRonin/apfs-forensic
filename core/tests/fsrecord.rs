//! File-system record key dispatch (`j_key_t`) and extended-field (xf_blob)
//! walking. The j_key split (top-4-bit type / low-60-bit oid) and the xf_blob
//! TLV layout are verified verbatim against the Apple reference + libfsapfs and
//! exercised on the REAL fs-tree fixture's records. See `tests/data/README.md`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use apfs_core::fsrecord::{decode_jkey, parse_xfields, RecordType};

#[test]
fn decode_jkey_splits_type_and_oid() {
    // obj_id_and_type = (type << 60) | oid. INODE=3, oid=20.
    let raw = (3u64 << 60) | 20;
    let (oid, ty) = decode_jkey(raw);
    assert_eq!(oid, 20);
    assert_eq!(ty, Some(RecordType::Inode));

    // DIR_REC=9, oid=2 (root).
    let raw = (9u64 << 60) | 2;
    let (oid, ty) = decode_jkey(raw);
    assert_eq!(oid, 2);
    assert_eq!(ty, Some(RecordType::DirRec));
}

#[test]
fn decode_jkey_masks_full_60_bit_oid() {
    // The oid occupies the low 60 bits; the top 4 bits are the type and must not
    // bleed into the oid.
    let oid_max = 0x0fff_ffff_ffff_ffff;
    let raw = (8u64 << 60) | oid_max;
    let (oid, ty) = decode_jkey(raw);
    assert_eq!(oid, oid_max);
    assert_eq!(ty, Some(RecordType::FileExtent));
}

#[test]
fn decode_jkey_unknown_type_is_none() {
    // Type 0 (INVALID) and 14/15 are not defined j_obj_types -> None, but the
    // oid still decodes (fleet "show the value" — caller still sees the oid).
    let raw = (0u64 << 60) | 7;
    let (oid, ty) = decode_jkey(raw);
    assert_eq!(oid, 7);
    assert_eq!(ty, None);

    let raw = (15u64 << 60) | 7;
    let (oid, ty) = decode_jkey(raw);
    assert_eq!(oid, 7);
    assert_eq!(ty, None);
}

#[test]
fn decode_jkey_all_defined_types() {
    let cases = [
        (1u64, RecordType::SnapMetadata),
        (2, RecordType::Extent),
        (3, RecordType::Inode),
        (4, RecordType::Xattr),
        (5, RecordType::SiblingLink),
        (6, RecordType::DstreamId),
        (7, RecordType::CryptoState),
        (8, RecordType::FileExtent),
        (9, RecordType::DirRec),
        (10, RecordType::DirStats),
        (11, RecordType::SnapName),
        (12, RecordType::SiblingMap),
        (13, RecordType::FileInfo),
    ];
    for (n, expect) in cases {
        let (oid, ty) = decode_jkey((n << 60) | 0x42);
        assert_eq!(oid, 0x42);
        assert_eq!(ty, Some(expect));
    }
}

#[test]
fn parse_xfields_decodes_name_tlv() {
    // Build an xf_blob with one INO_EXT_TYPE_NAME (4) field carrying "Hi\0".
    // xf_blob: num_exts u16, used_data u16, then descriptors (type u8, flags u8,
    // size u16), then 8-byte-aligned value data.
    let mut blob = Vec::new();
    blob.extend_from_slice(&1u16.to_le_bytes()); // xf_num_exts = 1
    blob.extend_from_slice(&3u16.to_le_bytes()); // xf_used_data (informational)
    blob.push(4); // x_type = INO_EXT_TYPE_NAME
    blob.push(0); // x_flags
    blob.extend_from_slice(&3u16.to_le_bytes()); // x_size = 3 ("Hi\0")
    blob.extend_from_slice(b"Hi\0"); // value
    blob.extend_from_slice(&[0u8; 5]); // 8-byte alignment padding

    let fields = parse_xfields(&blob);
    assert_eq!(fields.len(), 1);
    assert_eq!(fields[0].0, 4);
    assert_eq!(fields[0].1, b"Hi\0");
}

#[test]
fn parse_xfields_two_fields_aligned() {
    // Two fields: NAME (4, "A\0" = 2 bytes) then DSTREAM (8, 40-byte value).
    let mut blob = Vec::new();
    blob.extend_from_slice(&2u16.to_le_bytes()); // num_exts = 2
    blob.extend_from_slice(&0u16.to_le_bytes());
    blob.push(4);
    blob.push(0);
    blob.extend_from_slice(&2u16.to_le_bytes()); // NAME size 2
    blob.push(8);
    blob.push(0);
    blob.extend_from_slice(&40u16.to_le_bytes()); // DSTREAM size 40
                                                  // values: NAME "A\0" padded to 8, then 40-byte dstream
    blob.extend_from_slice(b"A\0");
    blob.extend_from_slice(&[0u8; 6]); // pad NAME to 8
    blob.extend_from_slice(&[0xCDu8; 40]); // dstream value

    let fields = parse_xfields(&blob);
    assert_eq!(fields.len(), 2);
    assert_eq!(fields[0], (4, &b"A\0"[..]));
    assert_eq!(fields[1].0, 8);
    assert_eq!(fields[1].1.len(), 40);
}

#[test]
fn parse_xfields_rejects_out_of_bounds() {
    // A blob claiming a huge num_exts / oversized field with no backing bytes
    // must yield a bounded (possibly empty) list, never an out-of-bounds panic.
    let mut blob = Vec::new();
    blob.extend_from_slice(&u16::MAX.to_le_bytes()); // num_exts = 65535
    blob.extend_from_slice(&0u16.to_le_bytes());
    // no descriptors / values follow
    let fields = parse_xfields(&blob);
    assert!(fields.is_empty());
}

#[test]
fn parse_xfields_empty_blob() {
    assert!(parse_xfields(&[]).is_empty());
    // num_exts = 0
    assert!(parse_xfields(&[0, 0, 0, 0]).is_empty());
}
